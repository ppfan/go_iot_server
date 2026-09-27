package devices

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/fleet/fleettest"
)

const testKey = "1111111111111111111111111111111111111111111111111111111111111111"

func TestCommandBody(t *testing.T) {
	tests := []struct {
		cmd  Command
		want string
		ok   bool
	}{
		{Command{Name: "device_status"}, `{"command":"device_status"}`, true},
		{Command{Name: "relay_up"}, `{"relay_up":true}`, true},
		{Command{Name: "relay_status"}, `{"relay_status":true}`, true},
		{Command{Name: "speedtest"}, `{"duration":3,"mode":"both","speedtest":true}`, true},
		{Command{Name: "speedtest", Mode: "upload", Duration: 15}, `{"duration":15,"mode":"upload","speedtest":true}`, true},
		{Command{Name: "speedtest", Duration: 16}, "", false},
		{Command{Name: "speedtest", Mode: "sideways"}, "", false},
		{Command{Name: "rotate_hmac"}, "", false}, // only via RotateKey
		{Command{Name: "relay"}, "", false},
	}
	for _, tt := range tests {
		got, err := tt.cmd.body()
		if (err == nil) != tt.ok || string(got) != tt.want {
			t.Errorf("%+v: body() = %s, %v; want %s ok=%v", tt.cmd, got, err, tt.want, tt.ok)
		}
		// A body with the substring "status" hits the firmware's telemetry branch.
		if tt.cmd.Name != "device_status" && strings.Contains(string(got), `"status"`) {
			t.Errorf("%+v: body contains \"status\"", tt.cmd)
		}
	}
}

// fakeDevice mimics data_server.c: verifies HMAC with its current key and
// implements rotate_hmac.
type fakeDevice struct {
	hold      chan struct{} // if set, requests block until it is closed
	key       string
	prevKey   string
	gotHeader http.Header
	dropAck   bool
}

func (d *fakeDevice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.hold != nil {
		<-d.hold
	}
	body, _ := io.ReadAll(r.Body)
	d.gotHeader = r.Header.Clone()
	sig := r.Header.Get("X-Signature-SHA256")
	if !crypto.VerifyHMAC(d.key, body, sig) && (d.prevKey == "" || !crypto.VerifyHMAC(d.prevKey, body, sig)) {
		http.Error(w, "Bad signature", http.StatusUnauthorized)
		return
	}
	var req map[string]any
	json.Unmarshal(body, &req)
	if req["rotate_hmac"] == true {
		d.prevKey, d.key = d.key, req["new_key"].(string)
		if d.dropAck {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "action": "hmac_rotated", "key_id": req["key_id"].(string)})
		return
	}
	w.Write([]byte(`{"relay_state":true}`))
}

func setup(t *testing.T, dev *fakeDevice) (*Client, *fleet.Vault) {
	t.Helper()
	v, _ := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: testKey}})
	srv := httptest.NewTLSServer(dev)
	t.Cleanup(srv.Close)

	c := NewClient(v, NewRegistry(v, time.Minute, nil), 8443, srv.Client().Transport.(*http.Transport).TLSClientConfig)
	tr := c.http.Transport.(*http.Transport)
	tr.TLSClientConfig.ServerName = "example.com"
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return c, v
}

func TestSendSignsPerDevice(t *testing.T) {
	dev := &fakeDevice{key: testKey}
	c, _ := setup(t, dev)
	res, err := c.Send(context.Background(), "n1", Command{Name: "relay_status"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != `{"relay_state":true}` {
		t.Fatalf("body = %s", res.Body)
	}
	if dev.gotHeader.Get("X-Device-ID") != "n1" {
		t.Fatal("X-Device-ID not sent")
	}
	if l := c.registry.List(); !l[0].IsOnline {
		t.Fatal("device not marked seen after successful command")
	}
	if _, err := c.Send(context.Background(), "nX", Command{Name: "relay_status"}); err == nil {
		t.Fatal("unknown device accepted")
	}
}

func TestRotateKey(t *testing.T) {
	dev := &fakeDevice{key: testKey}
	c, v := setup(t, dev)
	keyID, err := c.RotateKey(context.Background(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if k, id, _ := v.SigningKey("n1"); k != dev.key || id != keyID {
		t.Fatal("server and device keys diverged after rotation")
	}
	// Next command is signed with the new key and carries its key_id.
	if _, err := c.Send(context.Background(), "n1", Command{Name: "relay_status"}); err != nil {
		t.Fatal(err)
	}
	if dev.gotHeader.Get("X-Key-ID") != keyID {
		t.Fatalf("X-Key-ID = %q, want %q", dev.gotHeader.Get("X-Key-ID"), keyID)
	}
}

func TestRotateKeyLostAckIsRecoverable(t *testing.T) {
	dev := &fakeDevice{key: testKey, dropAck: true}
	c, v := setup(t, dev)
	if _, err := c.RotateKey(context.Background(), "n1"); err == nil {
		t.Fatal("expected error when ack is lost")
	}
	if d, _ := v.Get("n1"); !d.RotationPending {
		t.Fatal("pending key discarded after lost ack")
	}
	// Device already switched. The retry resends the same pending key signed with
	// the old key, which the device still accepts as its grace-period key.
	dev.dropAck = false
	keyID, err := c.RotateKey(context.Background(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if k, id, _ := v.SigningKey("n1"); k != dev.key || id != keyID {
		t.Fatal("server and device keys diverged")
	}
}

func TestOverlappingRequestIsBusy(t *testing.T) {
	dev := &fakeDevice{key: testKey, hold: make(chan struct{})}
	c, _ := setup(t, dev)
	done := make(chan error)
	go func() {
		_, err := c.Send(context.Background(), "n1", Command{Name: "relay_toggle"})
		done <- err
	}()
	// Wait until the first request holds the device lock.
	for i := 0; i < 100; i++ {
		if _, err := c.Send(context.Background(), "n1", Command{Name: "relay_status"}); errors.Is(err, ErrBusy) {
			close(dev.hold)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("second request was not rejected as busy")
}
