package fleet_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/fleet/fleettest"
	"iot_server_go/pkg/store"
)

const key1 = "1111111111111111111111111111111111111111111111111111111111111111"

var ctx = context.Background()

func TestImportJSON(t *testing.T) {
	tests := []struct {
		name, body string
		want       int
	}{
		{"wrapped", `{"devices":{"n1":{"ip":"10.10.0.3","hmac_key":"k"},"n2":{"ip":"10.10.0.4","hmac_key":"k"}}}`, 2},
		{"flat", `{"n1":{"ip":"10.10.0.4","hmac_key":"k"}}`, 1},
		{"relay ip", `{"devices":{"n1":{"ip":"10.10.0.1","hmac_key":"k"}}}`, -1},
		{"control room ip", `{"devices":{"n1":{"ip":"10.10.0.2","hmac_key":"k"}}}`, -1},
		{"outside subnet", `{"devices":{"n1":{"ip":"192.168.0.3","hmac_key":"k"}}}`, -1},
		{"duplicate ip", `{"devices":{"a":{"ip":"10.10.0.3","hmac_key":"k"},"b":{"ip":"10.10.0.3","hmac_key":"k"}}}`, -1},
		{"missing key", `{"devices":{"n1":{"ip":"10.10.0.3"}}}`, -1},
		{"csv-unsafe id", `{"devices":{"a,b":{"ip":"10.10.0.3","hmac_key":"k"}}}`, -1},
		{"empty", `{"devices":{}}`, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := fleettest.OpenStore(t)
			p := filepath.Join(t.TempDir(), "fleet_keys.json")
			os.WriteFile(p, []byte(tt.body), 0o600)
			n, err := fleet.ImportJSON(ctx, st, p)
			if tt.want < 0 {
				if err == nil {
					t.Fatal("import succeeded, want error")
				}
				if c, _ := st.CountDevices(ctx); c != 0 {
					t.Fatalf("failed import left %d rows", c)
				}
				return
			}
			if err != nil || n != tt.want {
				t.Fatalf("ImportJSON = %d, %v; want %d", n, err, tt.want)
			}
			// A second import is a no-op: the DB is now the source of truth.
			if n, err := fleet.ImportJSON(ctx, st, p); n != 0 || err != nil {
				t.Fatalf("re-import = %d, %v", n, err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	v, _ := fleettest.New(t, map[string]fleettest.Dev{
		"n1": {IP: "10.10.0.3", Key: key1},
		"n2": {IP: "10.10.0.4", Key: "other"},
	})
	body := []byte(`{"type":"device_status"}`)
	sig := crypto.ComputeHMAC(key1, body)
	n1 := netip.MustParseAddr("10.10.0.3")

	tests := []struct {
		name string
		id   string
		src  netip.Addr
		sig  string
		want error
	}{
		{"valid", "n1", n1, sig, nil},
		{"ipv4-mapped source", "n1", netip.MustParseAddr("::ffff:10.10.0.3"), sig, nil},
		{"unknown device", "nX", n1, sig, fleet.ErrUnknownDevice},
		{"wrong source ip", "n1", netip.MustParseAddr("10.10.0.4"), sig, fleet.ErrIPMismatch},
		{"other device's key", "n2", netip.MustParseAddr("10.10.0.4"), sig, fleet.ErrBadSignature},
		{"garbage signature", "n1", n1, "zz", fleet.ErrBadSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.Verify(tt.id, tt.src, body, tt.sig); !errors.Is(err, tt.want) {
				t.Fatalf("Verify() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRotationLifecycle(t *testing.T) {
	v, st := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: key1}})
	src := netip.MustParseAddr("10.10.0.3")
	body := []byte(`{}`)

	newKey, keyID, err := v.BeginRotation("n1")
	if err != nil {
		t.Fatal(err)
	}
	if len(newKey) != 64 {
		t.Fatalf("rotated key length %d, want 64", len(newKey))
	}
	if k2, id2, _ := v.BeginRotation("n1"); k2 != newKey || id2 != keyID {
		t.Fatal("BeginRotation retry produced a different key")
	}
	// Pending key is persisted before it is sent.
	reloaded, err := fleet.New(st)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := reloaded.Get("n1"); !d.RotationPending {
		t.Fatal("pending rotation not persisted")
	}

	if k, _, _ := v.SigningKey("n1"); k != key1 {
		t.Fatal("signing key changed before commit")
	}
	if err := v.CommitRotation("n1", "wrong"); err == nil {
		t.Fatal("commit with wrong key_id succeeded")
	}
	if err := v.CommitRotation("n1", keyID); err != nil {
		t.Fatal(err)
	}
	if k, id, _ := v.SigningKey("n1"); k != newKey || id != keyID {
		t.Fatal("signing key not promoted")
	}
	if err := v.Verify("n1", src, body, crypto.ComputeHMAC(key1, body)); err != nil {
		t.Fatalf("previous key rejected: %v", err)
	}
	// Committed state survives a restart.
	reloaded, _ = fleet.New(st)
	if k, id, _ := reloaded.SigningKey("n1"); k != newKey || id != keyID {
		t.Fatal("rotation not persisted")
	}
}

func TestVerifyWithPendingKeyCommits(t *testing.T) {
	v, _ := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: key1}})
	newKey, keyID, err := v.BeginRotation("n1")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"type":"device_status"}`)
	if err := v.Verify("n1", netip.MustParseAddr("10.10.0.3"), body, crypto.ComputeHMAC(newKey, body)); err != nil {
		t.Fatal(err)
	}
	if k, id, _ := v.SigningKey("n1"); k != newKey || id != keyID {
		t.Fatal("pending key not committed after device used it")
	}
}

func TestAddAndDisable(t *testing.T) {
	v, _ := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: key1}})
	for _, bad := range []store.Device{
		{ID: "x", IP: "10.10.0.1", HMACKey: key1},
		{ID: "x", IP: "10.10.0.2", HMACKey: key1},
		{ID: "x", IP: "10.10.0.3", HMACKey: key1}, // taken by n1
		{ID: "n1", IP: "10.10.0.9", HMACKey: key1},
		{ID: "bad\nid", IP: "10.10.0.9", HMACKey: key1},
		{ID: "x", IP: "10.10.0.9"},
	} {
		if err := v.AddDevice(ctx, bad); err == nil {
			t.Errorf("AddDevice(%q, %s) accepted", bad.ID, bad.IP)
		}
	}
	if err := v.AddDevice(ctx, store.Device{ID: "n2", IP: "10.10.0.4", HMACKey: key1}); err != nil {
		t.Fatal(err)
	}
	if !v.IsDeviceIP(netip.MustParseAddr("10.10.0.4")) {
		t.Fatal("new device not live without restart")
	}
	if err := v.DisableDevice(ctx, "n2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Get("n2"); ok || v.IsDeviceIP(netip.MustParseAddr("10.10.0.4")) {
		t.Fatal("disabled device still active")
	}
	if err := v.AddDevice(ctx, store.Device{ID: "n3", IP: "10.10.0.4", HMACKey: key1}); err == nil {
		t.Fatal("IP of disabled device reused")
	}
}
