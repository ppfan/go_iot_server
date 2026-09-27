package devices

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/fleet"
)

const maxResponseBytes = 4096

var (
	// ErrInvalidCommand wraps every rejection of a command before it is sent.
	ErrInvalidCommand = errors.New("invalid command")
	// ErrBusy means another request to the same device is still in flight.
	ErrBusy = errors.New("device is busy with another request")
)

// Command is an allowlisted action from the dashboard API.
type Command struct {
	Name     string `json:"command"`
	Mode     string `json:"mode,omitempty"`     // speedtest only
	Duration int    `json:"duration,omitempty"` // speedtest only, seconds
}

// body builds the exact JSON the firmware expects. The firmware matches with
// strstr (data_server.c), so each body carries one command and no extra keys.
func (c Command) body() ([]byte, error) {
	switch c.Name {
	case "device_status":
		return []byte(`{"command":"device_status"}`), nil
	case "relay_up", "relay_down", "relay_toggle", "relay_status":
		return []byte(`{"` + c.Name + `":true}`), nil
	case "speedtest":
		mode := c.Mode
		if mode == "" {
			mode = "both"
		}
		if mode != "download" && mode != "upload" && mode != "both" {
			return nil, fmt.Errorf("%w: speedtest mode %q", ErrInvalidCommand, c.Mode)
		}
		d := c.Duration
		if d == 0 {
			d = 3
		}
		if d < 1 || d > 15 {
			return nil, fmt.Errorf("%w: speedtest duration must be 1-15 s", ErrInvalidCommand)
		}
		return json.Marshal(map[string]any{"speedtest": true, "mode": mode, "duration": d})
	default:
		return nil, fmt.Errorf("%w: unknown command %q", ErrInvalidCommand, c.Name)
	}
}

// Result is a device reply passed through to the API caller.
type Result struct {
	Status  int             `json:"status"`
	Body    json.RawMessage `json:"body"`
	Elapsed time.Duration   `json:"-"`
}

type Client struct {
	vault    *fleet.Vault
	registry *Registry
	port     int
	http     *http.Client

	rotMu sync.Mutex // one rotation at a time
	busy  sync.Map   // device ID -> *sync.Mutex; one request per device at a time
}

// NewTLSConfig verifies devices against the fleet CA. Device certificates carry
// IP SANs for 10.10.0.1-64 (esp32_wg_http/certs/esp32_ext.cnf).
func NewTLSConfig(caPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no certificates in CA file")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

func NewClient(v *fleet.Vault, r *Registry, port int, tlsCfg *tls.Config) *Client {
	return &Client{
		vault:    v,
		registry: r,
		port:     port,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxConnsPerHost:     1, // ESP32 httpd has max_open_sockets = 4
				MaxIdleConnsPerHost: 1,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 8 * time.Second,
			},
		},
	}
}

// Send signs and delivers an allowlisted command to device id.
func (c *Client) Send(ctx context.Context, id string, cmd Command) (*Result, error) {
	body, err := cmd.body()
	if err != nil {
		return nil, err
	}
	return c.post(ctx, id, body)
}

// RotateKey generates a new key for id, sends it signed with the current key and
// commits it once the device confirms the key_id. The key never leaves this process
// except towards the device.
func (c *Client) RotateKey(ctx context.Context, id string) (keyID string, err error) {
	c.rotMu.Lock()
	defer c.rotMu.Unlock()

	newKey, keyID, err := c.vault.BeginRotation(id)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{"rotate_hmac": true, "new_key": newKey, "key_id": keyID})
	res, err := c.post(ctx, id, body)
	if err != nil {
		// Pending key stays persisted: a retry resends it, and a callback
		// signed with it commits it (fleet.Vault.Verify).
		return keyID, err
	}
	var ack struct {
		Action string `json:"action"`
		KeyID  string `json:"key_id"`
	}
	if json.Unmarshal(res.Body, &ack) != nil || ack.Action != "hmac_rotated" || ack.KeyID != keyID {
		return keyID, fmt.Errorf("device did not confirm rotation: %s", res.Body)
	}
	return keyID, c.vault.CommitRotation(id, keyID)
}

func (c *Client) post(ctx context.Context, id string, body []byte) (*Result, error) {
	dev, ok := c.vault.Get(id)
	if !ok {
		return nil, fleet.ErrUnknownDevice
	}
	// The ESP32 handles one command at a time well; overlapping requests fail
	// fast instead of queueing behind a slow TLS handshake.
	lock, _ := c.busy.LoadOrStore(id, &sync.Mutex{})
	if !lock.(*sync.Mutex).TryLock() {
		return nil, ErrBusy
	}
	defer lock.(*sync.Mutex).Unlock()
	start := time.Now()
	key, keyID, err := c.vault.SigningKey(id)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s:%d/data", dev.IP, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-SHA256", crypto.ComputeHMAC(key, body))
	req.Header.Set("X-Device-ID", id)
	if keyID != "" {
		req.Header.Set("X-Key-ID", keyID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		c.registry.MarkError(id, err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		c.registry.MarkError(id, err)
		return nil, err
	}
	c.registry.MarkSeen(id)

	res := &Result{Status: resp.StatusCode, Body: respBody, Elapsed: time.Since(start)}
	if !json.Valid(respBody) {
		res.Body, _ = json.Marshal(string(respBody))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return res, fmt.Errorf("device responded HTTP %d", resp.StatusCode)
	}
	return res, nil
}

// Poll sends relay_status to every device each interval to keep presence fresh.
// relay_status is used rather than device_status because it does not make the
// device open a TLS callback of its own.
func (c *Client) Poll(ctx context.Context, interval time.Duration, workers int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, id := range c.vault.IDs() {
			wg.Add(1)
			sem <- struct{}{}
			go func(id string) {
				defer wg.Done()
				defer func() { <-sem }()
				cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				if _, err := c.Send(cctx, id, Command{Name: "relay_status"}); err != nil && ctx.Err() == nil && !errors.Is(err, ErrBusy) {
					log.Printf("[poll] %s: %v", id, err)
				}
			}(id)
		}
		wg.Wait()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
