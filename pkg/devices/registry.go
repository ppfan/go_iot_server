package devices

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/models"
)

// Registry manages thread-safe tracking of dozens to hundreds of ESP32 devices.
type Registry struct {
	mu         sync.RWMutex
	devices    map[string]*models.DeviceInfo
	httpClient *http.Client
	secret     string
}

// NewRegistry initializes a device registry with custom HTTP transport tuned for IoT concurrency.
func NewRegistry(secret string) *Registry {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // Self-signed device certs inside WireGuard
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     60 * time.Second,
	}

	return &Registry{
		devices: make(map[string]*models.DeviceInfo),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		secret: secret,
	}
}

// RecordTelemetry updates or registers a device upon receiving incoming telemetry.
func (r *Registry) RecordTelemetry(ip string, t *models.TelemetryPayload) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := ip
	if t.IP != "" {
		id = t.IP
	}

	dev, exists := r.devices[id]
	if !exists {
		dev = &models.DeviceInfo{
			ID: id,
			IP: ip,
		}
		r.devices[id] = dev
	}

	dev.LastSeen = time.Now()
	dev.IsOnline = true
	dev.LastTelemetry = t
}

// ListDevices returns a snapshot of all registered devices.
func (r *Registry) ListDevices() []*models.DeviceInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*models.DeviceInfo, 0, len(r.devices))
	for _, dev := range r.devices {
		// Deep copy snapshot
		copyDev := *dev
		list = append(list, &copyDev)
	}
	return list
}

// SendHTTPCommand sends an authenticated HMAC-signed HTTP POST command to an ESP32 HTTPS endpoint.
func (r *Registry) SendHTTPCommand(ctx context.Context, targetIP string, port int, payload map[string]interface{}) ([]byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	url := fmt.Sprintf("https://%s:%d/data", targetIP, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	sig := crypto.ComputeHMAC(r.secret, bodyBytes)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-SHA256", sig)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBody, fmt.Errorf("device responded with HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
