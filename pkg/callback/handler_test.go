package callback

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/events"
	"iot_server_go/pkg/fleet/fleettest"
)

const key = "1111111111111111111111111111111111111111111111111111111111111111"

func TestCallback(t *testing.T) {
	v, _ := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: key}})
	reg := devices.NewRegistry(v, time.Minute, nil)
	ev := events.NewRing(10)
	h := Handler(v, reg, ev)

	telemetry := `{"type":"device_status","status":"ok","wireguard_peer_up":true,"uptime_s":42,"free_heap":1000,"min_free_heap":900,"relay_state":true,"relay_gpio":4,"interface":"Ethernet","ip":"10.10.0.3"}`
	speed := `{"type":"speedtest_result","dl_mbps":5.10,"dl_bytes":100,"ul_mbps":4.20,"ul_bytes":90,"duration_s":3}`

	tests := []struct {
		name, body, id, remote, sig string
		method                      string
		want                        int
	}{
		{"telemetry", telemetry, "n1", "10.10.0.3:5000", crypto.ComputeHMAC(key, []byte(telemetry)), "POST", 200},
		{"speedtest", speed, "n1", "10.10.0.3:5000", crypto.ComputeHMAC(key, []byte(speed)), "POST", 200},
		{"bad signature", telemetry, "n1", "10.10.0.3:5000", crypto.ComputeHMAC("other", []byte(telemetry)), "POST", 401},
		{"no device id", telemetry, "", "10.10.0.3:5000", crypto.ComputeHMAC(key, []byte(telemetry)), "POST", 401},
		{"spoofed source", telemetry, "n1", "10.10.0.9:5000", crypto.ComputeHMAC(key, []byte(telemetry)), "POST", 401},
		{"too large", strings.Repeat("x", 5000), "n1", "10.10.0.3:5000", "", "POST", 413},
		{"GET", "", "n1", "10.10.0.3:5000", "", "GET", 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/callback", strings.NewReader(tt.body))
			req.RemoteAddr = tt.remote
			req.Header.Set("X-Device-ID", tt.id)
			req.Header.Set("X-Signature-SHA256", tt.sig)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tt.want, rec.Body)
			}
		})
	}

	d := reg.List()[0]
	if d.LastTelemetry == nil || d.LastTelemetry.UptimeS != 42 || !d.IsOnline {
		t.Fatalf("telemetry not recorded: %+v", d)
	}
	if d.LastSpeedtest == nil || d.LastSpeedtest.DLMbps != 5.10 {
		t.Fatalf("speedtest not recorded: %+v", d.LastSpeedtest)
	}
	// Only the two verified callbacks are shown on the dashboard.
	if got := ev.List(); len(got) != 2 || got[0].DeviceID != "n1" {
		t.Fatalf("events = %+v", got)
	}
}
