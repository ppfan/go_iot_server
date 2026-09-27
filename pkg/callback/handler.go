// Package callback receives signed POSTs from devices at https://10.10.0.2:9090/callback.
package callback

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"

	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/events"
	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/models"
)

const maxBodyBytes = 4096 // matches APP_MAX_BODY_LEN on the device

// Handler verifies callbacks and records them in r and, if non-nil, ev.
func Handler(v *fleet.Vault, r *devices.Registry, ev *events.Ring) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /callback", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, `{"error":"body_too_large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		src, err := netip.ParseAddr(host)
		if err != nil {
			http.Error(w, `{"error":"bad_source"}`, http.StatusBadRequest)
			return
		}

		id := req.Header.Get("X-Device-ID")
		if err := v.Verify(id, src, body, req.Header.Get("X-Signature-SHA256")); err != nil {
			log.Printf("[callback] rejected %q from %s: %v", id, src, err)
			code := `{"error":"invalid_signature"}`
			if errors.Is(err, fleet.ErrUnknownDevice) {
				code = `{"error":"unknown_device_id"}`
			}
			http.Error(w, code, http.StatusUnauthorized)
			return
		}

		if ev != nil {
			ev.Add(id, body)
		}

		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &head); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		switch head.Type {
		case models.TypeDeviceStatus:
			var t models.TelemetryPayload
			if json.Unmarshal(body, &t) == nil {
				r.RecordTelemetry(id, &t)
				log.Printf("[callback] %s telemetry: uptime=%ds heap=%d relay=%v", id, t.UptimeS, t.FreeHeap, t.RelayState)
			}
		case models.TypeSpeedtestResult:
			var s models.SpeedtestResult
			if json.Unmarshal(body, &s) == nil {
				r.RecordSpeedtest(id, &s)
				log.Printf("[callback] %s speedtest: %s", id, body)
			}
		default:
			r.MarkSeen(id)
			log.Printf("[callback] %s sent unhandled type %q", id, head.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}
