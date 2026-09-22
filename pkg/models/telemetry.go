package models

import "time"

// TelemetryPayload represents the JSON sent by an ESP32 device.
type TelemetryPayload struct {
	Type            string `json:"type"`
	Status          string `json:"status"`
	WireGuardPeerUp bool   `json:"wireguard_peer_up"`
	UptimeS         uint64 `json:"uptime_s"`
	FreeHeap        uint32 `json:"free_heap"`
	MinFreeHeap     uint32 `json:"min_free_heap"`
	RelayState      bool   `json:"relay_state"`
	RelayGPIO       int    `json:"relay_gpio"`
	Interface       string `json:"interface"`
	IP              string `json:"ip"`
}

// DeviceCommand represents an action sent from the Go server to an ESP32.
type DeviceCommand struct {
	Action      string `json:"action,omitempty"`
	Relay       *int   `json:"relay,omitempty"`
	Speedtest   bool   `json:"speedtest,omitempty"`
	DurationSec int    `json:"duration_sec,omitempty"`
	Mode        string `json:"mode,omitempty"`
	NewKey      string `json:"new_key,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
}

// DeviceInfo represents an active or registered ESP32 in the fleet registry.
type DeviceInfo struct {
	ID            string            `json:"id"`
	IP            string            `json:"ip"`
	LastSeen      time.Time         `json:"last_seen"`
	IsOnline      bool              `json:"is_online"`
	LastTelemetry *TelemetryPayload `json:"last_telemetry,omitempty"`
}
