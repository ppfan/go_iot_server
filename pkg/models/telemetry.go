package models

import "time"

// Callback types sent by the firmware in the "type" field.
const (
	TypeDeviceStatus    = "device_status"
	TypeSpeedtestResult = "speedtest_result"
)

// TelemetryPayload is the device_status JSON built by build_telemetry_json() in data_server.c.
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

// SpeedtestResult is the speedtest_result JSON built in speedtest.c.
// Mode "both" fills the dl_*/ul_* fields; single-direction modes fill Mode/Mbps/Bytes.
type SpeedtestResult struct {
	Type      string  `json:"type"`
	Mode      string  `json:"mode,omitempty"`
	Mbps      float64 `json:"mbps,omitempty"`
	Bytes     int64   `json:"bytes,omitempty"`
	DLMbps    float64 `json:"dl_mbps,omitempty"`
	DLBytes   int64   `json:"dl_bytes,omitempty"`
	ULMbps    float64 `json:"ul_mbps,omitempty"`
	ULBytes   int64   `json:"ul_bytes,omitempty"`
	DurationS float64 `json:"duration_s"`
}

// DeviceInfo is the dashboard view of a fleet device. It never contains key material.
type DeviceInfo struct {
	ID            string            `json:"id"`
	IP            string            `json:"ip"`
	KeyID         string            `json:"key_id,omitempty"`
	RotationOpen  bool              `json:"rotation_pending"`
	LastSeen      *time.Time        `json:"last_seen,omitempty"`
	IsOnline      bool              `json:"is_online"`
	LastTelemetry *TelemetryPayload `json:"last_telemetry,omitempty"`
	LastSpeedtest *SpeedtestResult  `json:"last_speedtest,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
}
