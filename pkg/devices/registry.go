package devices

import (
	"sync"
	"time"

	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/models"
)

type state struct {
	lastSeen      time.Time
	lastTelemetry *models.TelemetryPayload
	lastSpeedtest *models.SpeedtestResult
	lastError     string
}

// Registry tracks runtime state for devices in the fleet vault only; unknown
// senders never create entries. Devices added at runtime get state on first use.
type Registry struct {
	vault        *fleet.Vault
	onlineWindow time.Duration
	tunnelUp     func() bool

	mu    sync.RWMutex
	state map[string]*state
}

// NewRegistry builds a registry. tunnelUp may be nil; when it reports false,
// every device is shown offline regardless of when it was last seen.
func NewRegistry(v *fleet.Vault, onlineWindow time.Duration, tunnelUp func() bool) *Registry {
	return &Registry{vault: v, onlineWindow: onlineWindow, tunnelUp: tunnelUp, state: make(map[string]*state)}
}

func (r *Registry) update(id string, fn func(*state)) {
	if _, ok := r.vault.Get(id); !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.state[id]
	if !ok {
		s = &state{}
		r.state[id] = s
	}
	fn(s)
}

func (r *Registry) MarkSeen(id string) {
	r.update(id, func(s *state) { s.lastSeen = time.Now(); s.lastError = "" })
}

func (r *Registry) MarkError(id string, err error) {
	r.update(id, func(s *state) { s.lastError = err.Error() })
}

func (r *Registry) RecordTelemetry(id string, t *models.TelemetryPayload) {
	r.update(id, func(s *state) { s.lastSeen = time.Now(); s.lastError = ""; s.lastTelemetry = t })
}

func (r *Registry) RecordSpeedtest(id string, res *models.SpeedtestResult) {
	r.update(id, func(s *state) { s.lastSeen = time.Now(); s.lastSpeedtest = res })
}

// List returns a snapshot of all devices, sorted by ID.
func (r *Registry) List() []models.DeviceInfo {
	tunnelUp := r.tunnelUp == nil || r.tunnelUp()
	ids := r.vault.IDs()
	out := make([]models.DeviceInfo, 0, len(ids))

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, id := range ids {
		d, ok := r.vault.Get(id)
		if !ok {
			continue
		}
		s := r.state[id]
		if s == nil {
			s = &state{}
		}
		info := models.DeviceInfo{
			ID:            id,
			IP:            d.IP.String(),
			KeyID:         d.KeyID,
			RotationOpen:  d.RotationPending,
			LastTelemetry: s.lastTelemetry,
			LastSpeedtest: s.lastSpeedtest,
			LastError:     s.lastError,
		}
		if !s.lastSeen.IsZero() {
			seen := s.lastSeen
			info.LastSeen = &seen
			info.IsOnline = tunnelUp && time.Since(seen) < r.onlineWindow
		}
		out = append(out, info)
	}
	return out
}
