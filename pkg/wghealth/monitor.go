// Package wghealth reports tunnel health from the kernel WireGuard interface.
//
// The control room's only peer is the relay (10.10.0.1); devices are peers of the
// relay, not of us. So this tells whether the tunnel to the fleet is up, not
// whether a given device is.
package wghealth

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// A handshake older than this means the tunnel is down (WireGuard rekeys every 2 min).
const staleAfter = 3 * time.Minute

type Status struct {
	Interface     string     `json:"interface"`
	Up            bool       `json:"up"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	Endpoint      string     `json:"endpoint,omitempty"`
	Error         string     `json:"error,omitempty"`
	unknown       bool       // interface could not be queried at all
}

type Monitor struct {
	iface string
	mu    sync.RWMutex
	st    Status
}

func New(iface string) *Monitor {
	return &Monitor{iface: iface, st: Status{Interface: iface, Error: "not checked yet", unknown: true}}
}

func (m *Monitor) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.st
}

// Up reports false when the tunnel is known to be down, including when the
// interface does not exist. If WireGuard cannot be queried at all (e.g. missing
// CAP_NET_ADMIN) it returns true so device presence falls back to last-seen
// times; the error is visible in Status.
func (m *Monitor) Up() bool {
	st := m.Status()
	return st.Up || st.unknown
}

// Run polls the interface until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		m.check()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Monitor) check() {
	st := Status{Interface: m.iface}
	c, err := wgctrl.New()
	if err == nil {
		defer c.Close()
		dev, derr := c.Device(m.iface)
		if derr != nil {
			err = derr
			st.unknown = !errors.Is(derr, os.ErrNotExist)
		} else {
			for _, p := range dev.Peers {
				if p.LastHandshakeTime.IsZero() {
					continue
				}
				if st.LastHandshake == nil || p.LastHandshakeTime.After(*st.LastHandshake) {
					hs := p.LastHandshakeTime
					st.LastHandshake = &hs
					if p.Endpoint != nil {
						st.Endpoint = p.Endpoint.String()
					}
				}
			}
			st.Up = st.LastHandshake != nil && time.Since(*st.LastHandshake) < staleAfter
		}
	}
	if err != nil {
		st.Error = err.Error()
		if c == nil {
			st.unknown = true
		}
	}
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()
}
