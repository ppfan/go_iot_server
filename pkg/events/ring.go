// Package events keeps the most recent verified device callbacks for the dashboard.
package events

import (
	"sync"
	"time"
)

// Event mirrors the shape the dashboard's app.js reads from /api/events.
type Event struct {
	Time     float64 `json:"time"` // unix seconds
	DeviceID string  `json:"device_id"`
	Verified bool    `json:"verified"`
	Body     string  `json:"body"`
}

type Ring struct {
	mu    sync.Mutex
	items []Event
	next  int
	full  bool
}

func NewRing(size int) *Ring { return &Ring{items: make([]Event, size)} }

func (r *Ring) Add(deviceID string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[r.next] = Event{
		Time:     float64(time.Now().UnixMilli()) / 1000,
		DeviceID: deviceID,
		Verified: true,
		Body:     string(body),
	}
	r.next = (r.next + 1) % len(r.items)
	if r.next == 0 {
		r.full = true
	}
}

// List returns events newest first.
func (r *Ring) List() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.items)
	}
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.items[(r.next-i+len(r.items))%len(r.items)])
	}
	return out
}
