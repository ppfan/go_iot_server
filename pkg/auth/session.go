package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"iot_server_go/pkg/store"
)

var (
	ErrBadCredentials = errors.New("invalid username or password")
	ErrRateLimited    = errors.New("too many failed logins, try again later")
	ErrNoSession      = errors.New("not logged in")
)

const (
	maxFailures   = 5
	failureWindow = 15 * time.Minute
)

// Manager issues and checks sessions. Only SHA-256 hashes of session tokens
// are stored, so a copy of the database cannot be used to hijack a session.
type Manager struct {
	Store *store.Store
	TTL   time.Duration

	dummyHash string // compared for unknown users so timing does not reveal them

	mu       sync.Mutex
	failures map[string][]time.Time // "ip:<addr>" and "user:<name>" -> failure times
}

func NewManager(st *store.Store, ttl time.Duration) (*Manager, error) {
	dummy, err := HashPassword("dummy-password-for-timing")
	if err != nil {
		return nil, err
	}
	return &Manager{Store: st, TTL: ttl, dummyHash: dummy, failures: map[string][]time.Time{}}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is how session tokens are stored and looked up.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func (m *Manager) limited(keys ...string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-failureWindow)
	for _, k := range keys {
		recent := m.failures[k][:0]
		for _, t := range m.failures[k] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(m.failures, k)
		} else {
			m.failures[k] = recent
		}
		if len(recent) >= maxFailures {
			return true
		}
	}
	return false
}

func (m *Manager) recordFailure(keys ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		m.failures[k] = append(m.failures[k], time.Now())
	}
}

func (m *Manager) clearFailures(keys ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.failures, k)
	}
}

// Login checks credentials and returns a new session token and its CSRF token.
func (m *Manager) Login(ctx context.Context, name, password, clientIP string) (token, csrf string, err error) {
	keys := []string{"ip:" + clientIP, "user:" + name}
	if m.limited(keys...) {
		return "", "", ErrRateLimited
	}
	u, err := m.Store.GetUser(ctx, name)
	hash := u.PwHash
	if errors.Is(err, store.ErrNotFound) {
		hash = m.dummyHash
	} else if err != nil {
		return "", "", err
	}
	ok, verr := VerifyPassword(hash, password)
	if err != nil || verr != nil || !ok {
		m.recordFailure(keys...)
		return "", "", ErrBadCredentials
	}
	m.clearFailures(keys...)

	if token, err = randomToken(); err != nil {
		return "", "", err
	}
	if csrf, err = randomToken(); err != nil {
		return "", "", err
	}
	if err := m.Store.CreateSession(ctx, HashToken(token), u.ID, csrf, time.Now().Add(m.TTL)); err != nil {
		return "", "", err
	}
	return token, csrf, nil
}

// Session returns the live session for token.
func (m *Manager) Session(ctx context.Context, token string) (store.Session, error) {
	if token == "" {
		return store.Session{}, ErrNoSession
	}
	s, err := m.Store.GetSession(ctx, HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return s, ErrNoSession
	}
	return s, err
}

func (m *Manager) Logout(ctx context.Context, token string) error {
	return m.Store.DeleteSession(ctx, HashToken(token))
}

// Janitor removes expired sessions periodically until ctx is cancelled.
func (m *Manager) Janitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Store.DeleteExpiredSessions(ctx)
		}
	}
}
