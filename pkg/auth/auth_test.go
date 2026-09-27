package auth

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iot_server_go/pkg/store"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if ok, _ := VerifyPassword(h, "correct horse battery"); !ok {
		t.Fatal("correct password rejected")
	}
	if ok, _ := VerifyPassword(h, "correct horse batterY"); ok {
		t.Fatal("wrong password accepted")
	}
	if h2, _ := HashPassword("correct horse battery"); h2 == h {
		t.Fatal("hash is not salted")
	}
	if err := CheckPasswordPolicy("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func setup(t *testing.T) (*Manager, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.db")
	st, err := store.Open(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h, _ := HashPassword("correct horse battery")
	st.CreateUser(context.Background(), "admin", h)
	m, err := NewManager(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return m, p
}

func TestLoginSessionLogout(t *testing.T) {
	m, dbPath := setup(t)
	ctx := context.Background()

	if _, _, err := m.Login(ctx, "admin", "wrong password!", "1.2.3.4"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := m.Login(ctx, "nobody", "correct horse battery", "1.2.3.4"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	token, csrf, err := m.Login(ctx, "admin", "correct horse battery", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Session(ctx, token)
	if err != nil || s.UserName != "admin" || s.CSRF != csrf {
		t.Fatalf("Session = %+v, %v", s, err)
	}
	if _, err := m.Session(ctx, token+"x"); !errors.Is(err, ErrNoSession) {
		t.Fatal("forged token accepted")
	}

	// The raw token is never written to disk.
	m.Store.Close()
	for _, f := range []string{dbPath, dbPath + "-wal"} {
		raw, _ := os.ReadFile(f)
		if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte("correct horse battery")) {
			t.Fatalf("plaintext token or password in %s", f)
		}
	}
	st, _ := store.Open(dbPath, nil)
	defer st.Close()
	m.Store = st

	if err := m.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Session(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatal("session survived logout")
	}
}

func TestExpiredSession(t *testing.T) {
	m, _ := setup(t)
	m.TTL = -time.Second
	token, _, err := m.Login(context.Background(), "admin", "correct horse battery", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Session(context.Background(), token); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired session accepted")
	}
}

func TestRateLimit(t *testing.T) {
	m, _ := setup(t)
	ctx := context.Background()
	for i := 0; i < maxFailures; i++ {
		m.Login(ctx, "admin", "wrong password!", "1.2.3.4")
	}
	// Even the right password is refused while limited, by IP and by user.
	if _, _, err := m.Login(ctx, "admin", "correct horse battery", "1.2.3.4"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("same IP: %v", err)
	}
	if _, _, err := m.Login(ctx, "admin", "correct horse battery", "5.6.7.8"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("same user, other IP: %v", err)
	}
	// Failures expire.
	for k, times := range m.failures {
		for i := range times {
			times[i] = times[i].Add(-failureWindow - time.Second)
		}
		m.failures[k] = times
	}
	if _, _, err := m.Login(ctx, "admin", "correct horse battery", "1.2.3.4"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}
