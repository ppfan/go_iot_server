package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	ctx       = context.Background()
	masterA   = bytes.Repeat([]byte{0xA5}, MasterKeySize)
	masterB   = bytes.Repeat([]byte{0x5A}, MasterKeySize)
	secretKey = strings.Repeat("ab", 32)
)

func openTemp(t *testing.T, key []byte) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cr.db")
	s, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func TestDeviceKeysEncryptedAtRest(t *testing.T) {
	s, p := openTemp(t, masterA)
	d := Device{ID: "n1", IP: "10.10.0.3", KeyID: "k1", HMACKey: secretKey, PendingKeyID: "k2", PendingHMAC: strings.Repeat("cd", 32)}
	if err := s.InsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].HMACKey != secretKey || got[0].PendingHMAC != d.PendingHMAC || got[0].PrevHMACKey != "" {
		t.Fatalf("round trip failed: %+v", got)
	}
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	for _, f := range []string{p, p + "-wal"} {
		raw, _ := os.ReadFile(f)
		if bytes.Contains(raw, []byte(secretKey)) {
			t.Fatalf("plaintext HMAC key found in %s", f)
		}
		if k, _ := hex.DecodeString(secretKey); bytes.Contains(raw, k) {
			t.Fatalf("raw HMAC key bytes found in %s", f)
		}
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("db file mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestWrongMasterKeyFails(t *testing.T) {
	s, p := openTemp(t, masterA)
	s.InsertDevice(ctx, Device{ID: "n1", IP: "10.10.0.3", HMACKey: secretKey})
	s.Close()
	s2, err := Open(p, masterB)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.ListDevices(ctx); err == nil {
		t.Fatal("decrypted with the wrong master key")
	}
}

func TestCiphertextBoundToRowAndSlot(t *testing.T) {
	s, _ := openTemp(t, masterA)
	s.InsertDevice(ctx, Device{ID: "n1", IP: "10.10.0.3", HMACKey: secretKey})
	s.InsertDevice(ctx, Device{ID: "n2", IP: "10.10.0.4", HMACKey: strings.Repeat("ef", 32)})
	// Copy n1's key ciphertext into n2's row, and into n1's prev slot.
	if _, err := s.db.Exec(`UPDATE devices SET hmac_enc=(SELECT hmac_enc FROM devices WHERE id='n1') WHERE id='n2'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListDevices(ctx); err == nil {
		t.Fatal("ciphertext moved to another device decrypted")
	}
	s.db.Exec(`DELETE FROM devices WHERE id='n2'`)
	s.db.Exec(`UPDATE devices SET prev_hmac_enc=hmac_enc WHERE id='n1'`)
	if _, err := s.ListDevices(ctx); err == nil {
		t.Fatal("ciphertext moved to another slot decrypted")
	}
}

func TestNoMasterKey(t *testing.T) {
	s, _ := openTemp(t, nil)
	if err := s.InsertDevice(ctx, Device{ID: "n1", IP: "10.10.0.3", HMACKey: secretKey}); err != ErrNoMasterKey {
		t.Fatalf("err = %v, want ErrNoMasterKey", err)
	}
	// User management works without it.
	if err := s.CreateUser(ctx, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	s, p := openTemp(t, masterA)
	s.CreateUser(ctx, "admin", "hash")
	s.Close()
	s2, err := Open(p, masterA)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.GetUser(ctx, "admin"); err != nil {
		t.Fatalf("data lost on reopen: %v", err)
	}
}

func TestUniqueIDAndIP(t *testing.T) {
	s, _ := openTemp(t, masterA)
	s.InsertDevice(ctx, Device{ID: "n1", IP: "10.10.0.3", HMACKey: secretKey, Disabled: true})
	if err := s.InsertDevice(ctx, Device{ID: "n2", IP: "10.10.0.3", HMACKey: secretKey}); err == nil {
		t.Fatal("IP of a disabled device was reused")
	}
	if err := s.InsertDevice(ctx, Device{ID: "n1", IP: "10.10.0.9", HMACKey: secretKey}); err == nil {
		t.Fatal("duplicate device ID accepted")
	}
}

func TestSessions(t *testing.T) {
	s, _ := openTemp(t, nil)
	s.CreateUser(ctx, "admin", "hash")
	u, _ := s.GetUser(ctx, "admin")
	live, expired := []byte("live-token-hash"), []byte("old-token-hash")
	s.CreateSession(ctx, live, u.ID, "csrf1", time.Now().Add(time.Hour))
	s.CreateSession(ctx, expired, u.ID, "csrf2", time.Now().Add(-time.Second))

	if sess, err := s.GetSession(ctx, live); err != nil || sess.UserName != "admin" || sess.CSRF != "csrf1" {
		t.Fatalf("live session: %+v %v", sess, err)
	}
	if _, err := s.GetSession(ctx, expired); err != ErrNotFound {
		t.Fatalf("expired session: %v", err)
	}
	// Password change ends sessions.
	s.SetPassword(ctx, "admin", "hash2")
	if _, err := s.GetSession(ctx, live); err != ErrNotFound {
		t.Fatal("session survived password change")
	}
	// Deleting a user cascades to sessions.
	s.CreateSession(ctx, live, u.ID, "csrf1", time.Now().Add(time.Hour))
	s.DeleteUser(ctx, "admin")
	if _, err := s.GetSession(ctx, live); err != ErrNotFound {
		t.Fatal("session survived user deletion")
	}
}
