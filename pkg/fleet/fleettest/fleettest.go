// Package fleettest builds store-backed vaults for tests.
package fleettest

import (
	"bytes"
	"context"
	"path/filepath"
	"sort"
	"testing"

	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/store"
)

// MasterKey is a fixed test master key.
var MasterKey = bytes.Repeat([]byte{0x42}, store.MasterKeySize)

// Dev describes one test device.
type Dev struct {
	IP  string
	Key string
}

// OpenStore opens a temporary store.
func OpenStore(t testing.TB) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// New returns a vault over a temporary store holding devs.
func New(t testing.TB, devs map[string]Dev) (*fleet.Vault, *store.Store) {
	t.Helper()
	st := OpenStore(t)
	ids := make([]string, 0, len(devs))
	for id := range devs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := st.InsertDevice(context.Background(), store.Device{ID: id, IP: devs[id].IP, HMACKey: devs[id].Key}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := fleet.New(st)
	if err != nil {
		t.Fatal(err)
	}
	return v, st
}
