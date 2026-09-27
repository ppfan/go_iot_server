// Package fleet holds per-device identities and HMAC keys. The SQLite store is
// the source of truth; the vault keeps a decrypted in-memory copy of the
// enabled devices so request verification never touches the database.
package fleet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/store"
)

var (
	ErrUnknownDevice = errors.New("unknown device")
	ErrIPMismatch    = errors.New("source IP does not match device")
	ErrBadSignature  = errors.New("bad signature")
)

// VPN plan: .1 relay, .2 control room, .3-.254 devices.
var (
	fleetSubnet = netip.MustParsePrefix("10.10.0.0/24")
	relayIP     = netip.MustParseAddr("10.10.0.1")
	controlIP   = netip.MustParseAddr("10.10.0.2")
	broadcastIP = netip.MustParseAddr("10.10.0.255")

	// Device IDs end up in NVS CSV files and HTTP headers: keep them plain.
	deviceIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

// ValidateDeviceID checks an ID is safe for NVS CSV, headers and URLs.
func ValidateDeviceID(id string) error {
	if !deviceIDRe.MatchString(id) {
		return fmt.Errorf("device ID %q: use 1-32 letters, digits, '.', '_' or '-'", id)
	}
	return nil
}

// ValidateDeviceIP checks ip is a device address (10.10.0.3-254).
func ValidateDeviceIP(ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !fleetSubnet.Contains(a) || a == relayIP || a == controlIP ||
		a == fleetSubnet.Addr() || a == broadcastIP {
		return netip.Addr{}, fmt.Errorf("IP %q is not a device address (10.10.0.3-254)", ip)
	}
	return a, nil
}

// Device is a read-only snapshot of one device's identity (no key material).
type Device struct {
	ID              string
	IP              netip.Addr
	KeyID           string
	RotationPending bool
}

type Vault struct {
	store *store.Store

	mu      sync.RWMutex
	devices map[string]*store.Device
	byIP    map[netip.Addr]string
}

// New loads the enabled devices from st.
func New(st *store.Store) (*Vault, error) {
	v := &Vault{store: st}
	if err := v.Reload(context.Background()); err != nil {
		return nil, err
	}
	return v, nil
}

// Reload rebuilds the in-memory copy from the store.
func (v *Vault) Reload(ctx context.Context) error {
	rows, err := v.store.ListDevices(ctx)
	if err != nil {
		return err
	}
	devices := make(map[string]*store.Device)
	byIP := make(map[netip.Addr]string)
	for i := range rows {
		d := &rows[i]
		if d.Disabled {
			continue
		}
		ip, err := ValidateDeviceIP(d.IP)
		if err != nil {
			return fmt.Errorf("device %q: %w", d.ID, err)
		}
		devices[d.ID] = d
		byIP[ip] = d.ID
	}
	v.mu.Lock()
	v.devices, v.byIP = devices, byIP
	v.mu.Unlock()
	return nil
}

func (v *Vault) IDs() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := make([]string, 0, len(v.devices))
	for id := range v.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (v *Vault) Get(id string) (Device, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	d, ok := v.devices[id]
	if !ok {
		return Device{}, false
	}
	return Device{ID: id, IP: netip.MustParseAddr(d.IP), KeyID: d.KeyID, RotationPending: d.PendingHMAC != ""}, true
}

// IsDeviceIP reports whether ip belongs to an enabled device.
func (v *Vault) IsDeviceIP(ip netip.Addr) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.byIP[ip.Unmap()]
	return ok
}

// SigningKey returns the key the device currently expects.
func (v *Vault) SigningKey(id string) (key, keyID string, err error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	d, ok := v.devices[id]
	if !ok {
		return "", "", ErrUnknownDevice
	}
	return d.HMACKey, d.KeyID, nil
}

// Verify authenticates a request from device id arriving from src. It accepts the
// current key, the grace-period previous key, and a pending rotated key; a valid
// signature with the pending key means the device has rotated, so it is committed.
func (v *Vault) Verify(id string, src netip.Addr, body []byte, sigHex string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, ok := v.devices[id]
	if !ok {
		return ErrUnknownDevice
	}
	if netip.MustParseAddr(d.IP) != src.Unmap() {
		return ErrIPMismatch
	}
	if crypto.VerifyHMAC(d.HMACKey, body, sigHex) {
		return nil
	}
	if d.PrevHMACKey != "" && crypto.VerifyHMAC(d.PrevHMACKey, body, sigHex) {
		return nil
	}
	if d.PendingHMAC != "" && crypto.VerifyHMAC(d.PendingHMAC, body, sigHex) {
		return v.commitLocked(d)
	}
	return ErrBadSignature
}

// BeginRotation generates (or reuses, on retry) a pending key for id and persists
// it before it is sent, so a lost response never loses the key the device stored.
func (v *Vault) BeginRotation(id string) (key, keyID string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, ok := v.devices[id]
	if !ok {
		return "", "", ErrUnknownDevice
	}
	if d.PendingHMAC != "" {
		return d.PendingHMAC, d.PendingKeyID, nil
	}
	newKey, err := NewHMACKey()
	if err != nil {
		return "", "", err
	}
	next := *d
	next.PendingHMAC = newKey
	next.PendingKeyID = "k" + time.Now().UTC().Format("20060102T150405")
	if err := v.saveLocked(&next); err != nil {
		return "", "", err
	}
	return next.PendingHMAC, next.PendingKeyID, nil
}

// CommitRotation promotes the pending key after the device confirmed keyID.
func (v *Vault) CommitRotation(id, keyID string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, ok := v.devices[id]
	if !ok {
		return ErrUnknownDevice
	}
	if d.PendingHMAC == "" || d.PendingKeyID != keyID {
		return fmt.Errorf("no pending rotation %q for %s", keyID, id)
	}
	return v.commitLocked(d)
}

func (v *Vault) commitLocked(d *store.Device) error {
	next := *d
	next.PrevHMACKey, next.PrevKeyID = d.HMACKey, d.KeyID
	next.HMACKey, next.KeyID = d.PendingHMAC, d.PendingKeyID
	next.PendingHMAC, next.PendingKeyID = "", ""
	return v.saveLocked(&next)
}

// saveLocked writes d to the store and only then swaps it into memory, so a
// failed write leaves the previous keys in use.
func (v *Vault) saveLocked(d *store.Device) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.store.UpdateDeviceKeys(ctx, *d); err != nil {
		return err
	}
	v.devices[d.ID] = d
	return nil
}

// NewHMACKey returns a random 256-bit key as 64 hex chars (the firmware format).
func NewHMACKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// AddDevice validates and stores a new enabled device.
func (v *Vault) AddDevice(ctx context.Context, d store.Device) error {
	if err := ValidateDeviceID(d.ID); err != nil {
		return err
	}
	if _, err := ValidateDeviceIP(d.IP); err != nil {
		return err
	}
	if d.HMACKey == "" {
		return errors.New("device has no HMAC key")
	}
	d.Disabled = false
	if err := v.store.InsertDevice(ctx, d); err != nil {
		return err
	}
	return v.Reload(ctx)
}

// DisableDevice revokes a device. Its ID and IP stay reserved.
func (v *Vault) DisableDevice(ctx context.Context, id string) error {
	if err := v.store.SetDeviceDisabled(ctx, id, true); err != nil {
		return err
	}
	return v.Reload(ctx)
}

// ImportJSON copies devices from a legacy fleet_keys.json (written by
// esp32_wg_http/scripts/generate_device_identity.py) into an empty store.
// Both {"devices": {...}} and the flat {id: {...}} form are accepted.
func ImportJSON(ctx context.Context, st *store.Store, path string) (int, error) {
	if n, err := st.CountDevices(ctx); err != nil || n > 0 {
		return 0, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	type entry struct {
		IP             string `json:"ip"`
		HMACKey        string `json:"hmac_key"`
		KeyID          string `json:"key_id"`
		PrevHMACKey    string `json:"prev_hmac_key"`
		PrevKeyID      string `json:"prev_key_id"`
		PendingHMACKey string `json:"pending_hmac_key"`
		PendingKeyID   string `json:"pending_key_id"`
	}
	var wrapped struct {
		Devices map[string]entry `json:"devices"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	devices := wrapped.Devices
	if devices == nil {
		if err := json.Unmarshal(raw, &devices); err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
	}
	if len(devices) == 0 {
		return 0, fmt.Errorf("%s: no devices", path)
	}

	ids := make([]string, 0, len(devices))
	seenIP := map[string]string{}
	for id, e := range devices {
		if err := ValidateDeviceID(id); err != nil {
			return 0, err
		}
		if _, err := ValidateDeviceIP(e.IP); err != nil {
			return 0, fmt.Errorf("device %q: %w", id, err)
		}
		if other, dup := seenIP[e.IP]; dup {
			return 0, fmt.Errorf("devices %q and %q share IP %s", other, id, e.IP)
		}
		if e.HMACKey == "" {
			return 0, fmt.Errorf("device %q has no hmac_key", id)
		}
		seenIP[e.IP] = id
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]store.Device, 0, len(ids))
	for _, id := range ids {
		e := devices[id]
		rows = append(rows, store.Device{
			ID: id, IP: e.IP, KeyID: e.KeyID, HMACKey: e.HMACKey,
			PrevKeyID: e.PrevKeyID, PrevHMACKey: e.PrevHMACKey,
			PendingKeyID: e.PendingKeyID, PendingHMAC: e.PendingHMACKey,
		})
	}
	if err := st.InsertDevices(ctx, rows); err != nil {
		return 0, err
	}
	return len(ids), nil
}
