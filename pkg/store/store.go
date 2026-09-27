// Package store is the SQLite persistence layer: devices (with encrypted HMAC
// keys), admin users, sessions and the audit log.
package store

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("not found")

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

// Open opens (creating if needed) the database at path. masterKey may be nil
// for user management commands; device key operations then fail.
func Open(path string, masterKey []byte) (*Store, error) {
	aead, err := newAEAD(masterKey)
	if err != nil {
		return nil, err
	}
	// Create the file ourselves so it is never world-readable.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; also keeps pragmas on a single connection
	s := &Store{db: db, aead: aead}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %s", name)
		}
		if v <= current {
			continue
		}
		body, _ := migrations.ReadFile(name)
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %w", base, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (?)`, v); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Device is a decrypted device row. It only lives in memory.
type Device struct {
	ID           string
	IP           string
	KeyID        string
	HMACKey      string
	PrevKeyID    string
	PrevHMACKey  string
	PendingKeyID string
	PendingHMAC  string
	WGPubKey     string
	CreatedAt    time.Time
	Disabled     bool
}

// ListDevices returns every device, including disabled ones, with keys decrypted.
func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ip, key_id, hmac_enc, prev_key_id, prev_hmac_enc,
		pending_key_id, pending_hmac_enc, wg_pubkey, created_at, disabled FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var cur, prev, pending []byte
		var created int64
		if err := rows.Scan(&d.ID, &d.IP, &d.KeyID, &cur, &d.PrevKeyID, &prev,
			&d.PendingKeyID, &pending, &d.WGPubKey, &created, &d.Disabled); err != nil {
			return nil, err
		}
		d.CreatedAt = time.Unix(created, 0)
		if d.HMACKey, err = s.open(d.ID, "cur", cur); err != nil {
			return nil, err
		}
		if d.PrevHMACKey, err = s.open(d.ID, "prev", prev); err != nil {
			return nil, err
		}
		if d.PendingHMAC, err = s.open(d.ID, "pending", pending); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) sealAll(d Device) (cur, prev, pending []byte, err error) {
	if cur, err = s.seal(d.ID, "cur", d.HMACKey); err != nil {
		return
	}
	if prev, err = s.seal(d.ID, "prev", d.PrevHMACKey); err != nil {
		return
	}
	pending, err = s.seal(d.ID, "pending", d.PendingHMAC)
	return
}

// InsertDevice adds a new device. It fails if the ID or IP is already taken,
// including by a disabled device.
func (s *Store) InsertDevice(ctx context.Context, d Device) error {
	return s.InsertDevices(ctx, []Device{d})
}

// InsertDevices adds all devices in one transaction: all or nothing.
func (s *Store) InsertDevices(ctx context.Context, ds []Device) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, d := range ds {
		cur, prev, pending, err := s.sealAll(d)
		if err != nil {
			return err
		}
		if d.CreatedAt.IsZero() {
			d.CreatedAt = time.Now()
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO devices (id, ip, key_id, hmac_enc, prev_key_id, prev_hmac_enc,
			pending_key_id, pending_hmac_enc, wg_pubkey, created_at, disabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			d.ID, d.IP, d.KeyID, cur, d.PrevKeyID, prev, d.PendingKeyID, pending, d.WGPubKey, d.CreatedAt.Unix(), d.Disabled)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("device %s: ID or IP already in use", d.ID)
			}
			return err
		}
	}
	return tx.Commit()
}

// UpdateDeviceKeys persists the key slots of an existing device.
func (s *Store) UpdateDeviceKeys(ctx context.Context, d Device) error {
	cur, prev, pending, err := s.sealAll(d)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET key_id=?, hmac_enc=?, prev_key_id=?, prev_hmac_enc=?,
		pending_key_id=?, pending_hmac_enc=? WHERE id=?`,
		d.KeyID, cur, d.PrevKeyID, prev, d.PendingKeyID, pending, d.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetDeviceDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET disabled=? WHERE id=?`, disabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountDevices(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&n)
	return n, err
}

// ---- users ----

type User struct {
	ID        int64
	Name      string
	PwHash    string
	CreatedAt time.Time
}

func (s *Store) CreateUser(ctx context.Context, name, pwHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (name, pw_hash, created_at) VALUES (?,?,?)`, name, pwHash, time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("user %q already exists", name)
	}
	return err
}

func (s *Store) GetUser(ctx context.Context, name string) (User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, pw_hash, created_at FROM users WHERE name=?`, name).
		Scan(&u.ID, &u.Name, &u.PwHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt = time.Unix(created, 0)
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = time.Unix(created, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword changes a password and ends all of the user's sessions.
func (s *Store) SetPassword(ctx context.Context, name, pwHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET pw_hash=? WHERE name=?`, pwHash, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE name=?)`, name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- sessions ----

type Session struct {
	UserName  string
	CSRF      string
	ExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, csrf string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, csrf, expires_at, created_at) VALUES (?,?,?,?,?)`,
		tokenHash, userID, csrf, expires.Unix(), time.Now().Unix())
	return err
}

// GetSession returns a live session; expired sessions are reported as ErrNotFound.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (Session, error) {
	var sess Session
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT u.name, s.csrf, s.expires_at FROM sessions s
		JOIN users u ON u.id = s.user_id WHERE s.token_hash=? AND s.expires_at > ?`, tokenHash, time.Now().Unix()).
		Scan(&sess.UserName, &sess.CSRF, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	sess.ExpiresAt = time.Unix(exp, 0)
	return sess, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

// ---- audit ----

type AuditEntry struct {
	At       time.Time `json:"at"`
	User     string    `json:"user"`
	DeviceID string    `json:"device_id,omitempty"`
	Action   string    `json:"action"`
	Result   string    `json:"result,omitempty"`
}

func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at, user, device_id, action, result) VALUES (?,?,?,?,?)`,
		time.Now().Unix(), e.User, e.DeviceID, e.Action, e.Result)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, user, device_id, action, result FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.User, &e.DeviceID, &e.Action, &e.Result); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
