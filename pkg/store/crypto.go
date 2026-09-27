package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MasterKeySize is the AES-256 key length. The master key lives in a secret
// file outside the database (MASTER_KEY_FILE) and is never written to it.
const MasterKeySize = 32

var ErrNoMasterKey = errors.New("store opened without master key")

// NewMasterKey returns a random master key, hex-encoded for the secret file.
func NewMasterKey() (string, error) {
	k := make([]byte, MasterKeySize)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// LoadMasterKey reads a hex master key from path. The file must not be
// readable by group or others.
func LoadMasterKey(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %v are too open, use chmod 600", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != MasterKeySize {
		return nil, fmt.Errorf("%s: want %d hex-encoded bytes", path, MasterKeySize)
	}
	return key, nil
}

func newAEAD(masterKey []byte) (cipher.AEAD, error) {
	if masterKey == nil {
		return nil, nil
	}
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes", MasterKeySize)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds a ciphertext to its row and slot, so a value copied to another
// device or slot fails to decrypt.
func aad(deviceID, slot string) []byte {
	return []byte("iot_server_go/device-key/v1|" + deviceID + "|" + slot)
}

// seal returns nonce||ciphertext, or nil for an empty plaintext.
func (s *Store) seal(deviceID, slot, plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	if s.aead == nil {
		return nil, ErrNoMasterKey
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(plaintext), aad(deviceID, slot)), nil
}

func (s *Store) open(deviceID, slot string, sealed []byte) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	if s.aead == nil {
		return "", ErrNoMasterKey
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return "", fmt.Errorf("device %s %s key: ciphertext too short", deviceID, slot)
	}
	pt, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad(deviceID, slot))
	if err != nil {
		return "", fmt.Errorf("device %s %s key: cannot decrypt (wrong master key?)", deviceID, slot)
	}
	return string(pt), nil
}
