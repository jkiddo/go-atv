package hap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Credentials are the long-term keys and identifiers produced by HAP pairing.
// The string form (hex fields joined by ":") is identical to pyatv's
// credential format, so credentials can be moved between goatv and pyatv.
type Credentials struct {
	LTPK     []byte // device (Apple TV) long-term public key
	LTSK     []byte // our long-term secret key (Ed25519 seed)
	ATVID    []byte // device pairing identifier
	ClientID []byte // our pairing identifier
}

// String encodes credentials in pyatv's compatible format. Legacy AirPlay
// credentials use client-id:seed; HAP credentials use four fields.
func (c Credentials) String() string {
	if c.IsLegacy() {
		return strings.Join([]string{
			hex.EncodeToString(c.ClientID),
			hex.EncodeToString(c.LTSK),
		}, ":")
	}
	return strings.Join([]string{
		hex.EncodeToString(c.LTPK),
		hex.EncodeToString(c.LTSK),
		hex.EncodeToString(c.ATVID),
		hex.EncodeToString(c.ClientID),
	}, ":")
}

// ParseCredentials decodes pyatv's two-part legacy or four-part HAP format.
func ParseCredentials(s string) (Credentials, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 && len(parts) != 4 {
		return Credentials{}, fmt.Errorf("hap: expected 2 or 4 credential parts, got %d", len(parts))
	}
	fields := make([][]byte, len(parts))
	for i, part := range parts {
		b, err := hex.DecodeString(part)
		if err != nil {
			return Credentials{}, fmt.Errorf("hap: invalid credentials hex: %w", err)
		}
		fields[i] = b
	}
	if len(fields) == 2 {
		c := Credentials{ClientID: fields[0], LTSK: fields[1]}
		if !c.IsLegacy() {
			return Credentials{}, fmt.Errorf("hap: invalid legacy credentials")
		}
		return c, nil
	}
	c := Credentials{LTPK: fields[0], LTSK: fields[1], ATVID: fields[2], ClientID: fields[3]}
	if !c.IsHAP() {
		return Credentials{}, fmt.Errorf("hap: incomplete credentials")
	}
	return c, nil
}

// IsLegacy reports whether credentials use legacy AirPlay v1 authentication.
func (c Credentials) IsLegacy() bool {
	return len(c.LTPK) == 0 && len(c.ATVID) == 0 && len(c.LTSK) == 32 && len(c.ClientID) == 8
}

// IsHAP reports whether credentials contain all HAP long-term keys and IDs.
func (c Credentials) IsHAP() bool {
	return len(c.LTPK) > 0 && len(c.LTSK) > 0 && len(c.ATVID) > 0 && len(c.ClientID) > 0
}

// LoadCredentials reads credentials from a file written by SaveCredentials.
func LoadCredentials(path string) (Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, err
	}
	return ParseCredentials(string(data))
}

// SaveCredentials writes credentials to path with owner-only permissions,
// creating parent directories as needed.
func SaveCredentials(path string, c Credentials) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(c.String()+"\n"), 0o600)
}

// NewPairingID generates a random UUIDv4 string identifier, matching the
// pairing id format pyatv uses.
func NewPairingID() ([]byte, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return nil, err
	}
	u[6] = (u[6] & 0x0F) | 0x40
	u[8] = (u[8] & 0x3F) | 0x80
	s := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	return []byte(s), nil
}
