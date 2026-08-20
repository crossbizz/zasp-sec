package sensor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	SensorTokenAudienceEventIngest = "event-ingest"
	sensorTokenPrefix              = "zasp_sensor_v1."
	sensorTokenLocatorBytes        = 16
	sensorTokenSecretBytes         = 32
	sensorTokenSaltBytes           = 32
	sensorTokenHashDomain          = "zasp-sensor-token-hash-v1\x00"
)

// TokenCredential owns the transient wire-token material. Call Destroy after
// the database authentication boundary has consumed the returned parts.
type TokenCredential struct {
	mu        sync.Mutex
	locator   [sensorTokenLocatorBytes]byte
	secret    [sensorTokenSecretBytes]byte
	destroyed bool
}

func (*TokenCredential) String() string   { return "[REDACTED]" }
func (*TokenCredential) GoString() string { return "[REDACTED]" }

func NewTokenCredential(locator, secret []byte) (*TokenCredential, error) {
	if len(locator) != sensorTokenLocatorBytes || len(secret) != sensorTokenSecretBytes || zeroBytes(locator) || zeroBytes(secret) {
		return nil, ErrInvalid
	}
	credential := &TokenCredential{}
	copy(credential.locator[:], locator)
	copy(credential.secret[:], secret)
	return credential, nil
}

func GenerateTokenCredential(reader io.Reader) (*TokenCredential, error) {
	if reader == nil {
		return nil, ErrInvalid
	}
	locator := make([]byte, sensorTokenLocatorBytes)
	secret := make([]byte, sensorTokenSecretBytes)
	defer clear(locator)
	defer clear(secret)
	if _, err := io.ReadFull(reader, locator); err != nil {
		return nil, ErrInvalid
	}
	if _, err := io.ReadFull(reader, secret); err != nil {
		return nil, ErrInvalid
	}
	return NewTokenCredential(locator, secret)
}

func ParseTokenCredential(value string) (*TokenCredential, error) {
	if !strings.HasPrefix(value, sensorTokenPrefix) || strings.TrimSpace(value) != value {
		return nil, ErrInvalid
	}
	encodedLocator, encodedSecret, found := strings.Cut(strings.TrimPrefix(value, sensorTokenPrefix), ".")
	if !found || strings.Contains(encodedSecret, ".") || encodedLocator == "" || encodedSecret == "" {
		return nil, ErrInvalid
	}
	locator, err := base64.RawURLEncoding.DecodeString(encodedLocator)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(locator)
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(secret)
	if base64.RawURLEncoding.EncodeToString(locator) != encodedLocator || base64.RawURLEncoding.EncodeToString(secret) != encodedSecret {
		return nil, ErrInvalid
	}
	return NewTokenCredential(locator, secret)
}

func (credential *TokenCredential) Wire() (string, error) {
	if credential == nil {
		return "", ErrInvalid
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return "", ErrInvalid
	}
	return sensorTokenPrefix + base64.RawURLEncoding.EncodeToString(credential.locator[:]) + "." + base64.RawURLEncoding.EncodeToString(credential.secret[:]), nil
}

func (credential *TokenCredential) Parts() ([]byte, []byte, error) {
	if credential == nil {
		return nil, nil, ErrInvalid
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return nil, nil, ErrInvalid
	}
	return append([]byte(nil), credential.locator[:]...), append([]byte(nil), credential.secret[:]...), nil
}

func (credential *TokenCredential) LocatorDigest() ([sha256.Size]byte, error) {
	if credential == nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256(credential.locator[:]), nil
}

func (credential *TokenCredential) Hash(audience string, tokenID domain.ProductID, generation uint64, salt []byte) ([sha256.Size]byte, error) {
	if credential == nil || audience != SensorTokenAudienceEventIngest || tokenID.IsZero() || generation == 0 || len(salt) != sensorTokenSaltBytes || zeroBytes(salt) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed {
		return [sha256.Size]byte{}, ErrInvalid
	}
	generationBytes := [8]byte{}
	binary.BigEndian.PutUint64(generationBytes[:], generation)
	hash := sha256.New()
	_, _ = hash.Write([]byte(sensorTokenHashDomain))
	_, _ = hash.Write([]byte(audience))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(tokenID.String()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(generationBytes[:])
	_, _ = hash.Write(salt)
	_, _ = hash.Write(credential.secret[:])
	result := [sha256.Size]byte{}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func (credential *TokenCredential) Destroy() {
	if credential == nil {
		return
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	clear(credential.locator[:])
	clear(credential.secret[:])
	credential.destroyed = true
}

func zeroBytes(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
