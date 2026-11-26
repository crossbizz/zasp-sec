// Package transit signs recovery manifests with OpenBao Transit.
package transit

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const refPrefix = "openbao:transit/v"

var (
	keyPattern   = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
	errAuthority = errors.New("recovery transit signing authority unavailable")
)

func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// ParseReference accepts only the fixed Transit mount and a canonical numeric version.
func ParseReference(ref string) (key, version string, ok bool) {
	suffix, ok := strings.CutPrefix(ref, refPrefix)
	if !ok {
		return "", "", false
	}
	version, key, ok = strings.Cut(suffix, "/")
	n, err := strconv.ParseInt(version, 10, 32)
	if !ok || err != nil || n < 1 || strconv.FormatInt(n, 10) != version || !ValidKey(key) {
		return "", "", false
	}
	return key, version, true
}

type Client interface {
	Do(context.Context, string, string, any, any) error
}

type Authority struct {
	client Client
	key    string
}

func New(client Client, key string) (*Authority, error) {
	if client == nil || !ValidKey(key) {
		return nil, errAuthority
	}
	return &Authority{client: client, key: key}, nil
}

type keyMetadata struct {
	Data struct {
		Name                 string `json:"name"`
		Type                 string `json:"type"`
		LatestVersion        int32  `json:"latest_version"`
		MinDecryptionVersion int32  `json:"min_decryption_version"`
		SupportsSigning      bool   `json:"supports_signing"`
		Exportable           *bool  `json:"exportable"`
		AllowPlaintextBackup *bool  `json:"allow_plaintext_backup"`
		DeletionAllowed      *bool  `json:"deletion_allowed"`
	} `json:"data"`
}

func (a *Authority) latest(ctx context.Context) (int32, error) {
	var reply keyMetadata
	if ctx == nil || ctx.Err() != nil || a.client.Do(ctx, http.MethodGet, "transit/keys/"+a.key, nil, &reply) != nil {
		return 0, errAuthority
	}
	d := reply.Data
	if d.Name != a.key || d.Type != "ecdsa-p256" || !d.SupportsSigning || d.LatestVersion < 1 || d.MinDecryptionVersion < 0 || d.MinDecryptionVersion > 1 ||
		d.Exportable == nil || *d.Exportable || d.AllowPlaintextBackup == nil || *d.AllowPlaintextBackup || d.DeletionAllowed == nil || *d.DeletionAllowed {
		return 0, errAuthority
	}
	return d.LatestVersion, nil
}

func (a *Authority) Ready(ctx context.Context) error {
	_, err := a.latest(ctx)
	return err
}

type signingRequest struct {
	Input               string `json:"input"`
	KeyVersion          int32  `json:"key_version,omitempty"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
	Signature           string `json:"signature,omitempty"`
}

func validDER(sig []byte) bool {
	if len(sig) < 8 || len(sig) > 72 {
		return false
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		return false
	}
	canonical, err := asn1.Marshal(pair)
	if err != nil || !bytes.Equal(canonical, sig) {
		return false
	}
	order := elliptic.P256().Params().N
	return pair.R.Sign() > 0 && pair.S.Sign() > 0 && pair.R.Cmp(order) < 0 && pair.S.Cmp(order) < 0
}

func (a *Authority) Sign(ctx context.Context, payload []byte) (string, []byte, error) {
	if len(payload) == 0 || len(payload) > 56<<10 {
		return "", nil, errAuthority
	}
	version, err := a.latest(ctx)
	if err != nil {
		return "", nil, err
	}
	v := strconv.FormatInt(int64(version), 10)
	req := signingRequest{Input: base64.StdEncoding.EncodeToString(payload), KeyVersion: version, MarshalingAlgorithm: "asn1"}
	var reply struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if a.client.Do(ctx, http.MethodPost, "transit/sign/"+a.key+"/sha2-256", req, &reply) != nil || ctx.Err() != nil {
		return "", nil, errAuthority
	}
	encoded, ok := strings.CutPrefix(reply.Data.Signature, "vault:v"+v+":")
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || !validDER(signature) || base64.StdEncoding.EncodeToString(signature) != encoded {
		return "", nil, errAuthority
	}
	return refPrefix + v + "/" + a.key, signature, nil
}

func (a *Authority) Verify(ctx context.Context, ref string, payload, signature []byte) error {
	key, version, ok := ParseReference(ref)
	if ctx == nil || ctx.Err() != nil || !ok || key != a.key || len(payload) == 0 || len(payload) > 56<<10 || !validDER(signature) {
		return errAuthority
	}
	req := signingRequest{Input: base64.StdEncoding.EncodeToString(payload), MarshalingAlgorithm: "asn1",
		Signature: "vault:v" + version + ":" + base64.StdEncoding.EncodeToString(signature)}
	var reply struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	if a.client.Do(ctx, http.MethodPost, "transit/verify/"+a.key+"/sha2-256", req, &reply) != nil || ctx.Err() != nil || !reply.Data.Valid {
		return errAuthority
	}
	return nil
}
