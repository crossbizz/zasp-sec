package authorization

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type IdentityDeployment struct {
	PublicOrigin, ProviderBaseURL, ProjectID, ConfiguredOrganization, Mode, OrganizationID string
}

func (d IdentityDeployment) Audience() (string, error) {
	canonical := func(raw string) (string, bool) {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			return "", false
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && (u.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
			return "", false
		}
		return strings.TrimSuffix(u.String(), "/"), true
	}
	origin, ok := canonical(d.PublicOrigin)
	base, baseOK := canonical(d.ProviderBaseURL)
	if !ok || !baseOK || !strings.HasPrefix(d.ProjectID, "project-") || !strings.HasPrefix(d.ConfiguredOrganization, "organization-") || len(d.ProjectID) > 128 || len(d.ConfiguredOrganization) > 128 {
		return "", ErrInvalid
	}
	if d.Mode == "saas" {
		if d.OrganizationID != "" {
			return "", ErrInvalid
		}
	} else if d.Mode == "single_tenant" {
		if _, err := domain.ParseProductID(d.OrganizationID); err != nil {
			return "", ErrInvalid
		}
	} else {
		return "", ErrInvalid
	}
	b, _ := json.Marshal([]string{origin, base, d.ProjectID, d.ConfiguredOrganization, d.Mode, d.OrganizationID})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (d IdentityDeployment) OrganizationPin() string {
	if d.Mode == "single_tenant" {
		return d.ConfiguredOrganization
	}
	return ""
}

type IdentityRegistration struct {
	Version         string `json:"version"`
	Epoch           int64  `json:"epoch"`
	Audience        string `json:"audience"`
	Project         string `json:"project"`
	APIPrincipal    string `json:"api_principal"`
	OrganizationPin string `json:"organization_pin"`
}

type identityPurposeKey struct {
	key     [32]byte
	version string
	purpose string
}
type IdentitySessionKey struct{ identityPurposeKey }
type IdentityWebhookKey struct{ identityPurposeKey }

func deriveIdentityKey(seed []byte, purpose string) (identityPurposeKey, error) {
	if len(seed) < 32 || len(seed) > 4096 {
		return identityPurposeKey{}, ErrInvalid
	}
	m := hmac.New(sha256.New, seed)
	_, _ = m.Write([]byte("zasp-identity-" + purpose + "-key-v1"))
	k := identityPurposeKey{purpose: purpose}
	copy(k.key[:], m.Sum(nil))
	h := sha256.Sum256(k.key[:])
	k.version = hex.EncodeToString(h[:])
	return k, nil
}
func NewIdentitySessionKey(seed []byte) (*IdentitySessionKey, error) {
	k, e := deriveIdentityKey(seed, "session")
	if e != nil {
		return nil, e
	}
	return &IdentitySessionKey{k}, nil
}
func NewIdentityWebhookKey(seed []byte) (*IdentityWebhookKey, error) {
	k, e := deriveIdentityKey(seed, "webhook")
	if e != nil {
		return nil, e
	}
	return &IdentityWebhookKey{k}, nil
}
func (k identityPurposeKey) Version() string  { return k.version }
func (k identityPurposeKey) Verifier() []byte { return append([]byte(nil), k.key[:]...) }
func (k identityPurposeKey) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[identity purpose key]"))
}

type IdentitySessionAdmission struct {
	Registration                                             IdentityRegistration
	Profile, StateDigest, AttemptID, TokenDigest, CSRFDigest string
	VerifiedAt                                               time.Time
}
type IdentityWebhookAdmission struct {
	Registration                 IdentityRegistration
	Profile, BodyDigest, AuditID string
	VerifiedAt                   time.Time
}

func (k identityPurposeKey) body(r IdentityRegistration, profile string, now time.Time) (map[string]any, error) {
	if k.version == "" || r.Version != k.version || r.Epoch < 1 || !identityHex(r.Audience) || !identityHex(profile) || r.APIPrincipal == "" || r.Project == "" || now.IsZero() {
		return nil, ErrInvalid
	}
	ms := now.UnixMilli()
	return map[string]any{"domain": "zasp-identity-" + k.purpose + "-attestation-v1", "version": k.version, "epoch": r.Epoch, "audience": r.Audience, "project": r.Project, "profile": profile, "issued_at": ms, "expires_at": ms + 60000}, nil
}
func identityHex(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func (k identityPurposeKey) envelope(value map[string]any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 65536 {
		return nil, ErrInvalid
	}
	m := hmac.New(sha256.New, k.key[:])
	_, _ = m.Write([]byte("zasp-identity-" + k.purpose + "-attestation-v1\x00"))
	_, _ = m.Write(body)
	return json.Marshal(struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{body, k.version, hex.EncodeToString(m.Sum(nil))})
}

// Only the provider adapter can construct a nonzero ExternalPrincipal. The
// session issuer receives it from the just-completed OAuth/session call chain.
func (k *IdentitySessionKey) SignSession(external identity.ExternalPrincipal, a IdentitySessionAdmission) ([]byte, error) {
	if k == nil || external.MemberReference() == "" || external.SessionReference() == "" || !identityHex(a.StateDigest) || !identityHex(a.AttemptID) || !identityHex(a.TokenDigest) || !identityHex(a.CSRFDigest) || external.AuthenticatedAt().After(a.VerifiedAt) || !external.ExpiresAt().After(a.VerifiedAt) || external.ExpiresAt().After(a.VerifiedAt.Add(24*time.Hour)) || a.Registration.OrganizationPin != "" && external.OrganizationReference() != a.Registration.OrganizationPin {
		return nil, ErrInvalid
	}
	body, err := k.body(a.Registration, a.Profile, a.VerifiedAt)
	if err != nil {
		return nil, err
	}
	body["organization"], body["member"], body["session"], body["groups"] = external.OrganizationReference(), external.MemberReference(), external.SessionReference(), external.GroupReferences()
	body["state_digest"], body["attempt_id"], body["token_digest"], body["csrf_digest"] = a.StateDigest, a.AttemptID, a.TokenDigest, a.CSRFDigest
	body["authenticated_at"], body["external_expires_at"], body["verified_at"] = external.AuthenticatedAt().UnixMilli(), external.ExpiresAt().UnixMilli(), a.VerifiedAt.UnixMilli()
	return k.envelope(body)
}

// The webhook issuer is held only by the verifier's successful delivery path.
func (k *IdentityWebhookKey) SignDeprovision(event identity.WebhookEvent, a IdentityWebhookAdmission) ([]byte, error) {
	if k == nil || event.Kind() != "scim.member.delete" || event.Vertical != "B2B" || event.ProjectID != a.Registration.Project || !identityHex(a.BodyDigest) || a.Registration.OrganizationPin != "" && event.Details.OrganizationReference != a.Registration.OrganizationPin {
		return nil, ErrInvalid
	}
	if _, err := domain.ParseProductID(a.AuditID); err != nil {
		return nil, ErrInvalid
	}
	body, err := k.body(a.Registration, a.Profile, a.VerifiedAt)
	if err != nil {
		return nil, err
	}
	body["organization"], body["member"], body["event_id"], body["event_kind"] = event.Details.OrganizationReference, event.ObjectID, event.EventID, event.Kind()
	body["body_digest"], body["audit_id"] = a.BodyDigest, a.AuditID
	return k.envelope(body)
}
