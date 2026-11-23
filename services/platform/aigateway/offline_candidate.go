package aigateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const offlineSafeguardModel = "openai/gpt-oss-safeguard-20b"
const offlineQualificationMode = "offline_async_candidate"

type offlineManifest struct {
	Mode             string     `json:"qualification_mode"`
	Deployment       Deployment `json:"deployment"`
	Purpose          Purpose    `json:"purpose"`
	CorpusSHA256     string     `json:"corpus_sha256"`
	CredentialSHA256 string     `json:"credential_sha256"`
	BaseWeightOrigin string     `json:"base_weight_origin"`
	ZeroRetention    bool       `json:"zero_retention"`
	ExpiresAt        time.Time  `json:"expires_at"`
}

type OfflineCandidateReport struct {
	Mode           string              `json:"qualification_mode"`
	Model          string              `json:"model"`
	Organization   string              `json:"organization_id"`
	Workspace      string              `json:"workspace_id"`
	Environment    string              `json:"environment_id"`
	ManifestSHA256 string              `json:"attestation_sha256"`
	CorpusSHA256   string              `json:"corpus_sha256"`
	Measurement    QualificationResult `json:"measurement"`
}

type offlineSafeguard struct {
	vllm  *VLLMDriver
	token string
}

func (s offlineSafeguard) Evaluate(ctx context.Context, p Purpose, input json.RawMessage) (json.RawMessage, error) {
	rule, _ := LookupPurpose(PurposeHeuristicVerify)
	if ctx == nil || p != PurposeHeuristicVerify || len(input) > rule.MaxInputBytes || !json.Valid(input) {
		return nil, ErrInvalidRequest
	}
	// Give reasoning-mode batch observations time to complete for measurement.
	// The report retains the registered 200 ms P95 objective for this purpose.
	return s.vllm.exchange(ctx, p, input, 30*time.Second, 512, s.token)
}

func candidateDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func verifiedOfflineManifest(raw, signature, publicKey []byte, scope [3]string, token string, now time.Time) (offlineManifest, error) {
	var m offlineManifest
	if len(raw) > 4096 || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, raw, signature) || !json.Valid(raw) || uniqueJSON(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return m, ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil {
		return m, ErrInvalidRequest
	}
	d := m.Deployment
	if m.Mode != offlineQualificationMode || m.Purpose != PurposeHeuristicVerify || d.Model != offlineSafeguardModel ||
		d.Provider != ModeBYOC || !d.validScope() || !d.ScopedTo(scope[0], scope[1], scope[2]) || d.SafeLabel != "" || d.MaliciousLabel != "" ||
		!m.ZeroRetention || m.BaseWeightOrigin != "us" || !m.ExpiresAt.After(now) || m.ExpiresAt.After(now.Add(90*24*time.Hour)) {
		return m, ErrInvalidRequest
	}
	hash, err := hex.DecodeString(m.CorpusSHA256)
	if err != nil || len(hash) != sha256.Size || len(token) < 16 || len(token) > 8192 ||
		strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 || m.CredentialSHA256 != candidateDigest([]byte(token)) {
		return m, ErrInvalidRequest
	}
	return m, nil
}

// Tier: 2 | Purpose: offline heuristic_fp_verify measurement on a signed corpus.
// Model: scoped private vLLM with operator-attested US-origin safeguard weights.
// Authority: signed release, exact deployment, mounted credential and corpus.
// Fallback: produces a report only. Tenant runtime eligibility is unchanged.
func MeasureOfflineCandidate(ctx context.Context, raw, signature, publicKey []byte, scope [3]string, token string, corpus []byte) (OfflineCandidateReport, error) {
	var report OfflineCandidateReport
	if ctx == nil || ctx.Err() != nil {
		return report, ErrInvalidRequest
	}
	m, err := verifiedOfflineManifest(raw, signature, publicKey, scope, token, time.Now())
	if err != nil {
		return report, err
	}
	ep, err := m.Deployment.privateEndpoint()
	if err != nil {
		return report, err
	}
	client, err := pinnedPrivateClient(ep, "/v1/chat/completions")
	if err != nil {
		return report, err
	}
	defer client.CloseIdleConnections()
	driver := offlineSafeguard{&VLLMDriver{client: client, endpoint: ep.URL, model: m.Deployment.Model}, token}
	att := DeploymentAttestation{Deployment: m.Deployment, Purpose: m.Purpose, CorpusSHA256: m.CorpusSHA256}
	bounded, cancel := context.WithDeadline(ctx, m.ExpiresAt)
	defer cancel()
	result, err := MeasureCorpus(bounded, driver, att, corpus)
	if err != nil {
		return report, err
	}
	if err := bounded.Err(); err != nil {
		return report, err
	}
	return OfflineCandidateReport{Mode: m.Mode, Model: m.Deployment.Model, Organization: scope[0], Workspace: scope[1], Environment: scope[2],
		ManifestSHA256: candidateDigest(raw), CorpusSHA256: m.CorpusSHA256, Measurement: result}, nil
}
