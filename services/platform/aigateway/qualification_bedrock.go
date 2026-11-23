package aigateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"
)

// The signed profile contains references only. Credentials are mounted on the
// trusted runner separately and never appear in the corpus or evidence report.
type BedrockQualificationProfile struct {
	VPCEHost            string `json:"vpce_host"`
	PrivateIP           string `json:"private_ip"`
	Model               string `json:"model"`
	CredentialReference string `json:"credential_reference"`
	MaximumNanoCredits  int64  `json:"maximum_nano_credits"`
}

type VertexQualificationProfile struct {
	Location            string `json:"location"`
	Project             string `json:"project"`
	PrivateIP           string `json:"private_ip"`
	Model               string `json:"model"`
	CredentialReference string `json:"credential_reference"`
	MaximumNanoCredits  int64  `json:"maximum_nano_credits"`
}

func (a DeploymentAttestation) ProviderMode() string {
	if a.Vertex != nil {
		return ModeVertex
	}
	if a.Deployment.Provider == ModeBYOC {
		return ModeBYOC
	}
	if a.Bedrock != nil {
		return ModeBedrock
	}
	return ModeVPC
}
func (a DeploymentAttestation) ModelName() string {
	if a.Vertex != nil {
		return a.Vertex.Model
	}
	if a.Bedrock != nil {
		return a.Bedrock.Model
	}
	return a.Deployment.Model
}

// credential is a bearer value for mounted-token profiles, or the path to the
// rotating projected JWT for a workload identity profile.
func (a DeploymentAttestation) MeasuredDriver(credential string) (ProviderDriver, string, error) {
	if a.Bedrock == nil && a.Vertex == nil {
		d, err := a.Deployment.Driver()
		return d, a.Deployment.Digest(), err
	}
	b, err := a.cloudBinding(credential)
	if err != nil {
		return nil, "", err
	}
	return b.Driver, b.Binding.DeploymentDigest, nil
}

func (a DeploymentAttestation) cloudBinding(credential string) (*BoundModel, error) {
	region := ""
	if a.Vertex != nil {
		region = a.Vertex.Location
	} else if a.Bedrock != nil {
		m := bedrockHost.FindStringSubmatch(a.Bedrock.VPCEHost)
		if len(m) != 2 {
			return nil, ErrInvalidConfiguration
		}
		region = m[1]
	} else {
		return nil, ErrInvalidConfiguration
	}
	var workload *privateFederation
	var err error
	bindingKey := credential
	if a.WorkloadIdentity != nil {
		workload, err = newPrivateFederation(a.ProviderMode(), region, credential, *a.WorkloadIdentity)
		if err != nil {
			return nil, err
		}
		encoded, _ := json.Marshal(a.WorkloadIdentity)
		bindingKey = string(encoded)
	}
	var b BedrockBinding
	var driver ProviderDriver
	if v := a.Vertex; v != nil {
		ip, err := netip.ParseAddr(v.PrivateIP)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		d, bind, err := NewVertexForPurpose(a.Purpose, v.Location, v.Project, ip, v.Model, v.CredentialReference, bindingKey, v.MaximumNanoCredits)
		if err != nil {
			return nil, err
		}
		d.workload = workload
		driver, b = d, bind
	} else {
		cfg := a.Bedrock
		ip, err := netip.ParseAddr(cfg.PrivateIP)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		d, bind, err := NewBedrockForPurpose(a.Purpose, cfg.VPCEHost, ip, cfg.Model, cfg.CredentialReference, bindingKey, cfg.MaximumNanoCredits)
		if err != nil {
			return nil, err
		}
		d.workload = workload
		driver, b = d, bind
	}
	if workload != nil {
		b.DeploymentDigest = digest(b.DeploymentDigest + "\n" + b.CredentialDigest + "\n" + b.CredentialReference)
	}
	return &BoundModel{Driver: driver, Binding: b}, nil
}

type deepFixture struct {
	Input             json.RawMessage `json:"input"`
	Expected          map[string]any  `json:"expected"`
	CounterfeitPolicy bool            `json:"counterfeit_policy"`
}

var expectedFields = map[Purpose][]string{
	PurposeTriage:          {"evidence_ids"},
	PurposeDiscoveryVerify: {"kind", "evidence_refs"},
	PurposeDraft:           {"allowed_tool_ids", "iam_mismatches"},
	PurposeAddonAudit:      {"threat_score", "risk_score", "citations"},
}

func matchesExpected(p Purpose, expected map[string]any, output []byte) bool {
	var actual map[string]any
	if json.Unmarshal(output, &actual) != nil || len(expected) == 0 {
		return false
	}
	for _, name := range expectedFields[p] {
		if _, ok := expected[name]; !ok {
			return false
		}
	}
	for name, want := range expected {
		if got, ok := actual[name]; !ok || !reflect.DeepEqual(got, want) {
			return false
		}
	}
	return true
}

// Tier: 3 | Purpose: read-only discovery, triage, audit and purpose drafting.
// Model: region-bound PrivateLink Converse accessed only for synthetic cases.
// Authority: a signed corpus fixes test inputs and the expected evidence.
// Fallback: inadequate evidence, latency or output fails qualification.
func MeasureCloud(ctx context.Context, driver ProviderDriver, a DeploymentAttestation, digest string, data []byte) (QualificationResult, error) {
	r := QualificationResult{SchemaVersion: semanticSchemaVersion, Purpose: a.Purpose, DeploymentDigest: digest}
	h := sha256.Sum256(data)
	d, ok := LookupPurpose(a.Purpose)
	if !ok || ctx == nil || driver == nil || len(expectedFields[a.Purpose]) == 0 || len(data) > 8<<20 || hex.EncodeToString(h[:]) != a.CorpusSHA256 || !strings.HasPrefix(digest, "sha256:") {
		return r, ErrInvalidRequest
	}
	var times []time.Duration
	seen := map[[32]byte]bool{}
	var isolated int
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		var f deepFixture
		if json.Unmarshal(scan.Bytes(), &f) != nil || len(f.Expected) == 0 || len(f.Input) == 0 || len(f.Input) > d.MaxInputBytes || r.Total >= 1024 {
			return r, ErrInvalidRequest
		}
		var canonical bytes.Buffer
		if json.Compact(&canonical, f.Input) != nil {
			return r, ErrInvalidRequest
		}
		key := sha256.Sum256(canonical.Bytes())
		if seen[key] {
			return r, ErrInvalidRequest
		}
		seen[key] = true
		r.Total++
		if f.CounterfeitPolicy {
			isolated++
		}
		start := time.Now()
		raw, err := driver.Evaluate(ctx, a.Purpose, f.Input)
		times = append(times, time.Since(start))
		valid := err == nil && ValidateSemanticOutput(a.Purpose, raw)
		if valid {
			r.Valid++
		}
		if !valid || !matchesExpected(a.Purpose, f.Expected, raw) {
			r.SemanticFailures++
			if f.CounterfeitPolicy {
				r.CounterfeitFailures++
			}
		}
	}
	if scan.Err() != nil || r.Total < 100 || isolated == 0 {
		return r, ErrInvalidRequest
	}
	slices.Sort(times)
	r.P95Millis = float64(times[(95*r.Total+99)/100-1]) / float64(time.Millisecond)
	r.Qualified = r.Valid*100 >= 99*r.Total && r.SemanticFailures*100 <= r.Total && r.CounterfeitFailures == 0 && r.P95Millis <= float64(d.MaxLatency)/float64(time.Millisecond)
	return r, nil
}
