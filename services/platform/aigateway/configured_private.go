package aigateway

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

// BoundModel couples the reachable private endpoint to its qualification identity.
type BoundModel struct {
	Driver  ProviderDriver
	Binding BedrockBinding
}

// An installation chooses the private provider per job. Both configured would
// be ambiguous, so a worker must never try a second host after a provider error.
func ConfiguredPrivateModel(p Purpose, bedrockPrefix string) *BoundModel {
	vertexPrefix := strings.Replace(bedrockPrefix, "ZASP_BEDROCK_", "ZASP_VERTEX_", 1)
	configured := func(prefix string) bool {
		return os.Getenv(prefix+"TOKEN_FILE") != "" || os.Getenv(prefix+"WORKLOAD_IDENTITY_FILE") != "" || os.Getenv(prefix+"SUBJECT_TOKEN_FILE") != ""
	}
	useVertex := configured(vertexPrefix)
	if useVertex && configured(bedrockPrefix) {
		return nil
	}
	prefix := bedrockPrefix
	if useVertex {
		prefix = vertexPrefix
	}
	var a DeploymentAttestation
	a.Purpose = p
	credFile := os.Getenv(prefix + "TOKEN_FILE")
	profileFile := os.Getenv(prefix + "WORKLOAD_IDENTITY_FILE")
	jwtFile := os.Getenv(prefix + "SUBJECT_TOKEN_FILE")
	var credential string
	if profileFile != "" || jwtFile != "" {
		if credFile != "" || profileFile == "" || jwtFile == "" {
			return nil
		}
		profile, ok := privateModelToken(profileFile)
		if !ok {
			return nil
		}
		var workload WorkloadIdentityProfile
		dec := json.NewDecoder(strings.NewReader(profile))
		dec.DisallowUnknownFields()
		if dec.Decode(&workload) != nil || dec.Decode(new(any)) != io.EOF {
			return nil
		}
		a.WorkloadIdentity, credential = &workload, jwtFile
	} else {
		token, ok := privateModelToken(credFile)
		if !ok {
			return nil
		}
		credential = token
	}
	cost, err := strconv.ParseInt(os.Getenv(prefix+"MAX_NANO_CREDITS"), 10, 64)
	if err != nil {
		return nil
	}
	model, ref := os.Getenv(prefix+"MODEL"), os.Getenv(prefix+"CREDENTIAL_REFERENCE")
	if useVertex {
		a.Vertex = &VertexQualificationProfile{PrivateIP: os.Getenv(prefix + "PSC_IP"), Location: os.Getenv(prefix + "LOCATION"), Project: os.Getenv(prefix + "PROJECT"), Model: model, CredentialReference: ref, MaximumNanoCredits: cost}
	} else {
		a.Bedrock = &BedrockQualificationProfile{PrivateIP: os.Getenv(prefix + "VPCE_IP"), VPCEHost: os.Getenv(prefix + "VPCE_HOST"), Model: model, CredentialReference: ref, MaximumNanoCredits: cost}
	}
	bound, err := a.cloudBinding(credential)
	if err != nil {
		return nil
	}
	return bound
}

func privateModelToken(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0022 != 0 || stat.Size() > 8193 {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, 8194))
	if err != nil || len(data) > 8193 {
		return "", false
	}
	return strings.TrimSuffix(string(data), "\n"), true
}
