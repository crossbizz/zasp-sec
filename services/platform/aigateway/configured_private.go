package aigateway

import (
	"io"
	"net/netip"
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
	useVertex := os.Getenv(vertexPrefix+"TOKEN_FILE") != ""
	if useVertex && os.Getenv(bedrockPrefix+"TOKEN_FILE") != "" {
		return nil
	}
	prefix, ipField := bedrockPrefix, "VPCE_IP"
	if useVertex {
		prefix, ipField = vertexPrefix, "PSC_IP"
	}
	token, ok := privateModelToken(os.Getenv(prefix + "TOKEN_FILE"))
	if !ok {
		return nil
	}
	ip, err := netip.ParseAddr(os.Getenv(prefix + ipField))
	if err != nil {
		return nil
	}
	cost, err := strconv.ParseInt(os.Getenv(prefix+"MAX_NANO_CREDITS"), 10, 64)
	if err != nil {
		return nil
	}
	model, reference := os.Getenv(prefix+"MODEL"), os.Getenv(prefix+"CREDENTIAL_REFERENCE")
	var driver ProviderDriver
	var b BedrockBinding
	if useVertex {
		driver, b, err = NewVertexForPurpose(p, os.Getenv(prefix+"LOCATION"), os.Getenv(prefix+"PROJECT"), ip, model, reference, token, cost)
	} else {
		driver, b, err = NewBedrockForPurpose(p, os.Getenv(prefix+"VPCE_HOST"), ip, model, reference, token, cost)
	}
	if err != nil {
		return nil
	}
	return &BoundModel{Driver: driver, Binding: b}
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
