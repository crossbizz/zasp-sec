package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// These test-only oracles retain the predecessor assembly, including its
// repeated enforcement renders and exact malformed-source refusal.
func predecessorConnectorProvenanceAssembly() (string, string, error) {
	pattern := regexp.MustCompile(`(?s)CREATE FUNCTION "public"\."zasp_connector_stage_pkce_cleanup"\([^;]*?LANGUAGE plpgsql AS \$\$(.*?)\$\$;`)
	matched := pattern.FindAllStringSubmatch(ConnectorAuthorization().UpSQL(), -1)
	if len(matched) != 1 || len(matched[0]) != 2 {
		return "", "", ErrInvalidState
	}
	predecessor := sha256.Sum256([]byte(matched[0][1]))
	source := strings.NewReplacer("-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- pkce predecessor source digest", hex.EncodeToString(predecessor[:])).Replace(connectorEnqueueProvenanceSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- connector provenance checksum", pin), pin, nil
}

func predecessorConnectorMaintenanceAssembly() (string, string, error) {
	_, capturePin, err := predecessorConnectorProvenanceAssembly()
	if err != nil {
		return "", "", err
	}
	source := strings.NewReplacer("-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- connector provenance checksum", capturePin).Replace(connectorMaintenanceSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- connector maintenance checksum", pin), pin, nil
}

func predecessorApprovalActivationAssembly() (string, string, error) {
	_, connectorPin, err := predecessorConnectorMaintenanceAssembly()
	if err != nil {
		return "", "", err
	}
	source := strings.NewReplacer("-- authorization79 checksum", ProductionAuthorizationProjection().Checksum(), "-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- connector checksum", connectorPin, "-- approval checksum", ApprovalMaintenanceProfileChecksum()).Replace(approvalActivationSQL)
	digest := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(source, "-- activation checksum", pin), pin, nil
}

func predecessorApprovalSettlementAssembly() (string, string, error) {
	_, activationPin, err := predecessorApprovalActivationAssembly()
	if err != nil {
		return "", "", err
	}
	source := strings.ReplaceAll(approvalSettlementAuditSQL, "-- activation checksum", activationPin)
	digest := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(source, "-- settlement checksum", pin), pin, nil
}

type connectorApprovalAssembly func() (string, string, error)

func TestConnectorApprovalAssemblyPreservesPredecessorSources(t *testing.T) {
	for _, pair := range []struct {
		name          string
		before, after connectorApprovalAssembly
	}{
		{"provenance", predecessorConnectorProvenanceAssembly, connectorEnqueueProvenanceSource},
		{"maintenance", predecessorConnectorMaintenanceAssembly, connectorMaintenanceSource},
		{"activation", predecessorApprovalActivationAssembly, approvalActivationSource},
		{"settlement", predecessorApprovalSettlementAssembly, approvalSettlementAuditSource},
	} {
		t.Run(pair.name, func(t *testing.T) {
			before, pin, err := pair.before()
			after, next, nextErr := pair.after()
			if err != nil || nextErr != nil || before != after || pin != next {
				t.Fatal("compiled source, pin or error changed", err, nextErr)
			}
		})
	}
}

func TestConnectorApprovalAssemblyRecomputesAndRefusesMalformedPredecessors(t *testing.T) {
	originalEnforcement := authorizationEnforcementSQL
	originalConnector := connectorUpSQL
	defer func() { authorizationEnforcementSQL, connectorUpSQL = originalEnforcement, originalConnector }()
	baseline, baselinePin, err := approvalActivationSource()
	if err != nil {
		t.Fatal(err)
	}
	authorizationEnforcementSQL += "\n-- owned in-memory enforcement mutation\n"
	want, wantPin, err := predecessorApprovalActivationAssembly()
	got, gotPin, gotErr := approvalActivationSource()
	if err != nil || gotErr != nil || want != got || wantPin != gotPin || gotPin == baselinePin {
		t.Fatal("fresh enforcement source mutation was hidden", err, gotErr)
	}
	authorizationEnforcementSQL = originalEnforcement
	if restored, restoredPin, err := approvalActivationSource(); err != nil || restored != baseline || restoredPin != baselinePin {
		t.Fatal("source restoration reused a stale assembly", err)
	}

	for _, predecessor := range []struct {
		name, source string
	}{
		{"missing", strings.ReplaceAll(originalConnector, "zasp_connector_stage_pkce_cleanup", "owned_missing_predecessor")},
		{"duplicate", originalConnector + "\n" + originalConnector},
	} {
		t.Run(predecessor.name, func(t *testing.T) {
			connectorUpSQL = predecessor.source
			for _, build := range []connectorApprovalAssembly{connectorEnqueueProvenanceSource, connectorMaintenanceSource, approvalActivationSource, approvalSettlementAuditSource} {
				if source, pin, err := build(); source != "" || pin != "" || !errors.Is(err, ErrInvalidState) {
					t.Fatal("invalid exact original PKCE predecessor admitted", err)
				}
			}
			for _, build := range []func(func() string) (string, string, error){connectorEnqueueProvenanceSourceWithEnforcement, connectorMaintenanceSourceWithEnforcement} {
				reads := 0
				source, pin, err := build(func() string { reads++; return "unexpected enforcement read" })
				if source != "" || pin != "" || !errors.Is(err, ErrInvalidState) || reads != 0 {
					t.Fatalf("predecessor refusal must precede enforcement read: reads=%d err=%v", reads, err)
				}
			}
		})
	}
}

func TestConnectorApprovalAssemblyAvoidsRepeatedEnforcementRendering(t *testing.T) {
	measure := func(build connectorApprovalAssembly) (string, string, uint64) {
		t.Helper()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		source, pin, err := build()
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		return source, pin, after.TotalAlloc - before.TotalAlloc
	}
	for _, pair := range []struct {
		name          string
		before, after connectorApprovalAssembly
	}{
		{"maintenance", predecessorConnectorMaintenanceAssembly, connectorMaintenanceSource},
		{"activation", predecessorApprovalActivationAssembly, approvalActivationSource},
		{"settlement", predecessorApprovalSettlementAssembly, approvalSettlementAuditSource},
	} {
		t.Run(pair.name, func(t *testing.T) {
			before, pin, previousBytes := measure(pair.before)
			after, next, currentBytes := measure(pair.after)
			if before != after || pin != next {
				t.Fatal("allocation optimization changed compiled identity")
			}
			if currentBytes > previousBytes*3/4 {
				t.Fatalf("duplicate enforcement renders retained: predecessor=%d successor=%d", previousBytes, currentBytes)
			}
			t.Logf("fresh assembly allocation: predecessor=%d successor=%d", previousBytes, currentBytes)
		})
	}
}
