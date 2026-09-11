package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrationAttackLabSandboxName(organizationID, workspaceID, environmentID, runID string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{organizationID, workspaceID, environmentID, runID}, "\x1f")))
	return "zasp-attack-lab-" + fmt.Sprintf("%x", digest[:16])
}

func TestLoadMigrationTimeoutRequiresFiniteBound(t *testing.T) {
	if got, err := loadMigrationTimeout(func(string) string { return "2m" }); err != nil || got != 2*time.Minute {
		t.Fatalf("timeout = (%v, %v)", got, err)
	}
	for _, value := range []string{"", "0s", "31m", "forever"} {
		if _, err := loadMigrationTimeout(func(string) string { return value }); err == nil {
			t.Fatalf("timeout %q accepted", value)
		}
	}
}

type scriptedMigrationRunner struct {
	events  []string
	errAt   string
	version int64
}

func (runner *scriptedMigrationRunner) Version(context.Context) (int64, error) {
	runner.events = append(runner.events, "version")
	if runner.errAt == "version" {
		return 0, errors.New("detail")
	}
	return runner.version, nil
}

func (runner *scriptedMigrationRunner) Up(context.Context) error {
	runner.events = append(runner.events, "up-baseline")
	if runner.errAt == "up-baseline" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) UpCore(context.Context) error {
	runner.events = append(runner.events, "up-core")
	if runner.errAt == "up-core" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflows(context.Context) error {
	runner.events = append(runner.events, "up-workflows")
	if runner.errAt == "up-workflows" {
		return errors.New("detail")
	}
	runner.version = 3
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceipts(context.Context) error {
	runner.events = append(runner.events, "up-receipts")
	if runner.errAt == "up-receipts" {
		return errors.New("detail")
	}
	runner.version = 4
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceiptSafety(context.Context) error {
	runner.events = append(runner.events, "up-receipt-safety")
	if runner.errAt == "up-receipt-safety" {
		return errors.New("detail")
	}
	runner.version = 5
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflowReceiptProvenance(context.Context) error {
	runner.events = append(runner.events, "up-receipt-provenance")
	if runner.errAt == "up-receipt-provenance" {
		return errors.New("detail")
	}
	runner.version = 6
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflowReceiptProvenance(context.Context) error {
	runner.events = append(runner.events, "down-receipt-provenance")
	if runner.errAt == "down-receipt-provenance" {
		return errors.New("detail")
	}
	runner.version = 5
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionAdministration(context.Context) error {
	runner.events = append(runner.events, "up-production-administration")
	if runner.errAt == "up-production-administration" {
		return errors.New("detail")
	}
	runner.version = 7
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionAdministration(context.Context) error {
	runner.events = append(runner.events, "down-production-administration")
	if runner.errAt == "down-production-administration" {
		return errors.New("detail")
	}
	runner.version = 6
	return nil
}

func (runner *scriptedMigrationRunner) UpAPITokenRevealGrants(context.Context) error {
	runner.events = append(runner.events, "up-api-token-reveal-grants")
	if runner.errAt == "up-api-token-reveal-grants" {
		return errors.New("detail")
	}
	runner.version = 8
	return nil
}

func (runner *scriptedMigrationRunner) DownAPITokenRevealGrants(context.Context) error {
	runner.events = append(runner.events, "down-api-token-reveal-grants")
	if runner.errAt == "down-api-token-reveal-grants" {
		return errors.New("detail")
	}
	runner.version = 7
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRiskProjection(context.Context) error {
	runner.events = append(runner.events, "up-production-risk-projection")
	if runner.errAt == "up-production-risk-projection" {
		return errors.New("detail")
	}
	runner.version = 9
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRiskProjection(context.Context) error {
	runner.events = append(runner.events, "down-production-risk-projection")
	if runner.errAt == "down-production-risk-projection" {
		return errors.New("detail")
	}
	runner.version = 8
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionDiscovery(context.Context) error {
	runner.events = append(runner.events, "up-production-discovery")
	if runner.errAt == "up-production-discovery" {
		return errors.New("detail")
	}
	runner.version = 10
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionDiscovery(context.Context) error {
	runner.events = append(runner.events, "down-production-discovery")
	if runner.errAt == "down-production-discovery" {
		return errors.New("detail")
	}
	runner.version = 9
	return nil
}

func (runner *scriptedMigrationRunner) UpConnectorAuthorization(context.Context) error {
	runner.events = append(runner.events, "up-connector-authorization")
	if runner.errAt == "up-connector-authorization" {
		return errors.New("detail")
	}
	runner.version = 11
	return nil
}

func (runner *scriptedMigrationRunner) DownConnectorAuthorization(context.Context) error {
	runner.events = append(runner.events, "down-connector-authorization")
	if runner.errAt == "down-connector-authorization" {
		return errors.New("detail")
	}
	runner.version = 10
	return nil
}

func (runner *scriptedMigrationRunner) UpReferenceAuthorization(context.Context) error {
	runner.events = append(runner.events, "up-reference-authorization")
	if runner.errAt == "up-reference-authorization" {
		return errors.New("detail")
	}
	runner.version = 12
	return nil
}

func (runner *scriptedMigrationRunner) DownReferenceAuthorization(context.Context) error {
	runner.events = append(runner.events, "down-reference-authorization")
	if runner.errAt == "down-reference-authorization" {
		return errors.New("detail")
	}
	runner.version = 11
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionDiscoveryExecution(context.Context) error {
	runner.events = append(runner.events, "up-production-discovery-execution")
	if runner.errAt == "up-production-discovery-execution" {
		return errors.New("detail")
	}
	runner.version = 13
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionDiscoveryExecution(context.Context) error {
	runner.events = append(runner.events, "down-production-discovery-execution")
	if runner.errAt == "down-production-discovery-execution" {
		return errors.New("detail")
	}
	runner.version = 12
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionTypedInventoryCutover(context.Context) error {
	runner.events = append(runner.events, "up-production-typed-inventory-cutover")
	if runner.errAt == "up-production-typed-inventory-cutover" {
		return errors.New("detail")
	}
	runner.version = 14
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionTypedInventoryCutover(context.Context) error {
	runner.events = append(runner.events, "down-production-typed-inventory-cutover")
	if runner.errAt == "down-production-typed-inventory-cutover" {
		return errors.New("detail")
	}
	runner.version = 13
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRuntimeDataPlane(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-data-plane")
	if runner.errAt == "up-production-runtime-data-plane" {
		return errors.New("detail")
	}
	runner.version = 15
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeDataPlane(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-data-plane")
	if runner.errAt == "down-production-runtime-data-plane" {
		return errors.New("detail")
	}
	runner.version = 14
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRuntimeGatewayReconciliation(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-gateway-reconciliation")
	if runner.errAt == "up-production-runtime-gateway-reconciliation" {
		return errors.New("detail")
	}
	runner.version = 16
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeGatewayReconciliation(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-gateway-reconciliation")
	if runner.errAt == "down-production-runtime-gateway-reconciliation" {
		return errors.New("detail")
	}
	runner.version = 15
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRuntimeIngestReconciliation(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-ingest-reconciliation")
	if runner.errAt == "up-production-runtime-ingest-reconciliation" {
		return errors.New("detail")
	}
	runner.version = 17
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeIngestReconciliation(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-ingest-reconciliation")
	if runner.errAt == "down-production-runtime-ingest-reconciliation" {
		return errors.New("detail")
	}
	runner.version = 16
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentExecution(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-execution")
	if runner.errAt == "up-production-security-agent-execution" {
		return errors.New("detail")
	}
	runner.version = 18
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentExecution(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-execution")
	if runner.errAt == "down-production-security-agent-execution" {
		return errors.New("detail")
	}
	runner.version = 17
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionIdentityAdministration(context.Context) error {
	runner.events = append(runner.events, "up-production-identity-administration")
	if runner.errAt == "up-production-identity-administration" {
		return errors.New("detail")
	}
	runner.version = 19
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionIdentityAdministration(context.Context) error {
	runner.events = append(runner.events, "down-production-identity-administration")
	if runner.errAt == "down-production-identity-administration" {
		return errors.New("detail")
	}
	runner.version = 18
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentControls(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-controls")
	if runner.errAt == "up-production-security-agent-controls" {
		return errors.New("detail")
	}
	runner.version = 20
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentControls(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-controls")
	if runner.errAt == "down-production-security-agent-controls" {
		return errors.New("detail")
	}
	runner.version = 19
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentAutonomousResponse(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-autonomous-response")
	if runner.errAt == "up-production-security-agent-autonomous-response" {
		return errors.New("detail")
	}
	runner.version = 21
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentAutonomousResponse(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-autonomous-response")
	if runner.errAt == "down-production-security-agent-autonomous-response" {
		return errors.New("detail")
	}
	runner.version = 20
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentTemporaryPolicy(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-temporary-policy")
	if runner.errAt == "up-production-security-agent-temporary-policy" {
		return errors.New("detail")
	}
	runner.version = 22
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentTemporaryPolicy(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-temporary-policy")
	if runner.errAt == "down-production-security-agent-temporary-policy" {
		return errors.New("detail")
	}
	runner.version = 21
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentConnectorRevocation(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-connector-revocation")
	if runner.errAt == "up-production-security-agent-connector-revocation" {
		return errors.New("detail")
	}
	runner.version = 23
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentConnectorRevocation(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-connector-revocation")
	if runner.errAt == "down-production-security-agent-connector-revocation" {
		return errors.New("detail")
	}
	runner.version = 22
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentSessionIsolation(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-session-isolation")
	if runner.errAt == "up-production-security-agent-session-isolation" {
		return errors.New("detail")
	}
	runner.version = 24
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentSessionIsolation(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-session-isolation")
	if runner.errAt == "down-production-security-agent-session-isolation" {
		return errors.New("detail")
	}
	runner.version = 23
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRedTeamExecution(context.Context) error {
	runner.events = append(runner.events, "up-production-red-team-execution")
	if runner.errAt == "up-production-red-team-execution" {
		return errors.New("detail")
	}
	runner.version = 25
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRedTeamExecution(context.Context) error {
	runner.events = append(runner.events, "down-production-red-team-execution")
	if runner.errAt == "down-production-red-team-execution" {
		return errors.New("detail")
	}
	runner.version = 24
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionAttackLabExecution(context.Context) error {
	runner.events = append(runner.events, "up-production-attack-lab-execution")
	if runner.errAt == "up-production-attack-lab-execution" {
		return errors.New("detail")
	}
	runner.version = 26
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionAttackLabExecution(context.Context) error {
	runner.events = append(runner.events, "down-production-attack-lab-execution")
	if runner.errAt == "down-production-attack-lab-execution" {
		return errors.New("detail")
	}
	runner.version = 25
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRecovery(context.Context) error {
	runner.events = append(runner.events, "up-production-recovery")
	if runner.errAt == "up-production-recovery" {
		return errors.New("detail")
	}
	runner.version = 27
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRecovery(context.Context) error {
	runner.events = append(runner.events, "down-production-recovery")
	if runner.errAt == "down-production-recovery" {
		return errors.New("detail")
	}
	runner.version = 26
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionPolicyDeployment(context.Context) error {
	runner.events = append(runner.events, "up-production-policy-deployment")
	if runner.errAt == "up-production-policy-deployment" {
		return errors.New("detail")
	}
	runner.version = 28
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionPolicyDeployment(context.Context) error {
	runner.events = append(runner.events, "down-production-policy-deployment")
	if runner.errAt == "down-production-policy-deployment" {
		return errors.New("detail")
	}
	runner.version = 27
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionHomeAttention(context.Context) error {
	runner.events = append(runner.events, "up-production-home-attention")
	if runner.errAt == "up-production-home-attention" {
		return errors.New("detail")
	}
	runner.version = 29
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionHomeAttention(context.Context) error {
	runner.events = append(runner.events, "down-production-home-attention")
	if runner.errAt == "down-production-home-attention" {
		return errors.New("detail")
	}
	runner.version = 28
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionApprovalNotification(context.Context) error {
	runner.events = append(runner.events, "up-production-approval-notification")
	if runner.errAt == "up-production-approval-notification" {
		return errors.New("detail")
	}
	runner.version = 30
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionApprovalNotification(context.Context) error {
	runner.events = append(runner.events, "down-production-approval-notification")
	if runner.errAt == "down-production-approval-notification" {
		return errors.New("detail")
	}
	runner.version = 29
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionWorkflowCompatibility(context.Context) error {
	runner.events = append(runner.events, "up-production-workflow-compatibility")
	if runner.errAt == "up-production-workflow-compatibility" {
		return errors.New("detail")
	}
	runner.version = 31
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionWorkflowCompatibility(context.Context) error {
	runner.events = append(runner.events, "down-production-workflow-compatibility")
	if runner.errAt == "down-production-workflow-compatibility" {
		return errors.New("detail")
	}
	runner.version = 30
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentPlanner(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-planner")
	if runner.errAt == "up-production-security-agent-planner" {
		return errors.New("detail")
	}
	runner.version = 32
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentPlanner(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-planner")
	if runner.errAt == "down-production-security-agent-planner" {
		return errors.New("detail")
	}
	runner.version = 31
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentAttackPath(context.Context) error {
	runner.events = append(runner.events, "up-production-security-agent-attack-path")
	if runner.errAt == "up-production-security-agent-attack-path" {
		return errors.New("detail")
	}
	runner.version = 33
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentAttackPath(context.Context) error {
	runner.events = append(runner.events, "down-production-security-agent-attack-path")
	if runner.errAt == "down-production-security-agent-attack-path" {
		return errors.New("detail")
	}
	runner.version = 32
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionIntegrationSetup(context.Context) error {
	runner.events = append(runner.events, "up-production-integration-setup")
	if runner.errAt == "up-production-integration-setup" {
		return errors.New("detail")
	}
	runner.version = 34
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionIntegrationSetup(context.Context) error {
	runner.events = append(runner.events, "down-production-integration-setup")
	if runner.errAt == "down-production-integration-setup" {
		return errors.New("detail")
	}
	runner.version = 33
	return nil
}

func TestAgentsecMigrateReachesV34FromV27AndDowngradesFirst(t *testing.T) {
	up := &scriptedMigrationRunner{version: 27}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-production-policy-deployment", "up-production-home-attention", "up-production-approval-notification", "up-production-workflow-compatibility", "up-production-security-agent-planner", "up-production-security-agent-attack-path", "up-production-integration-setup", "up-production-integration-webhook", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("v27 to v34 = %#v, %v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 34}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err != nil || len(down.events) < 9 || down.events[1] != "down-production-integration-setup" || down.events[2] != "down-production-security-agent-attack-path" || down.events[3] != "down-production-security-agent-planner" || down.events[4] != "down-production-workflow-compatibility" || down.events[5] != "down-production-approval-notification" || down.events[6] != "down-production-home-attention" || down.events[7] != "down-production-policy-deployment" || down.events[8] != "down-production-recovery" {
		t.Fatalf("v34 down = %#v, %v", down.events, err)
	}
}

func (runner *scriptedMigrationRunner) UpProductionIntegrationWebhook(context.Context) error {
	runner.events = append(runner.events, "up-production-integration-webhook")
	if runner.errAt == "up-production-integration-webhook" {
		return errors.New("detail")
	}
	runner.version = 35
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionRuntimeQueueReplay(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-queue-replay")
	if runner.errAt == "up-production-runtime-queue-replay" {
		return errors.New("detail")
	}
	runner.version = 36
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeQueueReplay(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-queue-replay")
	if runner.errAt == "down-production-runtime-queue-replay" {
		return errors.New("detail")
	}
	runner.version = 35
	return nil
}

func TestAgentsecMigrateReachesV36AndDowngradesRuntimeReplayFirst(t *testing.T) {
	up := &scriptedMigrationRunner{version: 35}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("up=%v err=%v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 36, errAt: "down-production-integration-webhook"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-queue-replay", "down-production-integration-webhook"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
}

func (runner *scriptedMigrationRunner) DownProductionIntegrationWebhook(context.Context) error {
	runner.events = append(runner.events, "down-production-integration-webhook")
	if runner.errAt == "down-production-integration-webhook" {
		return errors.New("detail")
	}
	runner.version = 34
	return nil
}

func TestAgentsecMigrateReachesV35AndDowngradesWebhookFirst(t *testing.T) {
	up := &scriptedMigrationRunner{version: 34}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-production-integration-webhook", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("up=%v err=%v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 35, errAt: "down-production-integration-setup"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-integration-webhook", "down-production-integration-setup"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
}

func TestAgentsecMigrateReachesV34FromV17AndDowngradesFirst(t *testing.T) {
	up := &scriptedMigrationRunner{version: 17}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-production-security-agent-execution", "up-production-identity-administration", "up-production-security-agent-controls", "up-production-security-agent-autonomous-response", "up-production-security-agent-temporary-policy", "up-production-security-agent-connector-revocation", "up-production-security-agent-session-isolation", "up-production-red-team-execution", "up-production-attack-lab-execution", "up-production-recovery", "up-production-policy-deployment", "up-production-home-attention", "up-production-approval-notification", "up-production-workflow-compatibility", "up-production-security-agent-planner", "up-production-security-agent-attack-path", "up-production-integration-setup", "up-production-integration-webhook", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("v17 to v34 = %#v, %v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 24}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err != nil || len(down.events) < 9 || down.events[1] != "down-production-security-agent-session-isolation" || down.events[2] != "down-production-security-agent-connector-revocation" || down.events[3] != "down-production-security-agent-temporary-policy" || down.events[4] != "down-production-security-agent-autonomous-response" || down.events[5] != "down-production-security-agent-controls" || down.events[6] != "down-production-identity-administration" || down.events[7] != "down-production-security-agent-execution" || down.events[8] != "down-production-runtime-ingest-reconciliation" {
		t.Fatalf("v24 down = %#v, %v", down.events, err)
	}
}

func (runner *scriptedMigrationRunner) DownWorkflowReceiptSafety(context.Context) error {
	runner.events = append(runner.events, "down-receipt-safety")
	if runner.errAt == "down-receipt-safety" {
		return errors.New("detail")
	}
	runner.version = 4
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflowReceipts(context.Context) error {
	runner.events = append(runner.events, "down-receipts")
	if runner.errAt == "down-receipts" {
		return errors.New("detail")
	}
	runner.version = 3
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflows(context.Context) error {
	runner.events = append(runner.events, "down-workflows")
	if runner.errAt == "down-workflows" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) DownCore(context.Context) error {
	runner.events = append(runner.events, "down-core")
	if runner.errAt == "down-core" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) Down(context.Context) error {
	runner.events = append(runner.events, "down-baseline")
	if runner.errAt == "down-baseline" {
		return errors.New("detail")
	}
	runner.version = 0
	return nil
}

func TestRunReleaseMigrationReachesExactTargetStateIdempotently(t *testing.T) {
	for _, test := range []struct {
		direction string
		version   int64
		want      []string
	}{
		{direction: "up", version: 0, want: []string{"version", "up-baseline", "up-core", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 1, want: []string{"version", "up-core", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 2, want: []string{"version", "up-workflows", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 3, want: []string{"version", "up-receipts", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 4, want: []string{"version", "up-receipt-safety", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 5, want: []string{"version", "up-receipt-provenance", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 6, want: []string{"version", "up-production-administration", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 7, want: []string{"version", "up-api-token-reveal-grants", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 8, want: []string{"version", "up-production-risk-projection", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 9, want: []string{"version", "up-production-discovery", "up-connector-authorization", "version"}},
		{direction: "up", version: 10, want: []string{"version", "up-connector-authorization", "version"}},
		{direction: "up", version: 11, want: []string{"version", "version"}},
		{direction: "up", version: 12, want: []string{"version", "version"}},
		{direction: "up", version: 13, want: []string{"version", "version"}},
		{direction: "up", version: 14, want: []string{"version", "version"}},
		{direction: "up", version: 15, want: []string{"version", "version"}},
		{direction: "up", version: 16, want: []string{"version", "version"}},
		{direction: "up", version: 17, want: []string{"version", "version"}},
		{direction: "up", version: 18, want: []string{"version", "version"}},
		{direction: "up", version: 19, want: []string{"version", "version"}},
		{direction: "up", version: 20, want: []string{"version", "version"}},
		{direction: "up", version: 21, want: []string{"version", "version"}},
		{direction: "up", version: 22, want: []string{"version", "version"}},
		{direction: "up", version: 23, want: []string{"version", "version"}},
		{direction: "up", version: 24, want: []string{"version", "version"}},
		{direction: "up", version: 25, want: []string{"version", "version"}},
		{direction: "up", version: 26, want: []string{"version", "version"}},
		{direction: "up", version: 27, want: []string{"version", "version"}},
		{direction: "up", version: 28, want: []string{"version", "version"}},
		{direction: "up", version: 29, want: []string{"version", "version"}},
		{direction: "up", version: 30, want: []string{"version", "version"}},
		{direction: "up", version: 31, want: []string{"version", "version"}},
		{direction: "up", version: 32, want: []string{"version", "version"}},
		{direction: "up", version: 33, want: []string{"version", "version"}},
		{direction: "up", version: 34, want: []string{"version", "version"}},
		{direction: "down", version: 26, want: []string{"version", "down-production-attack-lab-execution", "down-production-red-team-execution", "down-production-security-agent-session-isolation", "down-production-security-agent-connector-revocation", "down-production-security-agent-temporary-policy", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 25, want: []string{"version", "down-production-red-team-execution", "down-production-security-agent-session-isolation", "down-production-security-agent-connector-revocation", "down-production-security-agent-temporary-policy", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 24, want: []string{"version", "down-production-security-agent-session-isolation", "down-production-security-agent-connector-revocation", "down-production-security-agent-temporary-policy", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 23, want: []string{"version", "down-production-security-agent-connector-revocation", "down-production-security-agent-temporary-policy", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 22, want: []string{"version", "down-production-security-agent-temporary-policy", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 21, want: []string{"version", "down-production-security-agent-autonomous-response", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 20, want: []string{"version", "down-production-security-agent-controls", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 19, want: []string{"version", "down-production-identity-administration", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 18, want: []string{"version", "down-production-security-agent-execution", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 17, want: []string{"version", "down-production-runtime-ingest-reconciliation", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 16, want: []string{"version", "down-production-runtime-gateway-reconciliation", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 15, want: []string{"version", "down-production-runtime-data-plane", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 14, want: []string{"version", "down-production-typed-inventory-cutover", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 13, want: []string{"version", "down-production-discovery-execution", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 12, want: []string{"version", "down-reference-authorization", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 11, want: []string{"version", "down-connector-authorization", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 10, want: []string{"version", "down-production-discovery", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 9, want: []string{"version", "down-production-risk-projection", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 8, want: []string{"version", "down-api-token-reveal-grants", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 7, want: []string{"version", "down-production-administration", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 6, want: []string{"version", "down-receipt-provenance", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 5, want: []string{"version", "down-receipt-safety", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 4, want: []string{"version", "down-receipts", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 3, want: []string{"version", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 2, want: []string{"version", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 1, want: []string{"version", "down-baseline", "version"}},
		{direction: "down", version: 0, want: []string{"version", "version"}},
	} {
		t.Run(test.direction+string(rune('0'+test.version)), func(t *testing.T) {
			if test.direction == "up" {
				steps := append([]string(nil), test.want[:len(test.want)-1]...)
				if test.version <= 11 {
					steps = append(steps, "up-reference-authorization")
				}
				if test.version <= 12 {
					steps = append(steps, "up-production-discovery-execution")
				}
				if test.version <= 13 {
					steps = append(steps, "up-production-typed-inventory-cutover")
				}
				if test.version <= 14 {
					steps = append(steps, "up-production-runtime-data-plane")
				}
				if test.version <= 15 {
					steps = append(steps, "up-production-runtime-gateway-reconciliation")
				}
				if test.version <= 16 {
					steps = append(steps, "up-production-runtime-ingest-reconciliation")
				}
				if test.version <= 17 {
					steps = append(steps, "up-production-security-agent-execution")
				}
				if test.version <= 18 {
					steps = append(steps, "up-production-identity-administration")
				}
				if test.version <= 19 {
					steps = append(steps, "up-production-security-agent-controls")
				}
				if test.version <= 20 {
					steps = append(steps, "up-production-security-agent-autonomous-response")
				}
				if test.version <= 21 {
					steps = append(steps, "up-production-security-agent-temporary-policy")
				}
				if test.version <= 22 {
					steps = append(steps, "up-production-security-agent-connector-revocation")
				}
				if test.version <= 23 {
					steps = append(steps, "up-production-security-agent-session-isolation")
				}
				if test.version <= 24 {
					steps = append(steps, "up-production-red-team-execution")
				}
				if test.version <= 25 {
					steps = append(steps, "up-production-attack-lab-execution")
				}
				if test.version <= 26 {
					steps = append(steps, "up-production-recovery")
				}
				if test.version <= 27 {
					steps = append(steps, "up-production-policy-deployment")
				}
				if test.version <= 28 {
					steps = append(steps, "up-production-home-attention")
				}
				if test.version <= 29 {
					steps = append(steps, "up-production-approval-notification")
				}
				if test.version <= 30 {
					steps = append(steps, "up-production-workflow-compatibility")
				}
				if test.version <= 31 {
					steps = append(steps, "up-production-security-agent-planner")
				}
				if test.version <= 32 {
					steps = append(steps, "up-production-security-agent-attack-path")
				}
				if test.version <= 33 {
					steps = append(steps, "up-production-integration-setup")
				}
				if test.version <= 34 {
					steps = append(steps, "up-production-integration-webhook")
				}
				if test.version <= 35 {
					steps = append(steps, "up-production-runtime-queue-replay")
				}
				if test.version <= 36 {
					steps = append(steps, "up-production-red-team-safety")
				}
				if test.version <= 37 {
					steps = append(steps, "up-production-red-team-invocation")
				}
				if test.version <= 38 {
					steps = append(steps, "up-production-red-team-artifacts")
				}
				if test.version <= 39 {
					steps = append(steps, "up-production-runtime-sessions")
				}
				if test.version <= 40 {
					steps = append(steps, "up-production-runtime-session-reads")
				}
				if test.version <= 41 {
					steps = append(steps, "up-production-runtime-session-search")
				}
				if test.version <= 42 {
					steps = append(steps, "up-production-runtime-session-query")
				}
				if test.version <= 43 {
					steps = append(steps, "up-production-runtime-session-evidence")
				}
				if test.version <= 44 {
					steps = append(steps, "up-production-runtime-enrollment-pairing")
				}
				if test.version <= 45 {
					steps = append(steps, "up-production-reconciliation-lane-plan")
				}
				if test.version <= 46 {
					steps = append(steps, "up-production-runtime-candidate-authority")
				}
				if test.version <= 47 {
					steps = append(steps, "up-production-runtime-acceptance")
				}
				if test.version <= 48 {
					steps = append(steps, "up-production-runtime-correlation-routing")
				}
				test.want = append(steps, test.want[len(test.want)-1])
			}
			runner := &scriptedMigrationRunner{version: test.version}
			if err := runReleaseMigration(context.Background(), runner, []string{test.direction}); err != nil {
				t.Fatal(err)
			}
			if len(runner.events) != len(test.want) {
				t.Fatalf("events = %#v", runner.events)
			}
			for index := range test.want {
				if runner.events[index] != test.want[index] {
					t.Fatalf("events = %#v, want %#v", runner.events, test.want)
				}
			}
		})
	}
}

func TestRunReleaseMigrationIncludesDiscoveryExecutionRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 11}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-reference-authorization", "up-production-discovery-execution", "up-production-typed-inventory-cutover", "up-production-runtime-data-plane", "up-production-runtime-gateway-reconciliation", "up-production-runtime-ingest-reconciliation", "up-production-security-agent-execution", "up-production-identity-administration", "up-production-security-agent-controls", "up-production-security-agent-autonomous-response", "up-production-security-agent-temporary-policy", "up-production-security-agent-connector-revocation", "up-production-security-agent-session-isolation", "up-production-red-team-execution", "up-production-attack-lab-execution", "up-production-recovery", "up-production-policy-deployment", "up-production-home-attention", "up-production-approval-notification", "up-production-workflow-compatibility", "up-production-security-agent-planner", "up-production-security-agent-attack-path", "up-production-integration-setup", "up-production-integration-webhook", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("v11 to v34 = %#v, %v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 24}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err != nil || len(down.events) < 15 || down.events[1] != "down-production-security-agent-session-isolation" || down.events[2] != "down-production-security-agent-connector-revocation" || down.events[3] != "down-production-security-agent-temporary-policy" || down.events[4] != "down-production-security-agent-autonomous-response" || down.events[5] != "down-production-security-agent-controls" || down.events[6] != "down-production-identity-administration" || down.events[7] != "down-production-security-agent-execution" || down.events[8] != "down-production-runtime-ingest-reconciliation" || down.events[9] != "down-production-runtime-gateway-reconciliation" || down.events[10] != "down-production-runtime-data-plane" || down.events[11] != "down-production-typed-inventory-cutover" || down.events[12] != "down-production-discovery-execution" || down.events[13] != "down-reference-authorization" {
		t.Fatalf("v24 down = %#v, %v", down.events, err)
	}
}

func TestAgentsecMigrateCLIReachesV34FromV13AndRollsBackBeforeCutover(t *testing.T) {
	up := &scriptedMigrationRunner{version: 13}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || !equalMigrationEvents(up.events, []string{"version", "up-production-typed-inventory-cutover", "up-production-runtime-data-plane", "up-production-runtime-gateway-reconciliation", "up-production-runtime-ingest-reconciliation", "up-production-security-agent-execution", "up-production-identity-administration", "up-production-security-agent-controls", "up-production-security-agent-autonomous-response", "up-production-security-agent-temporary-policy", "up-production-security-agent-connector-revocation", "up-production-security-agent-session-isolation", "up-production-red-team-execution", "up-production-attack-lab-execution", "up-production-recovery", "up-production-policy-deployment", "up-production-home-attention", "up-production-approval-notification", "up-production-workflow-compatibility", "up-production-security-agent-planner", "up-production-security-agent-attack-path", "up-production-integration-setup", "up-production-integration-webhook", "up-production-runtime-queue-replay", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("v13 to v34 = %#v, %v", up.events, err)
	}
	down := &scriptedMigrationRunner{version: 24}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err != nil || len(down.events) < 13 || down.events[1] != "down-production-security-agent-session-isolation" || down.events[2] != "down-production-security-agent-connector-revocation" || down.events[3] != "down-production-security-agent-temporary-policy" || down.events[4] != "down-production-security-agent-autonomous-response" || down.events[5] != "down-production-security-agent-controls" || down.events[6] != "down-production-identity-administration" || down.events[7] != "down-production-security-agent-execution" || down.events[8] != "down-production-runtime-ingest-reconciliation" || down.events[9] != "down-production-runtime-gateway-reconciliation" || down.events[10] != "down-production-runtime-data-plane" || down.events[11] != "down-production-typed-inventory-cutover" || down.events[12] != "down-production-discovery-execution" {
		t.Fatalf("v24 down = %#v, %v", down.events, err)
	}
}

func TestAgentsecMigrateV14LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v13 setup step %d: %v", index+1, err)
		}
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, migrations.ProductionTypedInventoryCutover().UpSQL()); err != nil {
		t.Fatalf("v14 SQL: %v", err)
	}
	var live string
	if err := transaction.QueryRow(ctx, `SELECT zasp_inventory_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionTypedInventoryCutoverSemanticFingerprint() {
		t.Fatalf("v14 live fingerprint = %s, pinned = %s", live, migrations.ProductionTypedInventoryCutoverSemanticFingerprint())
	}
}

func TestAgentsecMigrateV26LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("step %d: %v", index+1, err)
		}
	}
	fingerprintTransaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintTransaction.Exec(ctx, migrations.ProductionAttackLabExecution().UpSQL()); err != nil {
		_ = fingerprintTransaction.Rollback(context.Background())
		t.Fatalf("v26 candidate SQL: %v", err)
	}
	var candidateLive string
	if err := fingerprintTransaction.QueryRow(ctx, `SELECT zasp_attack_lab_execution_live_fingerprint()`).Scan(&candidateLive); err != nil {
		_ = fingerprintTransaction.Rollback(context.Background())
		t.Fatal(err)
	}
	if err := fingerprintTransaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidateLive != migrations.ProductionAttackLabExecutionSemanticFingerprint() {
		t.Fatalf("v26 candidate live fingerprint=%s pinned=%s", candidateLive, migrations.ProductionAttackLabExecutionSemanticFingerprint())
	}
	if err := runner.UpProductionAttackLabExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var live string
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_execution_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionAttackLabExecutionSemanticFingerprint() {
		t.Fatalf("v26 live fingerprint=%s pinned=%s", live, migrations.ProductionAttackLabExecutionSemanticFingerprint())
	}
	if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
		t.Fatal(err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 25 {
		t.Fatalf("down version=%d err=%v", version, err)
	}
}

func TestAgentsecMigrateV27LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("step %d: %v", index+1, err)
		}
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, migrations.ProductionRecovery().UpSQL()); err != nil {
		t.Fatalf("v27 candidate SQL: %v", err)
	}
	var live string
	if err := transaction.QueryRow(ctx, `SELECT zasp_recovery_execution_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionRecoverySemanticFingerprint() {
		t.Fatalf("v27 candidate live fingerprint=%s pinned=%s", live, migrations.ProductionRecoverySemanticFingerprint())
	}
}

func TestAgentsecMigrateV17LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v16 setup step %d: %v", index+1, err)
		}
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, migrations.ProductionRuntimeIngestReconciliation().UpSQL()); err != nil {
		t.Fatalf("v17 SQL: %v", err)
	}
	var live string
	if err := transaction.QueryRow(ctx, `SELECT zasp_runtime_ingest_reconciliation_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint() {
		t.Fatalf("v17 live fingerprint = %s, pinned = %s", live, migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint())
	}
}

func TestAgentsecMigrateV18LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v17 setup step %d: %v", index+1, err)
		}
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, migrations.ProductionSecurityAgentExecution().UpSQL()); err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v18 SQL: %v position=%d detail=%s", err, postgresError.Position, postgresError.Detail)
		}
		t.Fatalf("v18 SQL: %v", err)
	}
	var live string
	if err := transaction.QueryRow(ctx, `SELECT zasp_security_agent_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionSecurityAgentExecutionSemanticFingerprint() {
		t.Fatalf("v18 live fingerprint = %s, pinned = %s", live, migrations.ProductionSecurityAgentExecutionSemanticFingerprint())
	}
	metadata := migrations.ProductionSecurityAgentExecution()
	if _, err := transaction.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := transaction.QueryRow(ctx, `SELECT zasp_security_agent_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v18 readiness=%t err=%v", ready, err)
	}
}

func TestAgentsecMigrateV25LiveFingerprintMatchesPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v24 setup step %d: %v", index+1, err)
		}
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, migrations.ProductionRedTeamExecution().UpSQL()); err != nil {
		t.Fatalf("v25 SQL: %v", err)
	}
	var live string
	if err := transaction.QueryRow(ctx, `SELECT zasp_red_team_execution_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionRedTeamExecutionSemanticFingerprint() {
		t.Fatalf("v25 live fingerprint = %s, pinned = %s", live, migrations.ProductionRedTeamExecutionSemanticFingerprint())
	}
}

func TestAgentsecMigrateV18RunnerInstallsFromV17(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v17 setup step %d: %v", index+1, err)
		}
	}
	if err := runner.UpProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatalf("v18 up: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 18 {
		t.Fatalf("version=(%d,%v)", version, err)
	}
}

func TestAgentsecMigrateV14InstallsRollsBackReappliesAndBlocksPostCutoverRollback(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		version, versionErr := runner.Version(ctx)
		t.Fatalf("install target at version %d (%v): %v", version, versionErr, err)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 48 {
		t.Fatalf("installed version = (%d, %v)", version, versionErr)
	}
	if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentPlanner(ctx); err != nil {
		t.Fatalf("v32 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionWorkflowCompatibility(ctx); err != nil {
		t.Fatalf("v31 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionPolicyDeployment(ctx); err != nil {
		t.Fatalf("v28 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionRecovery(ctx); err != nil {
		t.Fatalf("v27 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
		t.Fatalf("v26 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionRedTeamExecution(ctx); err != nil {
		t.Fatalf("v25 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err != nil {
		t.Fatalf("v24 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err != nil {
		t.Fatalf("v23 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
		t.Fatalf("v22 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentControls(ctx); err != nil {
		t.Fatalf("v20 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionIdentityAdministration(ctx); err != nil {
		t.Fatalf("v19 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatalf("v18 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("v17 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 pre-cutover down: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("pre-cutover down: %v", err)
	}
	var executionReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), migrations.ProductionDiscoveryExecutionSemanticFingerprint()).Scan(&executionReady); err != nil || !executionReady {
		t.Fatalf("v13 readiness after down = %v, %v", executionReady, err)
	}
	if err := runner.UpProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("v14 reapply: %v", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_cutover_state(
		organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,
		backfilled_at,equivalent_at,cutover_at
	) VALUES(
		'pid_74000001-0000-4000-8000-000000000001','pid_74000002-0000-4000-8000-000000000002','pid_74000003-0000-4000-8000-000000000003',
		'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',decode(repeat('ab',32),'hex'),decode(repeat('ab',32),'hex'),
		transaction_timestamp(),transaction_timestamp(),transaction_timestamp()
	)`); err != nil {
		t.Fatalf("mark cutover: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("post-cutover down error = %v", err)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 14 {
		t.Fatalf("blocked rollback version = (%d, %v)", version, versionErr)
	}
	var inventoryReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_readiness($1,$2)`, migrations.ProductionTypedInventoryCutover().Checksum(), migrations.ProductionTypedInventoryCutoverSemanticFingerprint()).Scan(&inventoryReady); err != nil || !inventoryReady {
		t.Fatalf("v14 readiness after blocked rollback = %v, %v", inventoryReady, err)
	}
}

func equalMigrationEvents(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestRunReleaseMigrationRejectsDriftAndHonorsDeadline(t *testing.T) {
	if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{version: 50}, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runReleaseMigration(ctx, &scriptedMigrationRunner{}, []string{"up"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestLoadDiscoveryPrincipalRegistrationRequiresDistinctSafeNames(t *testing.T) {
	values := map[string]string{
		migrationPrincipalEnvironment:           "zasp_test_migration_login",
		discoveryAPIPrincipalEnvironment:        "zasp_test_api_login",
		discoveryWorkerPrincipalEnvironment:     "zasp_test_discovery_login",
		runtimeIngestPrincipalEnvironment:       "zasp_test_ingest_login",
		runtimeWorkerPrincipalEnvironment:       "zasp_test_runtime_login",
		outboxWorkerPrincipalEnvironment:        "zasp_test_outbox_login",
		runtimeGatewayPrincipalEnvironment:      "zasp_test_gateway_login",
		discoverySchedulerPrincipalEnvironment:  "zasp_test_scheduler_login",
		projectionRiskPrincipalEnvironment:      "zasp_test_projection_risk_login",
		projectionGraphPrincipalEnvironment:     "zasp_test_projection_graph_login",
		projectionSearchPrincipalEnvironment:    "zasp_test_projection_search_login",
		runtimeCoordinatorPrincipalEnvironment:  "zasp_test_runtime_coordinator_login",
		runtimeArchivePrincipalEnvironment:      "zasp_test_runtime_archive_login",
		runtimeIndexPrincipalEnvironment:        "zasp_test_runtime_index_login",
		runtimeCorrelationPrincipalEnvironment:  "zasp_test_runtime_correlation_login",
		runtimeProjectionPrincipalEnvironment:   "zasp_test_runtime_projection_login",
		gatewayControlPrincipalEnvironment:      "zasp_test_gateway_control_login",
		securityAgentAPIPrincipalEnvironment:    "zasp_test_security_agent_api_login",
		securityAgentWorkerPrincipalEnvironment: "zasp_test_security_agent_worker_login",
		securityAgentActionPrincipalEnvironment: "zasp_test_security_agent_action_login",
		redTeamWorkerPrincipalEnvironment:       "zasp_test_red_team_worker_login",
		redTeamOutboxPrincipalEnvironment:       "zasp_test_red_team_outbox_login",
		redTeamAdapterPrincipalEnvironment:      "zasp_test_red_team_adapter_login",
		attackLabControllerPrincipalEnvironment: "zasp_test_attack_lab_controller_login",
		attackLabOutboxPrincipalEnvironment:     "zasp_test_attack_lab_outbox_login",
		attackLabProxyPrincipalEnvironment:      "zasp_test_attack_lab_proxy_login",
		recoveryWorkerPrincipalEnvironment:      "zasp_test_recovery_worker_login",
		recoveryOutboxPrincipalEnvironment:      "zasp_test_recovery_outbox_login",
		policyDeploymentPrincipalEnvironment:    "zasp_test_policy_deployment_login",
	}
	registration, err := loadDiscoveryPrincipalRegistration(func(key string) string { return values[key] })
	if err != nil || registration.migration != values[migrationPrincipalEnvironment] || registration.api != values[discoveryAPIPrincipalEnvironment] || registration.gateway != values[runtimeGatewayPrincipalEnvironment] || registration.scheduler != values[discoverySchedulerPrincipalEnvironment] || registration.projectionRisk != values[projectionRiskPrincipalEnvironment] || registration.projectionGraph != values[projectionGraphPrincipalEnvironment] || registration.projectionSearch != values[projectionSearchPrincipalEnvironment] || registration.securityAgentAPI != values[securityAgentAPIPrincipalEnvironment] || registration.securityAgentWorker != values[securityAgentWorkerPrincipalEnvironment] || registration.securityAgentAction != values[securityAgentActionPrincipalEnvironment] || registration.redTeamWorker != values[redTeamWorkerPrincipalEnvironment] || registration.redTeamOutbox != values[redTeamOutboxPrincipalEnvironment] || registration.redTeamAdapter != values[redTeamAdapterPrincipalEnvironment] || registration.attackLabController != values[attackLabControllerPrincipalEnvironment] || registration.attackLabOutbox != values[attackLabOutboxPrincipalEnvironment] || registration.attackLabProxy != values[attackLabProxyPrincipalEnvironment] || registration.recoveryWorker != values[recoveryWorkerPrincipalEnvironment] || registration.recoveryOutbox != values[recoveryOutboxPrincipalEnvironment] || registration.policyDeployment != values[policyDeploymentPrincipalEnvironment] {
		t.Fatalf("registration=%#v err=%v", registration, err)
	}
	delete(values, runtimeWorkerPrincipalEnvironment)
	if _, err := loadDiscoveryPrincipalRegistration(func(key string) string { return values[key] }); !errors.Is(err, errInvalidMigrationCommand) {
		t.Fatalf("missing principal error=%v", err)
	}
	values[runtimeWorkerPrincipalEnvironment] = values[discoveryAPIPrincipalEnvironment]
	if _, err := loadDiscoveryPrincipalRegistration(func(key string) string { return values[key] }); !errors.Is(err, errInvalidMigrationCommand) {
		t.Fatalf("duplicate principal error=%v", err)
	}
}

type scriptedPrincipalRow struct{ value bool }

func (row scriptedPrincipalRow) Scan(destinations ...any) error {
	if len(destinations) != 1 {
		return errors.New("scan arity")
	}
	value, ok := destinations[0].(*bool)
	if !ok {
		return errors.New("scan type")
	}
	*value = row.value
	return nil
}

type scriptedPrincipalQueryer struct {
	values     []bool
	statements []string
}

func (queryer *scriptedPrincipalQueryer) QueryRow(_ context.Context, statement string, _ ...any) pgx.Row {
	queryer.statements = append(queryer.statements, statement)
	value := false
	if len(queryer.values) > 0 {
		value, queryer.values = queryer.values[0], queryer.values[1:]
	}
	return scriptedPrincipalRow{value: value}
}

func TestRegisterReleasePrincipalsRequiresPostRegistrationRuntimeReadiness(t *testing.T) {
	registration := discoveryPrincipalRegistration{migration: "migration_login", api: "api_login", discovery: "discovery_login", ingest: "ingest_login", runtime: "runtime_login", outbox: "outbox_login", gateway: "gateway_login", scheduler: "scheduler_login", projectionRisk: "risk_login", projectionGraph: "graph_login", projectionSearch: "search_login", runtimeCoordinator: "runtime_coordinator_login", runtimeArchive: "runtime_archive_login", runtimeIndex: "runtime_index_login", runtimeCorrelation: "runtime_correlation_login", runtimeProjection: "runtime_projection_login", gatewayControl: "gateway_control_login", securityAgentAPI: "security_agent_api_login", securityAgentWorker: "security_agent_worker_login", securityAgentAction: "security_agent_action_login", redTeamWorker: "red_team_worker_login", redTeamOutbox: "red_team_outbox_login", redTeamAdapter: "red_team_adapter_login", attackLabController: "attack_lab_controller_login", attackLabOutbox: "attack_lab_outbox_login", attackLabProxy: "attack_lab_proxy_login", recoveryWorker: "recovery_worker_login", recoveryOutbox: "recovery_outbox_login", policyDeployment: "policy_deployment_login"}
	queryer := &scriptedPrincipalQueryer{values: []bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false}}
	if err := registerReleasePrincipals(context.Background(), queryer, registration); !errors.Is(err, errReleasePrincipalRegistration) {
		t.Fatalf("readiness error=%v", err)
	}
	if len(queryer.statements) != 16 || !strings.Contains(queryer.statements[5], "zasp_security_agent_register_principals") || !strings.Contains(queryer.statements[6], "zasp_security_agent_principals_ready") || !strings.Contains(queryer.statements[7], "zasp_security_agent_register_action_principal") || !strings.Contains(queryer.statements[8], "zasp_red_team_register_principals") || !strings.Contains(queryer.statements[9], "zasp_red_team_principals_ready") || !strings.Contains(queryer.statements[10], "zasp_attack_lab_register_principals") || !strings.Contains(queryer.statements[11], "zasp_attack_lab_principals_ready") || !strings.Contains(queryer.statements[12], "zasp_recovery_register_principals") || !strings.Contains(queryer.statements[13], "zasp_recovery_principals_ready") || !strings.Contains(queryer.statements[14], "zasp_policy_deployment_register_principal") || !strings.Contains(queryer.statements[15], "zasp_policy_deployment_execution_readiness") {
		t.Fatalf("registration statements=%#v", queryer.statements)
	}
	queryer = &scriptedPrincipalQueryer{values: []bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true}}
	if err := registerReleasePrincipals(context.Background(), queryer, registration); err != nil {
		t.Fatalf("ready registration error=%v", err)
	}
}

func TestAgentsecMigrateCLIReachesV34FromEmptyAndV12(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	principalNames := []string{"zasp_cli_api_login", "zasp_cli_discovery_login", "zasp_cli_ingest_login", "zasp_cli_runtime_login", "zasp_cli_outbox_login", "zasp_cli_gateway_login", "zasp_cli_scheduler_login", "zasp_cli_projection_risk_login", "zasp_cli_projection_graph_login", "zasp_cli_projection_search_login", "zasp_cli_runtime_coordinator_login", "zasp_cli_runtime_archive_login", "zasp_cli_runtime_index_login", "zasp_cli_runtime_correlation_login", "zasp_cli_runtime_projection_login", "zasp_cli_gateway_control_login", "zasp_cli_security_agent_api_login", "zasp_cli_security_agent_worker_login", "zasp_cli_security_agent_action_login", "zasp_cli_red_team_worker_login", "zasp_cli_red_team_outbox_login", "zasp_cli_red_team_adapter_login", "zasp_cli_attack_lab_controller_login", "zasp_cli_attack_lab_outbox_login", "zasp_cli_attack_lab_proxy_login", "zasp_cli_recovery_worker_login", "zasp_cli_recovery_outbox_login", "zasp_cli_policy_deployment_login"}
	for _, principal := range principalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	principalEnvironment := []string{
		"ZASP_MIGRATION_DB_PRINCIPAL=zasp_test",
		"ZASP_DISCOVERY_API_DB_PRINCIPAL=" + principalNames[0], "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL=" + principalNames[1],
		"ZASP_RUNTIME_INGEST_DB_PRINCIPAL=" + principalNames[2], "ZASP_RUNTIME_WORKER_DB_PRINCIPAL=" + principalNames[3],
		"ZASP_OUTBOX_WORKER_DB_PRINCIPAL=" + principalNames[4], "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL=" + principalNames[5],
		"ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL=" + principalNames[6], "ZASP_PROJECTION_RISK_DB_PRINCIPAL=" + principalNames[7],
		"ZASP_PROJECTION_GRAPH_DB_PRINCIPAL=" + principalNames[8], "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL=" + principalNames[9],
		"ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL=" + principalNames[10], "ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL=" + principalNames[11],
		"ZASP_RUNTIME_INDEX_DB_PRINCIPAL=" + principalNames[12], "ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL=" + principalNames[13],
		"ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL=" + principalNames[14], "ZASP_GATEWAY_CONTROL_DB_PRINCIPAL=" + principalNames[15],
		"ZASP_SECURITY_AGENT_API_DB_PRINCIPAL=" + principalNames[16], "ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL=" + principalNames[17],
		"ZASP_SECURITY_AGENT_ACTION_DB_PRINCIPAL=" + principalNames[18],
		"ZASP_RED_TEAM_WORKER_DB_PRINCIPAL=" + principalNames[19], "ZASP_RED_TEAM_OUTBOX_DB_PRINCIPAL=" + principalNames[20], "ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL=" + principalNames[21],
		"ZASP_ATTACK_LAB_CONTROLLER_DB_PRINCIPAL=" + principalNames[22], "ZASP_ATTACK_LAB_OUTBOX_DB_PRINCIPAL=" + principalNames[23], "ZASP_ATTACK_LAB_PROXY_DB_PRINCIPAL=" + principalNames[24],
		"ZASP_RECOVERY_WORKER_DB_PRINCIPAL=" + principalNames[25], "ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL=" + principalNames[26],
		"ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL=" + principalNames[27],
	}
	runCLI := func(label string) {
		t.Helper()
		command := exec.CommandContext(ctx, "go", "run", ".", "up-to-48")
		command.Env = append(os.Environ(), append([]string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s"}, principalEnvironment...)...)
		if output, commandErr := command.CombinedOutput(); commandErr != nil {
			var bindings int
			version, versionErr := runner.Version(ctx)
			var principalsReady, securityReady, releaseReady bool
			var liveFingerprint string
			var registerReady bool
			registerErr := connection.QueryRow(ctx, `SELECT zasp_red_team_register_principals($1,$2,$3,$4)`, "zasp_test", principalNames[19], principalNames[20], principalNames[21]).Scan(&registerReady)
			_ = connection.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_principal_bindings`).Scan(&bindings)
			_ = connection.QueryRow(ctx, `SELECT zasp_red_team_principals_ready()`).Scan(&principalsReady)
			_ = connection.QueryRow(ctx, `SELECT zasp_red_team_execution_security_ready()`).Scan(&securityReady)
			_ = connection.QueryRow(ctx, `SELECT zasp_red_team_execution_live_fingerprint()`).Scan(&liveFingerprint)
			_ = connection.QueryRow(ctx, `SELECT zasp_red_team_execution_readiness($1,$2)`, migrations.ProductionRedTeamExecution().Checksum(), migrations.ProductionRedTeamExecutionSemanticFingerprint()).Scan(&releaseReady)
			t.Fatalf("%s at version %d (%v): %v output=%q red_team=(register=%t register_err=%v bindings=%d principals=%t security=%t live=%s expected=%s release=%t)", label, version, versionErr, commandErr, output, registerReady, registerErr, bindings, principalsReady, securityReady, liveFingerprint, migrations.ProductionRedTeamExecutionSemanticFingerprint(), releaseReady)
		}
		if version, versionErr := runner.Version(ctx); versionErr != nil || version != 48 {
			t.Fatalf("%s version = (%d, %v)", label, version, versionErr)
		}
		var bindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_discovery_principal_bindings`).Scan(&bindings); err != nil || bindings != 7 {
			t.Fatalf("%s principal bindings=%d err=%v", label, bindings, err)
		}
		var runtimeBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_principal_bindings`).Scan(&runtimeBindings); err != nil || runtimeBindings != 6 {
			t.Fatalf("%s runtime principal bindings=%d err=%v", label, runtimeBindings, err)
		}
		var securityAgentBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_principal_bindings`).Scan(&securityAgentBindings); err != nil || securityAgentBindings != 2 {
			t.Fatalf("%s security agent principal bindings=%d err=%v", label, securityAgentBindings, err)
		}
		var securityAgentActionBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_action_principal_bindings`).Scan(&securityAgentActionBindings); err != nil || securityAgentActionBindings != 1 {
			t.Fatalf("%s security agent action principal bindings=%d err=%v", label, securityAgentActionBindings, err)
		}
		var redTeamBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_principal_bindings`).Scan(&redTeamBindings); err != nil || redTeamBindings != 3 {
			t.Fatalf("%s red team principal bindings=%d err=%v", label, redTeamBindings, err)
		}
		var attackLabBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_attack_lab_principal_bindings`).Scan(&attackLabBindings); err != nil || attackLabBindings != 3 {
			t.Fatalf("%s attack lab principal bindings=%d err=%v", label, attackLabBindings, err)
		}
		var recoveryBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_recovery_principal_bindings`).Scan(&recoveryBindings); err != nil || recoveryBindings != 2 {
			t.Fatalf("%s recovery principal bindings=%d err=%v", label, recoveryBindings, err)
		}
		var policyDeploymentBindings int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_policy_deployment_principal_bindings`).Scan(&policyDeploymentBindings); err != nil || policyDeploymentBindings != 1 {
			t.Fatalf("%s policy deployment principal bindings=%d err=%v", label, policyDeploymentBindings, err)
		}
	}
	runCLI("empty to v34")
	t.Run("routing CLI activation and bounded compatibility staging", func(t *testing.T) {
		for attempt := 0; attempt < 2; attempt++ {
			command := exec.CommandContext(ctx, "go", "run", ".", "up")
			command.Env = append(os.Environ(), append([]string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s"}, principalEnvironment...)...)
			if err := command.Run(); err != nil {
				t.Fatal("routing CLI activation failed", err)
			}
			if version, err := runner.Version(ctx); err != nil || version != 49 {
				t.Fatal("CLI did not reach exact49", version, err)
			}
			var ready bool
			if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
				t.Fatal("CLI skipped routing readiness or principal registration", err)
			}
		}
		command := exec.CommandContext(ctx, "go", "run", ".", "up-to-48")
		command.Env = append(os.Environ(), append([]string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s"}, principalEnvironment...)...)
		if err := command.Run(); err == nil {
			t.Fatal("compatibility command accepted activated49")
		}
		if version, err := runner.Version(ctx); err != nil || version != 49 {
			t.Fatal("compatibility command changed49", version, err)
		}
		// Restore this empty fixture for its historical48 security tests. This
		// isn't a production rollback recommendation or a retained-evidence bypass.
		if err := runner.DownProductionRuntimeCorrelationRouting(ctx); err != nil {
			t.Fatal(err)
		}
	})
	var runtimeReleaseReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&runtimeReleaseReady); err != nil || !runtimeReleaseReady {
		t.Fatalf("recovery release ready before down=%v err=%v", runtimeReleaseReady, err)
	}
	if _, err := connection.Exec(ctx, `GRANT zasp_discovery_api TO zasp_attack_lab_controller`); err != nil {
		t.Fatalf("grant hostile attack lab membership: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&runtimeReleaseReady); err != nil || runtimeReleaseReady {
		var attackSecurityReady, recoverySecurityReady, policyReady bool
		var membershipCount int
		_ = connection.QueryRow(ctx, `SELECT zasp_attack_lab_execution_security_ready(),zasp_recovery_execution_security_ready(),zasp_policy_deployment_execution_readiness($1,$2),(SELECT count(*) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname='zasp_discovery_api' AND member.rolname='zasp_attack_lab_controller')`, migrations.ProductionPolicyDeployment().Checksum(), migrations.ProductionPolicyDeploymentSemanticFingerprint()).Scan(&attackSecurityReady, &recoverySecurityReady, &policyReady, &membershipCount)
		t.Fatalf("attack lab release accepted hostile role membership=%v attack_security=%t recovery_security=%t policy_ready=%t membership=%d err=%v", runtimeReleaseReady, attackSecurityReady, recoverySecurityReady, policyReady, membershipCount, err)
	}
	if _, err := connection.Exec(ctx, `REVOKE zasp_discovery_api FROM zasp_attack_lab_controller`); err != nil {
		t.Fatalf("revoke hostile attack lab membership: %v", err)
	}
	if _, err := connection.Exec(ctx, `DROP INDEX zasp_attack_lab_runs_claim_idx;CREATE INDEX zasp_attack_lab_runs_claim_idx ON public.zasp_attack_lab_runs(queued_at,next_attempt_at) WHERE state IN('queued','retryable','leased','running','cleanup')`); err != nil {
		t.Fatalf("drift attack lab claim index: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&runtimeReleaseReady); err != nil || runtimeReleaseReady {
		t.Fatalf("attack lab release accepted index definition drift=%v err=%v", runtimeReleaseReady, err)
	}
	if _, err := connection.Exec(ctx, `DROP INDEX zasp_attack_lab_runs_claim_idx;CREATE INDEX zasp_attack_lab_runs_claim_idx ON public.zasp_attack_lab_runs(next_attempt_at,queued_at) WHERE state IN('queued','retryable','leased','running','cleanup')`); err != nil {
		t.Fatalf("restore attack lab claim index: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&runtimeReleaseReady); err != nil || !runtimeReleaseReady {
		t.Fatalf("attack lab release did not recover after drift repair=%v err=%v", runtimeReleaseReady, err)
	}
	var executionBindings int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_discovery_execution_principals`).Scan(&executionBindings); err != nil || executionBindings != 5 {
		t.Fatalf("execution principal bindings=%d err=%v", executionBindings, err)
	}
	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		configuration, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		configuration.User = principal
		principalConnection, connectErr := pgx.ConnectConfig(ctx, configuration)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return principalConnection
	}
	type privilegeCase struct {
		principal, authority, allowed, denied, legacyDenied string
	}
	for _, test := range []privilegeCase{
		{principalNames[1], "zasp_discovery_worker", "zasp_execution_finish_job(text,text,text,text,text,text,text,bytea,text,text,integer)", "zasp_execution_claim_schedules(text,text,integer,integer)", "zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)"},
		{principalNames[6], "zasp_discovery_scheduler", "zasp_execution_claim_schedules(text,text,integer,integer)", "zasp_execution_claim_jobs(text,text,integer,integer)", "zasp_discovery_claim_schedules(text,text,integer,integer)"},
		{principalNames[7], "zasp_projection_risk_worker", "zasp_execution_claim_projection_work(text,text,text,integer,integer)", "zasp_execution_claim_jobs(text,text,integer,integer)", "zasp_discovery_claim_projection_work(text,text,integer,integer)"},
		{principalNames[8], "zasp_projection_graph_worker", "zasp_execution_claim_projection_work(text,text,text,integer,integer)", "zasp_execution_claim_jobs(text,text,integer,integer)", "zasp_discovery_claim_projection_work(text,text,integer,integer)"},
		{principalNames[9], "zasp_projection_search_worker", "zasp_execution_claim_projection_work(text,text,text,integer,integer)", "zasp_execution_claim_jobs(text,text,integer,integer)", "zasp_discovery_claim_projection_work(text,text,integer,integer)"},
	} {
		principalConnection := connectAs(test.principal)
		var principalReady, allowed, denied, legacyDenied bool
		if err := principalConnection.QueryRow(ctx, `SELECT zasp_execution_principal_ready($1),has_function_privilege(session_user,$2,'EXECUTE'),has_function_privilege(session_user,$3,'EXECUTE'),has_function_privilege(session_user,$4,'EXECUTE')`, test.authority, test.allowed, test.denied, test.legacyDenied).Scan(&principalReady, &allowed, &denied, &legacyDenied); err != nil || !principalReady || !allowed || denied || legacyDenied {
			principalConnection.Close(context.Background())
			t.Fatalf("execution privileges principal=%s ready=%v allowed=%v denied=%v legacy=%v err=%v", test.principal, principalReady, allowed, denied, legacyDenied, err)
		}
		principalConnection.Close(context.Background())
	}
	riskConnection := connectAs(principalNames[7])
	var projectionClaim []byte
	if err := riskConnection.QueryRow(ctx, `SELECT zasp_execution_claim_projection_work('risk','risk-worker','risk-lease-token-0001',30,1)`).Scan(&projectionClaim); err != nil {
		riskConnection.Close(context.Background())
		t.Fatalf("risk projection claim: %v", err)
	}
	if err := riskConnection.QueryRow(ctx, `SELECT zasp_execution_claim_projection_work('graph','risk-worker','risk-lease-token-0001',30,1)`).Scan(&projectionClaim); err == nil {
		riskConnection.Close(context.Background())
		t.Fatal("risk principal claimed graph projection")
	}
	riskConnection.Close(context.Background())
	apiConnection := connectAs(principalNames[0])
	var apiRead, apiWorker, legacySync, rawSubject, legacyReference bool
	if err := apiConnection.QueryRow(ctx, `SELECT has_function_privilege(session_user,'zasp_execution_sync_detail(text,text,text,text,text)','EXECUTE'),has_function_privilege(session_user,'zasp_execution_claim_jobs(text,text,integer,integer)','EXECUTE'),has_function_privilege(session_user,'zasp_discovery_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text)','EXECUTE'),has_function_privilege(session_user,'zasp_execution_bind_connection_subject(text,text,text,text,text,text,text,text,bigint,jsonb,text)','EXECUTE'),has_function_privilege(session_user,'zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','EXECUTE')`).Scan(&apiRead, &apiWorker, &legacySync, &rawSubject, &legacyReference); err != nil || !apiRead || apiWorker || legacySync || rawSubject || legacyReference {
		apiConnection.Close(context.Background())
		t.Fatalf("execution API privileges read=%v worker=%v legacy_sync=%v raw_subject=%v legacy_reference=%v err=%v", apiRead, apiWorker, legacySync, rawSubject, legacyReference, err)
	}
	apiConnection.Close(context.Background())
	organizationID := "pid_7a000001-0000-4000-8000-000000000001"
	workspaceID := "pid_7a000002-0000-4000-8000-000000000002"
	environmentID := "pid_7a000003-0000-4000-8000-000000000003"
	targetID := "pid_7a000004-0000-4000-8000-000000000004"
	definitionID := "pid_7a000005-0000-4000-8000-000000000005"
	runID := "pid_7a000006-0000-4000-8000-000000000006"
	actorID := "pid_7a000007-0000-4000-8000-000000000007"
	correlationID := "pid_7a000008-0000-4000-8000-000000000008"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Red team tenant','red-team.invalid')`, []any{organizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Security')`, []any{workspaceID, organizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Staging','staging')`, []any{environmentID, organizationID, workspaceID}},
		{`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes) VALUES($1,$2,$3,$4,'agent_endpoint','Staging agent','active',transaction_timestamp(),transaction_timestamp(),'agent',transaction_timestamp(),transaction_timestamp()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/target-0001","target_kinds":["agent_endpoint"]}}'::jsonb)`, []any{organizationID, workspaceID, environmentID, targetID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("red team seed: %v", err)
		}
	}
	redTeamAPI := connectAs(principalNames[16])
	if _, err := redTeamAPI.Exec(ctx, `SET TIME ZONE 'America/Los_Angeles'`); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("set red team non-UTC session: %v", err)
	}
	var definitionJSON []byte
	// The Red Team admission gate now requires operator-registered credentials.
	bindingID := "pid_7a000016-0000-4000-8000-000000000016"
	bindingDigest := bytes.Repeat([]byte{0x2a}, 32)
	bindingValidUntil := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	var bindingJSON []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',1,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err != nil {
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_create_definition($1,$2,$3,$4,'red-team-create-0001',$5,'Staging prompt safety',$6,'agent_endpoint','["prompt_injection"]'::jsonb,'{"environment":"staging","credential_class":"read_only","expected_side_effects":["audit event"]}'::jsonb,$7)`, organizationID, workspaceID, environmentID, actorID, definitionID, targetID, correlationID).Scan(&definitionJSON); err != nil || !bytes.Contains(definitionJSON, []byte(`"version": 1`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team create=%s err=%v", definitionJSON, err)
	}
	duplicateEffectsDefinitionID := "pid_7a000009-0000-4000-8000-000000000009"
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_create_definition($1,$2,$3,$4,'red-team-create-duplicate-effects',$5,'Duplicate effects must fail',$6,'agent_endpoint','["prompt_injection"]'::jsonb,'{"environment":"staging","credential_class":"read_only","expected_side_effects":["audit event","audit event"]}'::jsonb,$7)`, organizationID, workspaceID, environmentID, actorID, duplicateEffectsDefinitionID, targetID, correlationID).Scan(&definitionJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("red team accepted duplicate expected side effects")
	}
	var runJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'red-team-run-000001',$5,1,$6,$7)`, organizationID, workspaceID, environmentID, actorID, definitionID, runID, correlationID).Scan(&runJSON); err != nil || !bytes.Contains(runJSON, []byte(`"status": "queued"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team run=%s err=%v", runJSON, err)
	}
	redTeamOutbox := connectAs(principalNames[20])
	outboxToken := bytes.Repeat([]byte{0x25}, 32)
	var outboxJSON []byte
	if err := redTeamOutbox.QueryRow(ctx, `SELECT zasp_red_team_claim_outbox($1,$2,60,10)`, "red-team-outbox-e2e", outboxToken).Scan(&outboxJSON); err != nil {
		redTeamOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team outbox claim: %v", err)
	}
	var outboxItems []struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		OutboxID       string `json:"outbox_id"`
	}
	if err := json.Unmarshal(outboxJSON, &outboxItems); err != nil || len(outboxItems) != 1 || outboxItems[0].OrganizationID != organizationID {
		redTeamOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team outbox=%s err=%v", outboxJSON, err)
	}
	var acknowledged bool
	if err := redTeamOutbox.QueryRow(ctx, `SELECT zasp_red_team_ack_outbox($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, outboxItems[0].OutboxID, "red-team-outbox-e2e", outboxToken, "sha256:"+strings.Repeat("a", 64)).Scan(&acknowledged); err != nil || !acknowledged {
		redTeamOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team outbox ack=%t err=%v", acknowledged, err)
	}
	redTeamOutbox.Close(context.Background())
	redTeamWorker := connectAs(principalNames[19])
	runToken := bytes.Repeat([]byte{0x26}, 32)
	var claimedJSON []byte
	if err := redTeamWorker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, runID, "red-team-worker-e2e", runToken).Scan(&claimedJSON); err != nil || !bytes.Contains(claimedJSON, []byte(`"disposition": "claimed"`)) {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team claim=%s err=%v", claimedJSON, err)
	}
	var inputDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_red_team_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, organizationID, workspaceID, environmentID, runID).Scan(&inputDigest); err != nil {
		t.Fatal(err)
	}
	evidenceKey := "organizations/" + organizationID + "/workspaces/" + workspaceID + "/environments/" + environmentID + "/artifacts/" + runID
	inputReceipt := json.RawMessage(`{"reference":"s3://zasp-red-team-evidence/` + strings.TrimSuffix(evidenceKey, runID) + `pid_95000007-0000-4000-8000-000000000007","version_id":"input-version-1","sha256":"` + strings.Repeat("b", 64) + `","size_bytes":512}`)
	var completedJSON []byte
	if err := redTeamWorker.QueryRow(ctx, `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,'fail','Reject direct prompt injection','The target exposed its system boundary',NULL,'["policy bypass observed"]'::jsonb,$8,$9,'s3-version-red-team-0001',$10,128,$11::jsonb)`, organizationID, workspaceID, environmentID, runID, "red-team-worker-e2e", runToken, inputDigest, "s3://zasp-red-team-evidence/"+evidenceKey, evidenceKey, bytes.Repeat([]byte{0x27}, 32), inputReceipt).Scan(&completedJSON); err != nil || !bytes.Contains(completedJSON, []byte(`"status": "complete"`)) || !bytes.Contains(completedJSON, []byte(`"verdict": "fail"`)) {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team finish=%s err=%v", completedJSON, err)
	}
	redTeamWorker.Close(context.Background())
	var detailJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_get_run($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&detailJSON); err != nil || !bytes.Contains(detailJSON, []byte(`"evidence_reference": "s3://zasp-red-team-evidence/`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team detail=%s err=%v", detailJSON, err)
	}
	var canonicalRedTeamTimes bool
	if err := redTeamAPI.QueryRow(ctx, `SELECT (zasp_red_team_get_run($1,$2,$3,$4)->>'queued_at')~'Z$' AND (zasp_red_team_get_run($1,$2,$3,$4)->>'started_at')~'Z$' AND (zasp_red_team_get_run($1,$2,$3,$4)->>'completed_at')~'Z$' AND (zasp_red_team_get_run($1,$2,$3,$4)->'attempts'->0->>'completed_at')~'Z$'`, organizationID, workspaceID, environmentID, runID).Scan(&canonicalRedTeamTimes); err != nil || !canonicalRedTeamTimes {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team non-UTC session emitted noncanonical time: %t err=%v", canonicalRedTeamTimes, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_get_run($1,$2,$3,$4)`, "pid_7affffff-0000-4000-8000-000000000001", workspaceID, environmentID, runID).Scan(&detailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("cross-tenant red team run was visible")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE binding_id=$1`, bindingID); err != nil {
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-missing-binding',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, "pid_7a000015-0000-4000-8000-000000000015", runID, bytes.Repeat([]byte{0x99}, 32), correlationID).Scan(&detailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a target without an active credential binding")
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_preflight($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&detailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab preflight accepted a target without an active credential binding")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE binding_id=$1`, bindingID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',1,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err != nil || !bytes.Contains(bindingJSON, []byte(`"state": "active"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab credential binding registration=%s err=%v", bindingJSON, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',1,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err != nil || !bytes.Contains(bindingJSON, []byte(`"replayed": true`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab credential binding replay=%s err=%v", bindingJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',1,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("runtime API gained attack lab credential registration authority")
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_revoke_credential_binding($1,$2,$3,$4,1)`, organizationID, workspaceID, environmentID, bindingID).Scan(&bindingJSON); err != nil || !bytes.Contains(bindingJSON, []byte(`"state": "revoked"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab credential binding revocation=%s err=%v", bindingJSON, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',1,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("stale attack lab credential registration reactivated a revoked version")
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',2,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bindingDigest, bindingValidUntil).Scan(&bindingJSON); err != nil || !bytes.Contains(bindingJSON, []byte(`"state": "active"`)) || !bytes.Contains(bindingJSON, []byte(`"version": 2`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab credential binding rotation=%s err=%v", bindingJSON, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET credential_class='test_write' WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-class-deny',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, "pid_7a000018-0000-4000-8000-000000000018", runID, bytes.Repeat([]byte{0x99}, 32), correlationID).Scan(&detailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a credential binding whose class differed from the approved definition")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET credential_class='read_only' WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_environments SET environment_class='production' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, organizationID, workspaceID, environmentID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-production-deny',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, "pid_7a000017-0000-4000-8000-000000000017", runID, bytes.Repeat([]byte{0x99}, 32), correlationID).Scan(&detailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a production environment")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, organizationID, workspaceID, environmentID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	var attackLabPreflightJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_preflight($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&attackLabPreflightJSON); err != nil || !bytes.Contains(attackLabPreflightJSON, []byte(`"source_run_id": "`+runID+`"`)) || !bytes.Contains(attackLabPreflightJSON, []byte(`"target_id": "`+targetID+`"`)) || !bytes.Contains(attackLabPreflightJSON, []byte(`"destination": "adapter.customer.example"`)) || !bytes.Contains(attackLabPreflightJSON, []byte(`"success_criterion": "Reject direct prompt injection"`)) || !bytes.Contains(attackLabPreflightJSON, []byte(`"allowed_destinations": ["adapter.customer.example"]`)) || bytes.Contains(attackLabPreflightJSON, []byte(`credential_reference`)) || bytes.Contains(attackLabPreflightJSON, []byte(`binding_id`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab preflight=%s err=%v", attackLabPreflightJSON, err)
	}
	var attackLabPreflight struct {
		DecisionDigest    string `json:"decision_digest"`
		DecisionExpiresAt string `json:"decision_expires_at"`
	}
	if err := json.Unmarshal(attackLabPreflightJSON, &attackLabPreflight); err != nil || len(attackLabPreflight.DecisionDigest) != 64 || !strings.HasSuffix(attackLabPreflight.DecisionExpiresAt, "Z") {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab decision=%#v err=%v", attackLabPreflight, err)
	}
	attackLabDecisionDigest, err := hex.DecodeString(attackLabPreflight.DecisionDigest)
	if err != nil || len(attackLabDecisionDigest) != 32 {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab decision digest=%q err=%v", attackLabPreflight.DecisionDigest, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_preflight($1,$2,$3,$4)`, "pid_7affffff-0000-4000-8000-000000000001", workspaceID, environmentID, runID).Scan(&attackLabPreflightJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("cross-tenant attack lab preflight was visible")
	}
	attackLabRunID := "pid_7a000009-0000-4000-8000-000000000009"
	var attackLabCreatedJSON []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,'ref:red-team/target-0001','read_only',3,$6,$7)`, organizationID, workspaceID, environmentID, bindingID, targetID, bytes.Repeat([]byte{0x2b}, 32), bindingValidUntil).Scan(&bindingJSON); err != nil || !bytes.Contains(bindingJSON, []byte(`"version": 3`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab credential binding drift=%s err=%v", bindingJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-drift-rejected-0001',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, runID, attackLabDecisionDigest, correlationID).Scan(&attackLabCreatedJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a credential binding that drifted after approval")
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_preflight($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&attackLabPreflightJSON); err != nil || json.Unmarshal(attackLabPreflightJSON, &attackLabPreflight) != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab refreshed preflight=%s err=%v", attackLabPreflightJSON, err)
	}
	attackLabDecisionDigest, err = hex.DecodeString(attackLabPreflight.DecisionDigest)
	if err != nil || len(attackLabDecisionDigest) != 32 {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab refreshed decision digest=%q err=%v", attackLabPreflight.DecisionDigest, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_set(winning_attributes,'{red_team,endpoint}',to_jsonb('https://drift.customer.example/v1/evaluate'::text)) WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-destination-drift-0001',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, runID, attackLabDecisionDigest, correlationID).Scan(&attackLabCreatedJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a destination that drifted after approval")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_set(winning_attributes,'{red_team,endpoint}',to_jsonb('https://adapter.customer.example/v1/evaluate'::text)) WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_preflight($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&attackLabPreflightJSON); err != nil || json.Unmarshal(attackLabPreflightJSON, &attackLabPreflight) != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab destination-restored preflight=%s err=%v", attackLabPreflightJSON, err)
	}
	attackLabDecisionDigest, err = hex.DecodeString(attackLabPreflight.DecisionDigest)
	if err != nil || len(attackLabDecisionDigest) != 32 {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab destination-restored decision digest=%q err=%v", attackLabPreflight.DecisionDigest, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-create-0001',$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, runID, attackLabDecisionDigest, correlationID).Scan(&attackLabCreatedJSON); err != nil || !bytes.Contains(attackLabCreatedJSON, []byte(`"status": "queued"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"source_run_id": "`+runID+`"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"target_id": "`+targetID+`"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"environment": "staging"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"credential_class": "read_only"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"destination": "adapter.customer.example"`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"timeout_seconds": 300`)) || !bytes.Contains(attackLabCreatedJSON, []byte(`"replayed": false`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab create=%s err=%v", attackLabCreatedJSON, err)
	}
	var attackLabReplayJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-create-0001',$5,$6,$7,'pid_7a000014-0000-4000-8000-000000000014')`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, runID, attackLabDecisionDigest).Scan(&attackLabReplayJSON); err != nil || !bytes.Contains(attackLabReplayJSON, []byte(`"replayed": true`)) || !bytes.Contains(attackLabReplayJSON, []byte(`"correlation_id": "`+correlationID+`"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab replay=%s err=%v", attackLabReplayJSON, err)
	}
	var attackLabDetailJSON, attackLabListJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_get_run($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRunID).Scan(&attackLabDetailJSON); err != nil || !bytes.Contains(attackLabDetailJSON, []byte(`"attempts": []`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"id": "`+attackLabRunID+`"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab detail=%s err=%v", attackLabDetailJSON, err)
	}
	var canonicalAttackLabTime bool
	if err := redTeamAPI.QueryRow(ctx, `SELECT (zasp_attack_lab_get_run($1,$2,$3,$4)->>'queued_at')~'Z$'`, organizationID, workspaceID, environmentID, attackLabRunID).Scan(&canonicalAttackLabTime); err != nil || !canonicalAttackLabTime {
		redTeamAPI.Close(context.Background())
		t.Fatalf("Attack Lab non-UTC session emitted noncanonical time: %t err=%v", canonicalAttackLabTime, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_list_runs($1,$2,$3,NULL,NULL,10)`, organizationID, workspaceID, environmentID).Scan(&attackLabListJSON); err != nil || !bytes.Contains(attackLabListJSON, []byte(`"id": "`+attackLabRunID+`"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab list=%s err=%v", attackLabListJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_get_run($1,$2,$3,$4)`, "pid_7affffff-0000-4000-8000-000000000001", workspaceID, environmentID, attackLabRunID).Scan(&attackLabDetailJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("cross-tenant attack lab run was visible")
	}
	var attackLabOutboxValid bool
	if err := connection.QueryRow(ctx, `SELECT payload ?& ARRAY['organization_id','workspace_id','environment_id','run_id','source_run_id','definition_id','definition_version','target_id','target_kind','input_digest'] AND NOT payload ?| ARRAY['credential','credential_reference','endpoint','destination'] AND payload_digest=digest(convert_to(payload::text,'UTF8'),'sha256') FROM zasp_attack_lab_outbox WHERE organization_id=$1 AND payload->>'run_id'=$2`, organizationID, attackLabRunID).Scan(&attackLabOutboxValid); err != nil || !attackLabOutboxValid {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox authority=%t err=%v", attackLabOutboxValid, err)
	}
	var attackLabCancelledJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_cancel_run($1,$2,$3,$4,'attack-lab-cancel-0001',$5,1,$6)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, correlationID).Scan(&attackLabCancelledJSON); err != nil || !bytes.Contains(attackLabCancelledJSON, []byte(`"status": "cancelled"`)) || !bytes.Contains(attackLabCancelledJSON, []byte(`"version": 2`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab cancel=%s err=%v", attackLabCancelledJSON, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_set(winning_attributes,'{red_team,endpoint}',to_jsonb('https://adapter-rerun.customer.example/v1/evaluate'::text)) WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("update attack lab target endpoint: %v", err)
	}
	attackLabRerunID := "pid_7a000015-0000-4000-8000-000000000015"
	var attackLabRerunJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,'attack-lab-rerun-0001',$5,2,$6,$7)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, attackLabRerunID, correlationID).Scan(&attackLabRerunJSON); err != nil || !bytes.Contains(attackLabRerunJSON, []byte(`"status": "queued"`)) || !bytes.Contains(attackLabRerunJSON, []byte(`"destination": "adapter-rerun.customer.example"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab rerun=%s err=%v", attackLabRerunJSON, err)
	}
	attackLabOutbox := connectAs(principalNames[23])
	if _, err := attackLabOutbox.Exec(ctx, `SET TIME ZONE 'America/Los_Angeles'`); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("set Attack Lab outbox non-UTC session: %v", err)
	}
	attackLabOutboxToken := bytes.Repeat([]byte{0x42}, 32)
	var attackLabOutboxJSON []byte
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_claim_outbox($1,$2,60,10)`, "attack-lab-outbox-e2e", attackLabOutboxToken).Scan(&attackLabOutboxJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox claim=%s err=%v", attackLabOutboxJSON, err)
	}
	type attackLabOutboxItem struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		OutboxID       string `json:"outbox_id"`
		Topic          string `json:"topic"`
		Payload        string `json:"payload"`
		PayloadDigest  string `json:"payload_digest"`
		Attempt        int    `json:"attempt"`
	}
	var attackLabClaim struct {
		Items []attackLabOutboxItem `json:"items"`
	}
	if err := json.Unmarshal(attackLabOutboxJSON, &attackLabClaim); err != nil || len(attackLabClaim.Items) != 1 {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox decode=%s items=%d err=%v", attackLabOutboxJSON, len(attackLabClaim.Items), err)
	}
	validateAttackLabOutboxItem := func(item attackLabOutboxItem) string {
		t.Helper()
		var payload struct {
			RunID string `json:"run_id"`
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(item.Payload)))
		if err := json.Unmarshal([]byte(item.Payload), &payload); err != nil || item.OrganizationID != organizationID || item.WorkspaceID != workspaceID || item.EnvironmentID != environmentID || item.Topic != "attack-lab-jobs" || item.Attempt != 1 || item.PayloadDigest != digest {
			attackLabOutbox.Close(context.Background())
			redTeamAPI.Close(context.Background())
			t.Fatalf("attack lab outbox item=%#v payload=%#v digest=%s err=%v", item, payload, digest, err)
		}
		return payload.RunID
	}
	firstItem := attackLabClaim.Items[0]
	firstRunID := validateAttackLabOutboxItem(firstItem)
	var attackLabHeartbeatJSON []byte
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_heartbeat_outbox($1,$2,60,1)`, "attack-lab-outbox-e2e", attackLabOutboxToken).Scan(&attackLabHeartbeatJSON); err != nil || !bytes.Contains(attackLabHeartbeatJSON, []byte(`"remaining_count": 1`)) || !bytes.Contains(attackLabHeartbeatJSON, []byte(`Z"`)) {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox heartbeat=%s err=%v", attackLabHeartbeatJSON, err)
	}
	providerAck := "sha256:" + strings.Repeat("a", 64)
	var attackLabAckJSON []byte
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_ack_outbox($1,$2,$3,$4,$5,$6,$7)`, firstItem.OrganizationID, firstItem.WorkspaceID, firstItem.EnvironmentID, firstItem.OutboxID, "attack-lab-outbox-e2e", attackLabOutboxToken, providerAck).Scan(&attackLabAckJSON); err != nil || !bytes.Contains(attackLabAckJSON, []byte(`"provider_ack": "`+providerAck+`"`)) || !bytes.Contains(attackLabAckJSON, []byte(`"remaining_count": 0`)) || !bytes.Contains(attackLabAckJSON, []byte(`"replayed": false`)) || !bytes.Contains(attackLabAckJSON, []byte(`Z"`)) {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox ack=%s err=%v", attackLabAckJSON, err)
	}
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_ack_outbox($1,$2,$3,$4,$5,$6,$7)`, firstItem.OrganizationID, firstItem.WorkspaceID, firstItem.EnvironmentID, firstItem.OutboxID, "attack-lab-outbox-e2e", attackLabOutboxToken, providerAck).Scan(&attackLabAckJSON); err != nil || !bytes.Contains(attackLabAckJSON, []byte(`"remaining_count": 0`)) || !bytes.Contains(attackLabAckJSON, []byte(`"replayed": true`)) {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox ack replay=%s err=%v", attackLabAckJSON, err)
	}
	attackLabRetryToken := bytes.Repeat([]byte{0x43}, 32)
	attackLabOutboxJSON = nil
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_claim_outbox($1,$2,60,10)`, "attack-lab-outbox-e2e", attackLabRetryToken).Scan(&attackLabOutboxJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab second outbox claim=%s err=%v", attackLabOutboxJSON, err)
	}
	attackLabClaim.Items = nil
	if err := json.Unmarshal(attackLabOutboxJSON, &attackLabClaim); err != nil || len(attackLabClaim.Items) != 1 {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab second outbox decode=%s items=%d err=%v", attackLabOutboxJSON, len(attackLabClaim.Items), err)
	}
	retryItem := attackLabClaim.Items[0]
	secondRunID := validateAttackLabOutboxItem(retryItem)
	if firstRunID == secondRunID || firstRunID != attackLabRunID && firstRunID != attackLabRerunID || secondRunID != attackLabRunID && secondRunID != attackLabRerunID {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox fair runs first=%s second=%s", firstRunID, secondRunID)
	}
	var attackLabRetryJSON []byte
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_retry_outbox($1,$2,$3,$4,$5,$6,10,'queue_publish_unknown')`, retryItem.OrganizationID, retryItem.WorkspaceID, retryItem.EnvironmentID, retryItem.OutboxID, "attack-lab-outbox-e2e", attackLabRetryToken).Scan(&attackLabRetryJSON); err != nil || !bytes.Contains(attackLabRetryJSON, []byte(`"remaining_count": 0`)) || !bytes.Contains(attackLabRetryJSON, []byte(`"state": "pending"`)) || !bytes.Contains(attackLabRetryJSON, []byte(`"replayed": false`)) || !bytes.Contains(attackLabRetryJSON, []byte(`Z"`)) {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab outbox retry=%s err=%v", attackLabRetryJSON, err)
	}
	fairOrganizationID := "pid_7b100001-0000-4000-8000-000000000001"
	fairWorkspaceID := "pid_7b100002-0000-4000-8000-000000000002"
	fairEnvironmentID := "pid_7b100003-0000-4000-8000-000000000003"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Attack lab fair tenant','attack-lab-fair.invalid')`, []any{fairOrganizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Attack Lab')`, []any{fairWorkspaceID, fairOrganizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Staging','staging')`, []any{fairEnvironmentID, fairOrganizationID, fairWorkspaceID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			attackLabOutbox.Close(context.Background())
			redTeamAPI.Close(context.Background())
			t.Fatalf("attack lab fairness tenant seed: %v", err)
		}
	}
	fairA1 := "pid_7b100004-0000-4000-8000-000000000004"
	fairA2 := "pid_7b100005-0000-4000-8000-000000000005"
	fairB1 := "pid_7b100006-0000-4000-8000-000000000006"
	exhaustedOutboxID := "pid_7b100007-0000-4000-8000-000000000007"
	exhaustedToken := bytes.Repeat([]byte{0x4c}, 32)
	if _, err := connection.Exec(ctx, `
		INSERT INTO zasp_attack_lab_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest,created_at) VALUES
		($1,$2,$3,$4,'attack-lab-jobs:fair-a1','{"test":"fair-a1"}'::jsonb,digest(convert_to('{"test": "fair-a1"}'::jsonb::text,'UTF8'),'sha256'),transaction_timestamp()-interval '4 seconds'),
		($1,$2,$3,$5,'attack-lab-jobs:fair-a2','{"test":"fair-a2"}'::jsonb,digest(convert_to('{"test": "fair-a2"}'::jsonb::text,'UTF8'),'sha256'),transaction_timestamp()-interval '3 seconds'),
		($6,$7,$8,$9,'attack-lab-jobs:fair-b1','{"test":"fair-b1"}'::jsonb,digest(convert_to('{"test": "fair-b1"}'::jsonb::text,'UTF8'),'sha256'),transaction_timestamp()-interval '2 seconds')`, organizationID, workspaceID, environmentID, fairA1, fairA2, fairOrganizationID, fairWorkspaceID, fairEnvironmentID, fairB1); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab fairness outbox seed: %v", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_attack_lab_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest,state,attempt,worker_id,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,'attack-lab-jobs:exhausted','{"test":"exhausted"}'::jsonb,digest(convert_to('{"test": "exhausted"}'::jsonb::text,'UTF8'),'sha256'),'leased',100,'attack-lab-outbox-expired',$5,transaction_timestamp()-interval '1 second')`, organizationID, workspaceID, environmentID, exhaustedOutboxID, exhaustedToken); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab exhausted outbox seed: %v", err)
	}
	fairTokenB := bytes.Repeat([]byte{0x4d}, 32)
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_claim_outbox($1,$2,60,1)`, "attack-lab-outbox-fair-e2e", fairTokenB).Scan(&attackLabOutboxJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab fair B claim: %v", err)
	}
	attackLabClaim.Items = nil
	if err := json.Unmarshal(attackLabOutboxJSON, &attackLabClaim); err != nil || len(attackLabClaim.Items) != 1 || attackLabClaim.Items[0].OrganizationID != fairOrganizationID || attackLabClaim.Items[0].OutboxID != fairB1 {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab durable fair first claim=%s items=%#v err=%v", attackLabOutboxJSON, attackLabClaim.Items, err)
	}
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_ack_outbox($1,$2,$3,$4,$5,$6,$7)`, fairOrganizationID, fairWorkspaceID, fairEnvironmentID, fairB1, "attack-lab-outbox-fair-e2e", fairTokenB, "sha256:"+strings.Repeat("d", 64)).Scan(&attackLabAckJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab fair B ack: %v", err)
	}
	var exhaustedState string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_attack_lab_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, exhaustedOutboxID).Scan(&exhaustedState); err != nil || exhaustedState != "failed" {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab attempt-100 terminal state=%q err=%v", exhaustedState, err)
	}
	fairTokenA := bytes.Repeat([]byte{0x4e}, 32)
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_claim_outbox($1,$2,60,1)`, "attack-lab-outbox-fair-e2e", fairTokenA).Scan(&attackLabOutboxJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab fair A claim: %v", err)
	}
	attackLabClaim.Items = nil
	if err := json.Unmarshal(attackLabOutboxJSON, &attackLabClaim); err != nil || len(attackLabClaim.Items) != 1 || attackLabClaim.Items[0].OrganizationID != organizationID || attackLabClaim.Items[0].OutboxID != fairA1 {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab durable fair wrapped claim=%s items=%#v err=%v", attackLabOutboxJSON, attackLabClaim.Items, err)
	}
	if err := attackLabOutbox.QueryRow(ctx, `SELECT zasp_attack_lab_ack_outbox($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, fairA1, "attack-lab-outbox-fair-e2e", fairTokenA, "sha256:"+strings.Repeat("e", 64)).Scan(&attackLabAckJSON); err != nil {
		attackLabOutbox.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab fair A ack: %v", err)
	}
	attackLabOutbox.Close(context.Background())
	attackLabController := connectAs(principalNames[22])
	if _, err := attackLabController.Exec(ctx, `SET TIME ZONE 'America/Los_Angeles'`); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("set Attack Lab controller non-UTC session: %v", err)
	}
	attackLabRetryRunID := "pid_7a000016-0000-4000-8000-000000000016"
	var attackLabRetryRunJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,'attack-lab-rerun-retry-0001',$5,2,$6,$7)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, attackLabRetryRunID, correlationID).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "queued"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry fixture=%s err=%v", attackLabRetryRunJSON, err)
	}
	attackLabRetryControllerToken := bytes.Repeat([]byte{0x48}, 32)
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetryControllerToken).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "leased"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry claim=%s err=%v", attackLabRetryRunJSON, err)
	}
	var attackLabRetryInputDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRetryRunID).Scan(&attackLabRetryInputDigest); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_retry_run($1,$2,$3,$4,$5,$6,$7,'retryable',transaction_timestamp()+interval '10 seconds')`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetryControllerToken, attackLabRetryInputDigest).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "retryable"`)) || !bytes.Contains(attackLabRetryRunJSON, []byte(`"error_code": "retryable"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry run=%s err=%v", attackLabRetryRunJSON, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_runs SET queued_at=transaction_timestamp()-interval '11 minutes',started_at=transaction_timestamp()-interval '10 minutes',attempt_started_at=transaction_timestamp()-interval '10 minutes',next_attempt_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRetryRunID); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	attackLabRetrySecondToken := bytes.Repeat([]byte{0x4b}, 32)
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetrySecondToken).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"disposition": "claimed"`)) || !bytes.Contains(attackLabRetryRunJSON, []byte(`"attempt": 2`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry second claim=%s err=%v", attackLabRetryRunJSON, err)
	}
	retrySandboxReference := "k8s://attack-lab/jobs/" + migrationAttackLabSandboxName(organizationID, workspaceID, environmentID, attackLabRetryRunID) + "@123e4567-e89b-12d3-a456-426614174001"
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_provisioning($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetrySecondToken, attackLabRetryInputDigest).Scan(&attackLabRetryRunJSON); err != nil {
		t.Fatalf("attack lab retry provisioning=%s err=%v", attackLabRetryRunJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_mark_running($1,$2,$3,$4,$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetrySecondToken, attackLabRetryInputDigest, retrySandboxReference).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "running"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry running=%s err=%v", attackLabRetryRunJSON, err)
	}
	retryProxy := connectAs(principalNames[24])
	var retryEgressJSON []byte
	if err := retryProxy.QueryRow(ctx, `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "adapter-rerun.customer.example").Scan(&retryEgressJSON); err != nil || !bytes.Contains(retryEgressJSON, []byte(`"methods": ["POST"]`)) {
		retryProxy.Close(context.Background())
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab retry fresh attempt egress=%s err=%v", retryEgressJSON, err)
	}
	retryProxy.Close(context.Background())
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,'inconclusive',false,false,'outcome_unknown','[]'::jsonb,'','','',$9,0)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetrySecondToken, attackLabRetryInputDigest, retrySandboxReference, []byte{}).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "cleanup"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab unavailable evidence cleanup=%s err=%v", attackLabRetryRunJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRetryRunID, "attack-lab-controller-retry-e2e", attackLabRetrySecondToken, attackLabRetryInputDigest).Scan(&attackLabRetryRunJSON); err != nil || !bytes.Contains(attackLabRetryRunJSON, []byte(`"status": "complete"`)) || !bytes.Contains(attackLabRetryRunJSON, []byte(`"error_code": "outcome_unknown"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab unavailable evidence finish=%s err=%v", attackLabRetryRunJSON, err)
	}
	var retryEvidenceState string
	if err := connection.QueryRow(ctx, `SELECT evidence_state FROM zasp_attack_lab_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,2)`, organizationID, workspaceID, environmentID, attackLabRetryRunID).Scan(&retryEvidenceState); err != nil || retryEvidenceState != "unavailable" {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab unavailable evidence state=%q err=%v", retryEvidenceState, err)
	}
	attackLabCancelActiveRunID := "pid_7a000017-0000-4000-8000-000000000017"
	var attackLabCancelActiveJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,'attack-lab-rerun-cancel-active-0001',$5,2,$6,$7)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, attackLabCancelActiveRunID, correlationID).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"status": "queued"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab active cancel fixture=%s err=%v", attackLabCancelActiveJSON, err)
	}
	attackLabCancelActiveToken := bytes.Repeat([]byte{0x49}, 32)
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabCancelActiveRunID, "attack-lab-controller-cancel-e2e", attackLabCancelActiveToken).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"status": "leased"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab active cancel claim=%s err=%v", attackLabCancelActiveJSON, err)
	}
	var attackLabCancelActiveDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabCancelActiveRunID).Scan(&attackLabCancelActiveDigest); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_cancel_run($1,$2,$3,$4,'attack-lab-cancel-active-0001',$5,2,$6)`, organizationID, workspaceID, environmentID, actorID, attackLabCancelActiveRunID, correlationID).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"status": "leased"`)) || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"cancel_requested": true`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab active cancel request=%s err=%v", attackLabCancelActiveJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_heartbeat_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabCancelActiveRunID, "attack-lab-controller-cancel-e2e", attackLabCancelActiveToken).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"renewed": true`)) || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"cancel_requested": true`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab active cancel heartbeat=%s err=%v", attackLabCancelActiveJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_retry_run($1,$2,$3,$4,$5,$6,$7,'retryable',transaction_timestamp()+interval '10 seconds')`, organizationID, workspaceID, environmentID, attackLabCancelActiveRunID, "attack-lab-controller-cancel-e2e", attackLabCancelActiveToken, attackLabCancelActiveDigest).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"status": "cancelled"`)) || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"cleanup_state": "complete"`)) || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"error_code": "cancelled"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab active cancel finish=%s err=%v", attackLabCancelActiveJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_get_run($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabCancelActiveRunID).Scan(&attackLabCancelActiveJSON); err != nil || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"attempts": [{`)) || !bytes.Contains(attackLabCancelActiveJSON, []byte(`"error_code": "cancelled"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab pre-provision cancellation detail=%s err=%v", attackLabCancelActiveJSON, err)
	}
	attackLabControllerToken := bytes.Repeat([]byte{0x44}, 32)
	var attackLabClaimJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken).Scan(&attackLabClaimJSON); err != nil || !bytes.Contains(attackLabClaimJSON, []byte(`"disposition": "claimed"`)) || !bytes.Contains(attackLabClaimJSON, []byte(`"status": "leased"`)) || !bytes.Contains(attackLabClaimJSON, []byte(`"success_criterion": "Reject direct prompt injection"`)) || !bytes.Contains(attackLabClaimJSON, []byte(`"allowed_destinations": ["adapter-rerun.customer.example"]`)) || !bytes.Contains(attackLabClaimJSON, []byte(`"expected_side_effects": ["audit event"]`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab controller claim=%s err=%v", attackLabClaimJSON, err)
	}
	var attackLabInputDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabInputDigest); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	var attackLabRunHeartbeatJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_heartbeat_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken).Scan(&attackLabRunHeartbeatJSON); err != nil || !bytes.Contains(attackLabRunHeartbeatJSON, []byte(`"renewed": true`)) || !bytes.Contains(attackLabRunHeartbeatJSON, []byte(`"cancel_requested": false`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab run heartbeat=%s err=%v", attackLabRunHeartbeatJSON, err)
	}
	sandboxReference := "k8s://attack-lab/jobs/" + migrationAttackLabSandboxName(organizationID, workspaceID, environmentID, attackLabRerunID) + "@123e4567-e89b-12d3-a456-426614174000"
	var attackLabRunningJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_provisioning($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest).Scan(&attackLabRunningJSON); err != nil {
		t.Fatalf("attack lab provisioning=%s err=%v", attackLabRunningJSON, err)
	}
	if !bytes.Contains(attackLabRunningJSON, []byte(`"replayed": false`)) {
		t.Fatalf("initial attack lab provisioning=%s", attackLabRunningJSON)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_provisioning($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest).Scan(&attackLabRunningJSON); err != nil || !bytes.Contains(attackLabRunningJSON, []byte(`"replayed": true`)) {
		t.Fatalf("replay attack lab provisioning=%s err=%v", attackLabRunningJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_mark_running($1,$2,$3,$4,$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest, sandboxReference).Scan(&attackLabRunningJSON); err != nil || !bytes.Contains(attackLabRunningJSON, []byte(`"status": "running"`)) || !bytes.Contains(attackLabRunningJSON, []byte(`"replayed": false`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab mark running=%s err=%v", attackLabRunningJSON, err)
	}
	attackLabProxy := connectAs(principalNames[24])
	var attackLabEgressJSON []byte
	if err := attackLabProxy.QueryRow(ctx, `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, attackLabRerunID, "adapter-rerun.customer.example").Scan(&attackLabEgressJSON); err != nil || !bytes.Contains(attackLabEgressJSON, []byte(`"destination": "adapter-rerun.customer.example"`)) || !bytes.Contains(attackLabEgressJSON, []byte(`"credential_reference": "ref:red-team/target-0001"`)) || !bytes.Contains(attackLabEgressJSON, []byte(`"methods": ["POST"]`)) {
		attackLabProxy.Close(context.Background())
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab egress resolve=%s err=%v", attackLabEgressJSON, err)
	}
	if err := attackLabProxy.QueryRow(ctx, `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,'evil.example')`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabEgressJSON); err == nil {
		attackLabProxy.Close(context.Background())
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab proxy resolved an undeclared destination")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		t.Fatal(err)
	}
	if err := attackLabProxy.QueryRow(ctx, `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, attackLabRerunID, "adapter-rerun.customer.example").Scan(&attackLabEgressJSON); err == nil {
		t.Fatal("attack lab proxy retained access after credential revocation")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, targetID); err != nil {
		t.Fatal(err)
	}
	attackLabProxy.Close(context.Background())
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_runs SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	runningResumeToken := bytes.Repeat([]byte{0x4a}, 32)
	var attackLabRunningResumeJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", runningResumeToken).Scan(&attackLabRunningResumeJSON); err != nil || !bytes.Contains(attackLabRunningResumeJSON, []byte(`"disposition": "running"`)) || !bytes.Contains(attackLabRunningResumeJSON, []byte(`"sandbox_reference": "`+sandboxReference+`"`)) || !bytes.Contains(attackLabRunningResumeJSON, []byte(`"status": "running"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab running resume=%s err=%v", attackLabRunningResumeJSON, err)
	}
	attackLabControllerToken = runningResumeToken
	var attackLabEvidenceID string
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'attack_lab_evidence',$4||chr(31)||'1')`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabEvidenceID); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	attackLabEvidenceKey := "organizations/" + organizationID + "/workspaces/" + workspaceID + "/environments/" + environmentID + "/artifacts/" + attackLabEvidenceID
	attackLabEvidenceReference := "s3://zasp-attack-lab-evidence/" + attackLabEvidenceKey
	attackLabEvidenceChecksum := bytes.Repeat([]byte{0x45}, 32)
	var attackLabCleanupJSON []byte
	wrongControllerToken := bytes.Repeat([]byte{0x46}, 32)
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,'verified',true,true,NULL,'["semantic:criterion observed","gateway:allowed","egress:adapter-rerun.customer.example","kubernetes:job complete","cloud:canary touched"]'::jsonb,$9,$10,'s3-version-attack-lab-0001',$11,512)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", wrongControllerToken, attackLabInputDigest, sandboxReference, attackLabEvidenceReference, attackLabEvidenceKey, attackLabEvidenceChecksum).Scan(&attackLabCleanupJSON); err == nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab cleanup accepted the wrong lease")
	}
	var attackLabCheckpointCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabCheckpointCount); err != nil || attackLabCheckpointCount != 1 {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab wrong-lease changed durable cleanup intent count=%d err=%v", attackLabCheckpointCount, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,'verified',true,true,NULL,'["semantic:criterion observed","gateway:allowed","egress:adapter-rerun.customer.example","kubernetes:job complete"]'::jsonb,$9,$10,'s3-version-attack-lab-0001',$11,512)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest, sandboxReference, attackLabEvidenceReference, attackLabEvidenceKey, attackLabEvidenceChecksum).Scan(&attackLabCleanupJSON); err == nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab cleanup accepted incomplete evidence")
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabCheckpointCount); err != nil || attackLabCheckpointCount != 1 {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab incomplete evidence changed durable cleanup intent count=%d err=%v", attackLabCheckpointCount, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,'verified',true,true,NULL,'["semantic:criterion observed","gateway:allowed","egress:adapter-rerun.customer.example","kubernetes:job complete","cloud:canary touched"]'::jsonb,$9,$10,'s3-version-attack-lab-0001',$11,512)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest, sandboxReference, attackLabEvidenceReference, attackLabEvidenceKey, attackLabEvidenceChecksum).Scan(&attackLabCleanupJSON); err != nil || !bytes.Contains(attackLabCleanupJSON, []byte(`"status": "cleanup"`)) || !bytes.Contains(attackLabCleanupJSON, []byte(`"replayed": false`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab begin cleanup=%s err=%v", attackLabCleanupJSON, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_runs SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	resumedControllerToken := bytes.Repeat([]byte{0x47}, 32)
	var attackLabResumeJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", resumedControllerToken).Scan(&attackLabResumeJSON); err != nil || !bytes.Contains(attackLabResumeJSON, []byte(`"disposition": "cleanup"`)) || !bytes.Contains(attackLabResumeJSON, []byte(`"sandbox_reference": "`+sandboxReference+`"`)) || !bytes.Contains(attackLabResumeJSON, []byte(`"evidence_reference": "`+attackLabEvidenceReference+`"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab cleanup resume=%s err=%v", attackLabResumeJSON, err)
	}
	var attackLabFinishedJSON []byte
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", attackLabControllerToken, attackLabInputDigest).Scan(&attackLabFinishedJSON); err == nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab cleanup accepted the expired lease")
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", resumedControllerToken, attackLabInputDigest).Scan(&attackLabFinishedJSON); err != nil || !bytes.Contains(attackLabFinishedJSON, []byte(`"status": "complete"`)) || !bytes.Contains(attackLabFinishedJSON, []byte(`"cleanup_state": "complete"`)) || !bytes.Contains(attackLabFinishedJSON, []byte(`"verdict": "verified"`)) || !bytes.Contains(attackLabFinishedJSON, []byte(`"replayed": false`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab finish cleanup=%s err=%v", attackLabFinishedJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabRerunID, "attack-lab-controller-e2e", resumedControllerToken, attackLabInputDigest).Scan(&attackLabFinishedJSON); err != nil || !bytes.Contains(attackLabFinishedJSON, []byte(`"status": "complete"`)) || !bytes.Contains(attackLabFinishedJSON, []byte(`"replayed": true`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab finish cleanup replay=%s err=%v", attackLabFinishedJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_get_run($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabRerunID).Scan(&attackLabDetailJSON); err != nil || !bytes.Contains(attackLabDetailJSON, []byte(`"attempt": 1`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"cleanup_completed": true`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"evidence_reference": "`+attackLabEvidenceReference+`"`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"evidence_version_id": "s3-version-attack-lab-0001"`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"evidence_checksum": "`+hex.EncodeToString(attackLabEvidenceChecksum)+`"`)) || !bytes.Contains(attackLabDetailJSON, []byte(`"evidence_size": 512`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab completed detail=%s err=%v", attackLabDetailJSON, err)
	}
	attackLabProxy = connectAs(principalNames[24])
	if err := attackLabProxy.QueryRow(ctx, `SELECT zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, attackLabRerunID, "adapter-rerun.customer.example").Scan(&attackLabEgressJSON); err == nil {
		attackLabProxy.Close(context.Background())
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab proxy retained access after cleanup")
	}
	attackLabProxy.Close(context.Background())
	attackLabCancelledSandboxRunID := "pid_7a000018-0000-4000-8000-000000000018"
	var attackLabCancelledSandboxJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,'attack-lab-rerun-cancel-sandbox-0001',$5,2,$6,$7)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, attackLabCancelledSandboxRunID, correlationID).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"status": "queued"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation fixture=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	attackLabCancelledSandboxToken := bytes.Repeat([]byte{0x4f}, 32)
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID, "attack-lab-controller-cancel-sandbox-e2e", attackLabCancelledSandboxToken).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"status": "leased"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation claim=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	var attackLabCancelledSandboxDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID).Scan(&attackLabCancelledSandboxDigest); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	attackLabCancelledSandboxReference := "k8s://attack-lab/jobs/" + migrationAttackLabSandboxName(organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID) + "@123e4567-e89b-12d3-a456-426614174002"
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_provisioning($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID, "attack-lab-controller-cancel-sandbox-e2e", attackLabCancelledSandboxToken, attackLabCancelledSandboxDigest).Scan(&attackLabCancelledSandboxJSON); err != nil {
		t.Fatalf("attack lab sandbox cancellation provisioning=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_mark_running($1,$2,$3,$4,$5,$6,$7,$8)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID, "attack-lab-controller-cancel-sandbox-e2e", attackLabCancelledSandboxToken, attackLabCancelledSandboxDigest, attackLabCancelledSandboxReference).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"version": 3`)) || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"status": "running"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation running=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_cancel_run($1,$2,$3,$4,'attack-lab-cancel-sandbox-0001',$5,3,$6)`, organizationID, workspaceID, environmentID, actorID, attackLabCancelledSandboxRunID, correlationID).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"cancel_requested": true`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation request=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	var attackLabCancelledEvidenceID string
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'attack_lab_evidence',$4||chr(31)||'1')`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID).Scan(&attackLabCancelledEvidenceID); err != nil {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	attackLabCancelledEvidenceKey := "organizations/" + organizationID + "/workspaces/" + workspaceID + "/environments/" + environmentID + "/artifacts/" + attackLabCancelledEvidenceID
	attackLabCancelledEvidenceReference := "s3://zasp-attack-lab-evidence/" + attackLabCancelledEvidenceKey
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_begin_cleanup($1,$2,$3,$4,$5,$6,$7,$8,'inconclusive',false,false,'cancelled','["semantic:cancelled before verdict","gateway:cancelled","egress:no undeclared egress","kubernetes:cleanup requested","cloud:no verified canary touch"]'::jsonb,$9,$10,'s3-version-attack-lab-cancelled',$11,512)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID, "attack-lab-controller-cancel-sandbox-e2e", attackLabCancelledSandboxToken, attackLabCancelledSandboxDigest, attackLabCancelledSandboxReference, attackLabCancelledEvidenceReference, attackLabCancelledEvidenceKey, bytes.Repeat([]byte{0x50}, 32)).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"status": "cleanup"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation evidence=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	if err := attackLabController.QueryRow(ctx, `SELECT zasp_attack_lab_finish_cleanup($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID, "attack-lab-controller-cancel-sandbox-e2e", attackLabCancelledSandboxToken, attackLabCancelledSandboxDigest).Scan(&attackLabCancelledSandboxJSON); err != nil || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"status": "cancelled"`)) || !bytes.Contains(attackLabCancelledSandboxJSON, []byte(`"evidence_reference": "`+attackLabCancelledEvidenceReference+`"`)) {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation finish=%s err=%v", attackLabCancelledSandboxJSON, err)
	}
	var cancelledEvidenceState, cancelledErrorCode string
	if err := connection.QueryRow(ctx, `SELECT evidence_state,error_code FROM zasp_attack_lab_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,1)`, organizationID, workspaceID, environmentID, attackLabCancelledSandboxRunID).Scan(&cancelledEvidenceState, &cancelledErrorCode); err != nil || cancelledEvidenceState != "complete" || cancelledErrorCode != "cancelled" {
		attackLabController.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab sandbox cancellation attempt evidence=%q error=%q err=%v", cancelledEvidenceState, cancelledErrorCode, err)
	}
	attackLabController.Close(context.Background())
	if _, err := connection.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=false,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, definitionID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("disable attack lab definition: %v", err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_rerun($1,$2,$3,$4,'attack-lab-rerun-disabled-0001',$5,2,'pid_7a000016-0000-4000-8000-000000000016',$6)`, organizationID, workspaceID, environmentID, actorID, attackLabRunID, correlationID).Scan(&attackLabRerunJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab reran a disabled definition")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, definitionID); err != nil {
		redTeamAPI.Close(context.Background())
		t.Fatalf("restore attack lab definition: %v", err)
	}
	cancelClaimedRunID := "pid_7a000010-0000-4000-8000-000000000010"
	var cancelClaimedQueuedJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'red-team-run-cancel-claimed-0001',$5,1,$6,$7)`, organizationID, workspaceID, environmentID, actorID, definitionID, cancelClaimedRunID, correlationID).Scan(&cancelClaimedQueuedJSON); err != nil || !bytes.Contains(cancelClaimedQueuedJSON, []byte(`"status": "queued"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team claimed-cancel fixture=%s err=%v", cancelClaimedQueuedJSON, err)
	}
	redTeamWorker = connectAs(principalNames[19])
	cancelClaimedToken := bytes.Repeat([]byte{0x28}, 32)
	if err := redTeamWorker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,$5,$6,60)`, organizationID, workspaceID, environmentID, cancelClaimedRunID, "red-team-worker-e2e", cancelClaimedToken).Scan(&claimedJSON); err != nil || !bytes.Contains(claimedJSON, []byte(`"disposition": "claimed"`)) {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team claimed-cancel claim=%s err=%v", claimedJSON, err)
	}
	var cancelClaimedDigest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_red_team_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, organizationID, workspaceID, environmentID, cancelClaimedRunID).Scan(&cancelClaimedDigest); err != nil {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal(err)
	}
	var cancellationRequestedJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,'red-team-cancel-claimed-0001',$5,2,$6)`, organizationID, workspaceID, environmentID, actorID, cancelClaimedRunID, correlationID).Scan(&cancellationRequestedJSON); err != nil || !bytes.Contains(cancellationRequestedJSON, []byte(`"status": "leased"`)) || !bytes.Contains(cancellationRequestedJSON, []byte(`"cancel_requested": true`)) {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team claimed cancellation=%s err=%v", cancellationRequestedJSON, err)
	}
	cancelClaimedEvidenceKey := "organizations/" + organizationID + "/workspaces/" + workspaceID + "/environments/" + environmentID + "/artifacts/" + cancelClaimedRunID
	if err := redTeamWorker.QueryRow(ctx, `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,'pass','Reject direct prompt injection','The target preserved its system boundary',NULL,'[]'::jsonb,$8,$9,'s3-version-red-team-cancel',$10,128)`, organizationID, workspaceID, environmentID, cancelClaimedRunID, "red-team-worker-e2e", cancelClaimedToken, cancelClaimedDigest, "s3://zasp-red-team-evidence/"+cancelClaimedEvidenceKey, cancelClaimedEvidenceKey, bytes.Repeat([]byte{0x29}, 32)).Scan(&completedJSON); err == nil {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatal("accepted red team completion after cancellation")
	}
	var cancelledClaimedJSON []byte
	if err := redTeamWorker.QueryRow(ctx, `SELECT zasp_red_team_cancel_claimed_run($1,$2,$3,$4,$5,$6,$7)`, organizationID, workspaceID, environmentID, cancelClaimedRunID, "red-team-worker-e2e", cancelClaimedToken, cancelClaimedDigest).Scan(&cancelledClaimedJSON); err != nil || !bytes.Contains(cancelledClaimedJSON, []byte(`"status": "cancelled"`)) {
		redTeamWorker.Close(context.Background())
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team claimed cancellation finish=%s err=%v", cancelledClaimedJSON, err)
	}
	redTeamWorker.Close(context.Background())
	cancelRunID := "pid_7a000011-0000-4000-8000-000000000011"
	var cancelQueuedJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'red-team-run-cancel-0001',$5,1,$6,$7)`, organizationID, workspaceID, environmentID, actorID, definitionID, cancelRunID, correlationID).Scan(&cancelQueuedJSON); err != nil || !bytes.Contains(cancelQueuedJSON, []byte(`"version": 1`)) || !bytes.Contains(cancelQueuedJSON, []byte(`"audit_id"`)) || !bytes.Contains(cancelQueuedJSON, []byte(`"receipt_id"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team cancel fixture queue=%s err=%v", cancelQueuedJSON, err)
	}
	var cancelJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,'red-team-cancel-0001',$5,1,$6)`, organizationID, workspaceID, environmentID, actorID, cancelRunID, correlationID).Scan(&cancelJSON); err != nil || !bytes.Contains(cancelJSON, []byte(`"status": "cancelled"`)) || !bytes.Contains(cancelJSON, []byte(`"version": 2`)) || !bytes.Contains(cancelJSON, []byte(`"replayed": false`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team cancel=%s err=%v", cancelJSON, err)
	}
	var cancelReplayJSON []byte
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,'red-team-cancel-0001',$5,1,'pid_7a000012-0000-4000-8000-000000000012')`, organizationID, workspaceID, environmentID, actorID, cancelRunID).Scan(&cancelReplayJSON); err != nil || !bytes.Contains(cancelReplayJSON, []byte(`"replayed": true`)) || !bytes.Contains(cancelReplayJSON, []byte(`"correlation_id": "`+correlationID+`"`)) {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team cancel replay=%s err=%v", cancelReplayJSON, err)
	}
	if err := redTeamAPI.QueryRow(ctx, `SELECT zasp_attack_lab_create_run($1,$2,$3,$4,'attack-lab-create-rejected-0001','pid_7a000013-0000-4000-8000-000000000013',$5,$6,$7)`, organizationID, workspaceID, environmentID, actorID, cancelRunID, attackLabDecisionDigest, correlationID).Scan(&attackLabCreatedJSON); err == nil {
		redTeamAPI.Close(context.Background())
		t.Fatal("attack lab accepted a cancelled red team source")
	}
	var attackLabRunCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_attack_lab_runs WHERE organization_id=$1`, organizationID).Scan(&attackLabRunCount); err != nil || attackLabRunCount != 5 {
		redTeamAPI.Close(context.Background())
		t.Fatalf("attack lab residue count=%d err=%v", attackLabRunCount, err)
	}
	var auditCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_audit WHERE organization_id=$1`, organizationID).Scan(&auditCount); err != nil || auditCount != 6 {
		redTeamAPI.Close(context.Background())
		t.Fatalf("red team audit count=%d err=%v", auditCount, err)
	}
	redTeamAPI.Close(context.Background())
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_attack_lab_audit;DELETE FROM zasp_attack_lab_request_receipts;DELETE FROM zasp_attack_lab_outbox;DELETE FROM zasp_attack_lab_cleanup_checkpoints;DELETE FROM zasp_attack_lab_attempts;DELETE FROM zasp_attack_lab_runs;DELETE FROM zasp_attack_lab_credential_bindings`); err != nil {
		t.Fatalf("attack lab cleanup: %v", err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_red_team_audit;DELETE FROM zasp_red_team_request_receipts;DELETE FROM zasp_red_team_outbox;DELETE FROM zasp_red_team_attempts;DELETE FROM zasp_red_team_runs;DELETE FROM zasp_red_team_definitions`); err != nil {
		t.Fatalf("red team cleanup: %v", err)
	}
	if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 to v33 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 to v32 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentPlanner(ctx); err != nil {
		t.Fatalf("v32 to v31 fixture: %v", err)
	}
	if err := runner.DownProductionWorkflowCompatibility(ctx); err != nil {
		t.Fatalf("v31 to v30 fixture: %v", err)
	}
	if err := runner.DownProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 to v29 fixture: %v", err)
	}
	if err := runner.DownProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 to v28 fixture: %v", err)
	}
	if err := runner.DownProductionPolicyDeployment(ctx); err != nil {
		t.Fatalf("v28 to v27 fixture: %v", err)
	}
	if err := runner.DownProductionRecovery(ctx); err != nil {
		t.Fatalf("v27 to v26 fixture: %v", err)
	}
	if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
		t.Fatalf("v26 to v25 fixture: %v", err)
	}
	if err := runner.DownProductionRedTeamExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionRedTeamExecution().DownSQL())
		var postgresError *pgconn.PgError
		_ = errors.As(detail, &postgresError)
		t.Fatalf("v25 to v24 fixture: %v detail=%#v", err, postgresError)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err != nil {
		t.Fatalf("v24 to v23 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err != nil {
		t.Fatalf("v23 to v22 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionSecurityAgentTemporaryPolicy().DownSQL())
		var postgresError *pgconn.PgError
		_ = errors.As(detail, &postgresError)
		t.Fatalf("v22 to v21 fixture: %v detail=%#v", err, postgresError)
	}
	if err := runner.DownProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21 to v20 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentControls(ctx); err != nil {
		t.Fatalf("v20 to v19 fixture: %v", err)
	}
	if err := runner.DownProductionIdentityAdministration(ctx); err != nil {
		t.Fatalf("v19 to v18 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionSecurityAgentExecution().DownSQL())
		var postgresError *pgconn.PgError
		_ = errors.As(detail, &postgresError)
		t.Fatalf("v18 to v17 fixture: %v detail=%#v", err, postgresError)
	}
	if err := runner.DownProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("v17 to v16 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 to v15 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 to v14 fixture: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("v14 to v13 fixture: %v", err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionDiscoveryExecution().DownSQL())
		t.Fatalf("v13 to v12 fixture: %v detail=%#v", err, detail)
	}
	if err := runner.DownReferenceAuthorization(ctx); err != nil {
		t.Fatalf("v12 to v11 fixture: %v", err)
	}
	runCLI("v11 to v34")
}

func TestRunReleaseMigrationRejectsAmbiguousInputsAndStopsOnFailure(t *testing.T) {
	for _, arguments := range [][]string{nil, {}, {"status"}, {"up", "extra"}} {
		if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{}, arguments); err == nil {
			t.Fatalf("arguments %#v accepted", arguments)
		}
	}
	runner := &scriptedMigrationRunner{errAt: "up-baseline"}
	if err := runReleaseMigration(context.Background(), runner, []string{"up"}); err == nil || len(runner.events) != 2 {
		t.Fatalf("failure = %v, events = %#v", err, runner.events)
	}
}

func TestReleaseMigrationReachesExactPostgresTargetFromEmptyV1AndV2AndRejectsDrift(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		version, versionErr := runner.Version(ctx)
		t.Fatalf("empty to target at version %d (%v): %v", version, versionErr, err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 48 {
		t.Fatalf("v34 = (%d, %v)", version, err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		t.Fatalf("v27 retry: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"down"}); err != nil {
		t.Fatalf("v27 to empty: %v", err)
	}
	if err := runner.Up(ctx); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		t.Fatalf("v1 to v27: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_schema_versions SET checksum = repeat('0', 64) WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
}

func TestAgentsecMigrateV34LiveFingerprintsMatchPinnedAuthority(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{
		runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance,
		runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery,
		runner.UpConnectorAuthorization, runner.UpReferenceAuthorization, runner.UpProductionDiscoveryExecution, runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution,
		runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification,
		runner.UpProductionWorkflowCompatibility,
	}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("v31 setup step %d: %v", index+1, err)
		}
	}
	metadata := migrations.ProductionSecurityAgentPlanner()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var candidateFingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_security_agent_planner_live_fingerprint()`).Scan(&candidateFingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidateFingerprint != migrations.ProductionSecurityAgentPlannerSemanticFingerprint() {
		t.Fatalf("v32 candidate fingerprint=%s", candidateFingerprint)
	}
	if err := runner.UpProductionSecurityAgentPlanner(ctx); err != nil {
		t.Fatalf("v32 up: %v", err)
	}
	var live string
	if err := connection.QueryRow(ctx, `SELECT zasp_production_security_agent_planner_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionSecurityAgentPlannerSemanticFingerprint() {
		t.Fatalf("v32 live fingerprint = %s, pinned = %s", live, migrations.ProductionSecurityAgentPlannerSemanticFingerprint())
	}
	var securityReady, ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_security_agent_planner_security_ready(),zasp_production_security_agent_planner_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionSecurityAgentPlannerSemanticFingerprint()).Scan(&securityReady, &ready); err != nil || !securityReady || !ready {
		t.Fatalf("v32 readiness security=%t ready=%t err=%v", securityReady, ready, err)
	}
	var workflowMutation json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_workflow_mutate('create','policy','policy-v32-compatibility','pid_70000001-0000-4000-8000-000000000001','pid_70000002-0000-4000-8000-000000000002','pid_70000003-0000-4000-8000-000000000003','pid_70000004-0000-4000-8000-000000000004','createPolicy','v32-workflow-write-0001',0,$1::jsonb,$2::jsonb,'pid_70000005-0000-4000-8000-000000000005','pid_70000006-0000-4000-8000-000000000006','')`,
		`{"body":{"id":"policy-v32-compatibility","name":"V32 compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"},"expected_version":0,"resource_id":""}`,
		`{"id":"policy-v32-compatibility","name":"V32 compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`).Scan(&workflowMutation); err != nil || !strings.Contains(string(workflowMutation), `"version": 1`) {
		t.Fatalf("v32 workflow mutation=%s err=%v", workflowMutation, err)
	}
	attackPath := migrations.ProductionSecurityAgentAttackPath()
	probe, err = connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, attackPath.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, attackPath.Version(), attackPath.Name(), attackPath.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if err := probe.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_live_fingerprint()`).Scan(&candidateFingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidateFingerprint != migrations.ProductionSecurityAgentAttackPathSemanticFingerprint() {
		t.Fatalf("v33 candidate fingerprint=%s", candidateFingerprint)
	}
	if err := runner.UpProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 up: %v", err)
	}
	var attackPathSecurityReady, attackPathReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_security_ready(),zasp_production_security_agent_attack_path_readiness($1,$2)`, attackPath.Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&attackPathSecurityReady, &attackPathReady); err != nil || !attackPathSecurityReady || !attackPathReady {
		t.Fatalf("v33 readiness security=%t ready=%t err=%v", attackPathSecurityReady, attackPathReady, err)
	}
	if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 down: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_security_agent_planner_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionSecurityAgentPlannerSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored v32 readiness=%t err=%v", ready, err)
	}
	if err := runner.UpProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 re-up: %v", err)
	}
	setup := migrations.ProductionIntegrationSetup()
	probe, err = connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, setup.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, setup.Version(), setup.Name(), setup.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if err := probe.QueryRow(ctx, `SELECT zasp_production_integration_setup_live_fingerprint()`).Scan(&candidateFingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var candidateSecurityReady, candidateReady bool
	if err := probe.QueryRow(ctx, `SELECT zasp_production_integration_setup_security_ready(),zasp_production_integration_setup_readiness($1,$2)`, setup.Checksum(), migrations.ProductionIntegrationSetupSemanticFingerprint()).Scan(&candidateSecurityReady, &candidateReady); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var priorSecurity, compatibilitySecurity, setupFunctionSecurity, apiCredentialSelect, apiSubjectSelect, apiHeartbeatSelect bool
	if err := probe.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_security_ready(),zasp_production_workflow_compatibility_security_ready(),EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname='zasp_execution_integration_setup_status' AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND has_function_privilege('zasp_discovery_api',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_discovery_worker',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_worker',procedure.oid,'EXECUTE')),has_table_privilege('zasp_discovery_api','public.zasp_connector_credentials','SELECT'),has_table_privilege('zasp_discovery_api','public.zasp_discovery_connection_subjects','SELECT'),has_table_privilege('zasp_discovery_api','public.zasp_sensor_heartbeats','SELECT')`).Scan(&priorSecurity, &compatibilitySecurity, &setupFunctionSecurity, &apiCredentialSelect, &apiSubjectSelect, &apiHeartbeatSelect); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidateFingerprint != migrations.ProductionIntegrationSetupSemanticFingerprint() || !candidateSecurityReady || !candidateReady {
		t.Fatalf("v34 candidate fingerprint=%s security=%t ready=%t prior=%t compatibility=%t function=%t selects=(%t,%t,%t)", candidateFingerprint, candidateSecurityReady, candidateReady, priorSecurity, compatibilitySecurity, setupFunctionSecurity, apiCredentialSelect, apiSubjectSelect, apiHeartbeatSelect)
	}
	if err := runner.UpProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 up: %v", err)
	}
	var setupSecurityReady, setupReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_integration_setup_security_ready(),zasp_production_integration_setup_readiness($1,$2)`, setup.Checksum(), migrations.ProductionIntegrationSetupSemanticFingerprint()).Scan(&setupSecurityReady, &setupReady); err != nil || !setupSecurityReady || !setupReady {
		t.Fatalf("v34 readiness security=%t ready=%t err=%v", setupSecurityReady, setupReady, err)
	}
	if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 down: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 33 {
		t.Fatalf("restored v33 version=%d err=%v", version, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_readiness($1,$2)`, attackPath.Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&attackPathReady); err != nil || !attackPathReady {
		t.Fatalf("restored v33 readiness=%t err=%v", attackPathReady, err)
	}
	if err := runner.UpProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 re-up: %v", err)
	}
}

func TestV6ReceiptlessPATReplayUsesDurableMarkerAndBlocksEveryRollbackWithoutPartialMigration(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		t.Fatalf("empty to v27: %v", err)
	}
	if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 to v33 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 to v32 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentPlanner(ctx); err != nil {
		t.Fatalf("v32 to v31 fixture: %v", err)
	}
	if err := runner.DownProductionWorkflowCompatibility(ctx); err != nil {
		t.Fatalf("v31 to v30 fixture: %v", err)
	}
	if err := runner.DownProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 to v29 fixture: %v", err)
	}
	if err := runner.DownProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 to v28 fixture: %v", err)
	}
	if err := runner.DownProductionPolicyDeployment(ctx); err != nil {
		t.Fatalf("v28 to v27 fixture: %v", err)
	}
	if err := runner.DownProductionRecovery(ctx); err != nil {
		t.Fatalf("v27 to v26 fixture: %v", err)
	}
	if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
		t.Fatalf("v26 to v25 fixture: %v", err)
	}
	if err := runner.DownProductionRedTeamExecution(ctx); err != nil {
		t.Fatalf("v25 to v24 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err != nil {
		t.Fatalf("v24 to v23 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err != nil {
		t.Fatalf("v23 to v22 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
		t.Fatalf("v22 to v21 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21 to v20 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentControls(ctx); err != nil {
		t.Fatalf("v20 to v19 fixture: %v", err)
	}
	if err := runner.DownProductionIdentityAdministration(ctx); err != nil {
		t.Fatalf("v19 to v18 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatalf("v18 to v17 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("v17 to v16 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("v16 to v15 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 to v14 fixture: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("v14 to v13 fixture: %v", err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("v13 to v12 fixture: %v", err)
	}
	if err := runner.DownReferenceAuthorization(ctx); err != nil {
		t.Fatalf("v12 to v11 fixture: %v", err)
	}
	if err := runner.DownConnectorAuthorization(ctx); err != nil {
		t.Fatalf("v11 to v10 fixture: %v", err)
	}
	if err := runner.DownProductionDiscovery(ctx); err != nil {
		t.Fatalf("v10 to v9 fixture: %v", err)
	}
	if err := runner.DownProductionRiskProjection(ctx); err != nil {
		t.Fatalf("v9 to v8 fixture: %v", err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("v8 to v7 fixture: %v", err)
	}
	if err := runner.DownProductionAdministration(ctx); err != nil {
		t.Fatalf("v7 to v6 fixture: %v", err)
	}
	organization := "pid_71000001-0000-4000-8000-000000000001"
	workspace := "pid_71000002-0000-4000-8000-000000000002"
	environment := "pid_71000003-0000-4000-8000-000000000003"
	principal := "pid_71000004-0000-4000-8000-000000000004"
	createReplay := func(id, key, auditID, correlationID string, receiptID any) string {
		t.Helper()
		body := fmt.Sprintf(`{"id":%q,"name":"Rollback replay","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`, id)
		intent := fmt.Sprintf(`{"body":%s,"expected_version":0,"resource_id":""}`, body)
		if _, err := connection.Exec(ctx, `SELECT public.zasp_workflow_mutate(
			'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`,
			id, organization, workspace, environment, principal, key, intent, body, auditID, correlationID, receiptID); err != nil {
			t.Fatalf("create replay %s: %v", key, err)
		}
		return intent
	}
	const patID = "policy-rollback-pat"
	const patKey = "idem-rollback-pat-0001"
	createReplay(patID, patKey, "pid_72000001-0000-4000-8000-000000000001", "pid_72000002-0000-4000-8000-000000000002", nil)
	const browserKey = "idem-rollback-browser-0001"
	const browserReceiptID = "pid_72000003-0000-4000-8000-000000000003"
	browserIntent := createReplay("policy-rollback-browser", browserKey, "pid_72000004-0000-4000-8000-000000000004", "pid_72000005-0000-4000-8000-000000000005", browserReceiptID)

	type rollbackSnapshot struct {
		Version             int64
		VersionRows         int
		ProvenanceChecksum  string
		Release             string
		Fingerprint         string
		MutationFunction    string
		IdempotencyRowCount int
		IncompatibleCount   int
	}
	snapshot := func() rollbackSnapshot {
		t.Helper()
		value := rollbackSnapshot{}
		value.Version, err = runner.Version(ctx)
		if err != nil {
			t.Fatalf("snapshot version: %v", err)
		}
		if err := connection.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM zasp_schema_versions),
			(SELECT checksum FROM zasp_schema_versions WHERE version=6),
			(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema'),
			(SELECT value FROM zasp_schema_metadata WHERE key='production_workflow_receipt_provenance_fingerprint'),
			pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure),
			(SELECT count(*) FROM zasp_workflow_idempotency),
			(SELECT count(*) FROM zasp_workflow_idempotency WHERE receipt_semantics='receiptless_incompatible')`).Scan(
			&value.VersionRows, &value.ProvenanceChecksum, &value.Release, &value.Fingerprint, &value.MutationFunction, &value.IdempotencyRowCount, &value.IncompatibleCount); err != nil {
			t.Fatalf("snapshot state: %v", err)
		}
		return value
	}
	before := snapshot()
	if before.Version != 6 || before.VersionRows != 6 || before.Release != "production-workflow-receipt-provenance-v3" || before.IdempotencyRowCount != 2 || before.IncompatibleCount != 1 {
		t.Fatalf("initial v6 snapshot = %#v", before)
	}
	for _, rollback := range []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "DownCore", run: runner.DownCore},
		{name: "Down", run: runner.Down},
	} {
		if err := rollback.run(ctx); !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatalf("%s v6 precondition = %v", rollback.name, err)
		}
		if after := snapshot(); after != before {
			t.Fatalf("%s changed v6 state: before=%#v after=%#v", rollback.name, before, after)
		}
	}
	for _, rollback := range []struct {
		name string
		run  func() error
	}{
		{name: "DownWorkflowReceiptProvenance", run: func() error { return runner.DownWorkflowReceiptProvenance(ctx) }},
		{name: "release down", run: func() error { return runReleaseMigration(ctx, runner, []string{"down"}) }},
	} {
		err := rollback.run()
		if !errors.Is(err, migrations.ErrDatabase) || err.Error() != migrations.ErrDatabase.Error() {
			t.Fatalf("%s unsanitized error = %v", rollback.name, err)
		}
		if after := snapshot(); after != before {
			t.Fatalf("%s partially changed v6 state: before=%#v after=%#v", rollback.name, before, after)
		}
	}
	command := exec.CommandContext(ctx, "go", "run", ".", "down")
	command.Env = append(os.Environ(), "ZASP_POSTGRES_DSN="+dsn, "ZASP_MIGRATION_TIMEOUT=10s")
	output, commandErr := command.CombinedOutput()
	if commandErr == nil || !strings.Contains(string(output), "release migration failed") || strings.Contains(string(output), "workflow receipt safety rollback blocked") || strings.Contains(string(output), patKey) {
		t.Fatalf("migrator CLI error = %v output=%q", commandErr, output)
	}
	if after := snapshot(); after != before {
		t.Fatalf("migrator CLI partially changed v6 state: before=%#v after=%#v", before, after)
	}

	cleanup, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, deletion := range []struct {
		name      string
		statement string
		args      []any
	}{
		{name: "idempotency", statement: `DELETE FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$4 AND operation='createPolicy' AND idempotency_key=$5`, args: []any{organization, workspace, environment, principal, patKey}},
		{name: "audit", statement: `DELETE FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, args: []any{organization, "pid_72000001-0000-4000-8000-000000000001"}},
		{name: "record", statement: `DELETE FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='policy' AND id=$4`, args: []any{organization, workspace, environment, patID}},
	} {
		result, err := cleanup.Exec(ctx, deletion.statement, deletion.args...)
		if err != nil || result.RowsAffected() != 1 {
			_ = cleanup.Rollback(ctx)
			t.Fatalf("exact %s cleanup = rows %d error %v", deletion.name, result.RowsAffected(), err)
		}
	}
	if err := cleanup.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("clean v6 to v5: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 5 {
		t.Fatalf("intermediate rollback target = (%d, %v)", version, err)
	}
	blocked := concurrentPATMutation("intermediate-v5", "pid_72000006-0000-4000-8000-000000000006", "pid_72000007-0000-4000-8000-000000000007")
	var blockedPayload []byte
	if err := connection.QueryRow(ctx, concurrentPATMutationSQL, blocked.arguments()...).Scan(&blockedPayload); err == nil || !strings.Contains(err.Error(), "workflow mutations unavailable at intermediate receipt provenance downgrade") {
		t.Fatalf("intermediate v5 mutation = %v", err)
	}
	if err := runner.DownWorkflowReceiptSafety(ctx); err != nil {
		t.Fatalf("safe v5 to v4: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 4 {
		t.Fatalf("rollback target = (%d, %v)", version, err)
	}
	var replayJSON []byte
	if err := connection.QueryRow(ctx, `SELECT public.zasp_workflow_replay($1,$2,$3,$4,'createPolicy',$5,$6::jsonb)`, organization, workspace, environment, principal, browserKey, browserIntent).Scan(&replayJSON); err != nil {
		t.Fatal(err)
	}
	var replay struct {
		Found  bool `json:"found"`
		Result struct {
			Replayed  bool   `json:"replayed"`
			ReceiptID string `json:"receipt_id"`
		} `json:"result"`
	}
	if json.Unmarshal(replayJSON, &replay) != nil || !replay.Found || !replay.Result.Replayed || replay.Result.ReceiptID != browserReceiptID {
		t.Fatalf("v4 replay semantics = %s", replayJSON)
	}
	if err := runReleaseMigration(ctx, runner, []string{"down"}); err != nil {
		t.Fatalf("clean release down: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 0 {
		t.Fatalf("clean release target = (%d, %v)", version, err)
	}
}

func TestV6BackfillsConservativelyAndMarksMutationFromOlderTransaction(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	migrationConnection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = migrationConnection.Close(context.Background()) }()
	writer := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = writer.Close(context.Background()) }()
	runner := migrateToV5(t, ctx, migrationConnection)

	prePAT := concurrentPATMutation("pre-v6-pat", "pid_74000001-0000-4000-8000-000000000001", "pid_74000002-0000-4000-8000-000000000002")
	var payload []byte
	if err := migrationConnection.QueryRow(ctx, concurrentPATMutationSQL, prePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("pre-v6 PAT mutation: %v", err)
	}
	preBrowser := concurrentPATMutation("pre-v6-browser", "pid_74000003-0000-4000-8000-000000000003", "pid_74000004-0000-4000-8000-000000000004")
	browserArguments := append(preBrowser.arguments(), "pid_74000005-0000-4000-8000-000000000005")
	if err := migrationConnection.QueryRow(ctx, concurrentBrowserMutationSQL, browserArguments...).Scan(&payload); err != nil {
		t.Fatalf("pre-v6 browser mutation: %v", err)
	}

	writerTx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writerTx.Rollback(context.Background()) }()
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("v5 to v6 with older transaction: %v", err)
	}
	latePAT := concurrentPATMutation("older-transaction", "pid_74000006-0000-4000-8000-000000000006", "pid_74000007-0000-4000-8000-000000000007")
	if err := writerTx.QueryRow(ctx, concurrentPATMutationSQL, latePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("older transaction mutation after v6: %v", err)
	}
	if err := writerTx.QueryRow(ctx, concurrentPATMutationSQL, latePAT.arguments()...).Scan(&payload); err != nil {
		t.Fatalf("older transaction replay after v6: %v", err)
	}
	if err := writerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var prePATMarker, preBrowserMarker, latePATMarker string
	var latePredatesMigration bool
	if err := migrationConnection.QueryRow(ctx, `SELECT
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$1),
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$2),
		(SELECT receipt_semantics FROM zasp_workflow_idempotency WHERE idempotency_key=$3),
		(SELECT replay.created_at < marker.applied_at
		   FROM zasp_workflow_idempotency AS replay
		   JOIN zasp_schema_metadata AS marker ON marker.key='production_core_schema'
		  WHERE replay.idempotency_key=$3)`, prePAT.key, preBrowser.key, latePAT.key).Scan(
		&prePATMarker, &preBrowserMarker, &latePATMarker, &latePredatesMigration); err != nil {
		t.Fatal(err)
	}
	if prePATMarker != "receiptless_incompatible" || preBrowserMarker != "receipt_backed" || latePATMarker != "receiptless_incompatible" || !latePredatesMigration {
		t.Fatalf("provenance markers = prePAT %q browser %q latePAT %q predates=%t", prePATMarker, preBrowserMarker, latePATMarker, latePredatesMigration)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("older transaction provenance rollback = %v", err)
	}
}

func TestV6DownRejectsMarkerDriftBeforeAnyDDL(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer func() { _ = connection.Close(context.Background()) }()
	runner := migrateToV6(t, ctx, connection)
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_workflow_idempotency ALTER COLUMN receipt_semantics SET DEFAULT 'receipt_backed'`); err != nil {
		t.Fatal(err)
	}
	var functionBefore string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)`).Scan(&functionBefore); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownWorkflowReceiptProvenance(ctx); !errors.Is(err, migrations.ErrDatabase) || err.Error() != migrations.ErrDatabase.Error() {
		t.Fatalf("marker drift down error = %v", err)
	}
	var functionAfter, markerDefault, markerRelease string
	if err := connection.QueryRow(ctx, `SELECT
		pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure),
		pg_get_expr(default_value.adbin, default_value.adrelid, true),
		(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema')
	 FROM pg_attribute AS attribute
	 JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
	 WHERE attribute.attrelid='public.zasp_workflow_idempotency'::regclass AND attribute.attname='receipt_semantics'`).Scan(
		&functionAfter, &markerDefault, &markerRelease); err != nil {
		t.Fatal(err)
	}
	if functionAfter != functionBefore || markerDefault != "'receipt_backed'::text" || markerRelease != "production-workflow-receipt-provenance-v3" {
		t.Fatalf("partial marker drift down: function_changed=%t default=%q release=%q", functionAfter != functionBefore, markerDefault, markerRelease)
	}
	if version, err := runner.Version(ctx); err != nil || version != 6 {
		t.Fatalf("marker drift version = (%d, %v)", version, err)
	}
}

func TestV6RollbackSerializesConcurrentWorkflowMutations(t *testing.T) {
	t.Run("writer before down blocks rollback then rejects it", func(t *testing.T) {
		dsn := startMigrationPostgres(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		writer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = writer.Close(context.Background()) }()
		down := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = down.Close(context.Background()) }()
		observer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = observer.Close(context.Background()) }()
		runner := migrateToV6(t, ctx, down)

		writerTx, err := writer.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writerTx.Rollback(context.Background()) }()
		fixture := concurrentPATMutation("writer-first", "pid_73000001-0000-4000-8000-000000000001", "pid_73000002-0000-4000-8000-000000000002")
		if _, err := writerTx.Exec(ctx, concurrentPATMutationSQL, fixture.arguments()...); err != nil {
			t.Fatalf("writer mutation: %v", err)
		}
		downPID := postgresBackendPID(t, ctx, down)
		downDone := make(chan error, 1)
		go func() {
			downCtx, downCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer downCancel()
			downDone <- runner.DownWorkflowReceiptProvenance(downCtx)
		}()
		awaitPostgresLockWait(t, ctx, observer, downPID, downDone)

		if err := writerTx.Commit(ctx); err != nil {
			t.Fatalf("writer commit: %v", err)
		}
		if err := awaitMigrationResult(t, downDone); !errors.Is(err, migrations.ErrDatabase) {
			t.Fatalf("down after committed receipt-less writer = %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 6 {
			t.Fatalf("guarded concurrent rollback state = (%d, %v)", version, err)
		}
		assertConcurrentMutationCounts(t, ctx, observer, fixture, 1, 1, 1)
	})

	t.Run("down before queued old v6 writer commits v5 and writer aborts", func(t *testing.T) {
		dsn := startMigrationPostgres(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		barrier := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = barrier.Close(context.Background()) }()
		down := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = down.Close(context.Background()) }()
		writer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = writer.Close(context.Background()) }()
		observer := connectMigrationPostgres(t, ctx, dsn)
		defer func() { _ = observer.Close(context.Background()) }()
		runner := migrateToV6(t, ctx, down)

		barrierTx, err := barrier.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = barrierTx.Rollback(context.Background()) }()
		if _, err := barrierTx.Exec(ctx, `LOCK TABLE public.zasp_workflow_idempotency IN ROW EXCLUSIVE MODE`); err != nil {
			t.Fatalf("barrier lock: %v", err)
		}
		downPID := postgresBackendPID(t, ctx, down)
		downDone := make(chan error, 1)
		go func() {
			downCtx, downCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer downCancel()
			downDone <- runner.DownWorkflowReceiptProvenance(downCtx)
		}()
		awaitPostgresLockWait(t, ctx, observer, downPID, downDone)

		fixture := concurrentPATMutation("down-first", "pid_73000003-0000-4000-8000-000000000003", "pid_73000004-0000-4000-8000-000000000004")
		writerPID := postgresBackendPID(t, ctx, writer)
		writerDone := make(chan error, 1)
		go func() {
			writerCtx, writerCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer writerCancel()
			var payload []byte
			writerDone <- writer.QueryRow(writerCtx, concurrentPATMutationSQL, fixture.arguments()...).Scan(&payload)
		}()
		awaitPostgresLockWait(t, ctx, observer, writerPID, writerDone)

		if err := barrierTx.Commit(ctx); err != nil {
			t.Fatalf("barrier commit: %v", err)
		}
		if err := awaitMigrationResult(t, downDone); err != nil {
			t.Fatalf("down with queued old-v5 writer: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 5 {
			t.Fatalf("concurrent rollback target = (%d, %v)", version, err)
		}
		if err := awaitMigrationResult(t, writerDone); err == nil || !strings.Contains(err.Error(), "workflow receipt provenance release unavailable") {
			t.Fatalf("queued old-v6 writer after v5 = %v", err)
		}
		assertConcurrentMutationCounts(t, ctx, observer, fixture, 0, 0, 0)
	})
}

const concurrentPATMutationSQL = `SELECT public.zasp_workflow_mutate(
	'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,NULL)`

const concurrentBrowserMutationSQL = `SELECT public.zasp_workflow_mutate(
	'create','policy',$1,$2,$3,$4,$5,'createPolicy',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`

type concurrentMutationFixture struct {
	id            string
	organization  string
	workspace     string
	environment   string
	principal     string
	key           string
	intent        string
	body          string
	auditID       string
	correlationID string
}

func concurrentPATMutation(suffix, auditID, correlationID string) concurrentMutationFixture {
	id := "policy-concurrent-" + suffix
	body := fmt.Sprintf(`{"id":%q,"name":"Concurrent rollback","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`, id)
	return concurrentMutationFixture{
		id: id, organization: "pid_73000011-0000-4000-8000-000000000011", workspace: "pid_73000012-0000-4000-8000-000000000012",
		environment: "pid_73000013-0000-4000-8000-000000000013", principal: "pid_73000014-0000-4000-8000-000000000014",
		key: "idem-concurrent-" + suffix + "-0001", intent: fmt.Sprintf(`{"body":%s,"expected_version":0,"resource_id":""}`, body), body: body,
		auditID: auditID, correlationID: correlationID,
	}
}

func (fixture concurrentMutationFixture) arguments() []any {
	return []any{fixture.id, fixture.organization, fixture.workspace, fixture.environment, fixture.principal, fixture.key, fixture.intent, fixture.body, fixture.auditID, fixture.correlationID}
}

func connectMigrationPostgres(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func migrateToV6(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		t.Fatalf("migrate to v6: %v", err)
	}
	if err := runner.DownProductionRuntimeAcceptance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeCandidateAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionQuery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessionReads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeQueueReplay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionIntegrationSetup(ctx); err != nil {
		t.Fatalf("v34 to v33 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAttackPath(ctx); err != nil {
		t.Fatalf("v33 to v32 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentPlanner(ctx); err != nil {
		t.Fatalf("v32 to v31 fixture: %v", err)
	}
	if err := runner.DownProductionWorkflowCompatibility(ctx); err != nil {
		t.Fatalf("v31 to v30 fixture: %v", err)
	}
	if err := runner.DownProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 to v29 fixture: %v", err)
	}
	if err := runner.DownProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 to v28 fixture: %v", err)
	}
	if err := runner.DownProductionPolicyDeployment(ctx); err != nil {
		t.Fatalf("v28 to v27 fixture: %v", err)
	}
	if err := runner.DownProductionRecovery(ctx); err != nil {
		t.Fatalf("v27 to v26 fixture: %v", err)
	}
	if err := runner.DownProductionAttackLabExecution(ctx); err != nil {
		t.Fatalf("v26 to v25 fixture: %v", err)
	}
	if err := runner.DownProductionRedTeamExecution(ctx); err != nil {
		t.Fatalf("v25 to v24 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err != nil {
		t.Fatalf("v24 to v23 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err != nil {
		t.Fatalf("v23 to v22 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
		t.Fatalf("v22 to v21 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21 to v20 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentControls(ctx); err != nil {
		t.Fatalf("v20 to v19 fixture: %v", err)
	}
	if err := runner.DownProductionIdentityAdministration(ctx); err != nil {
		t.Fatalf("v19 to v18 fixture: %v", err)
	}
	if err := runner.DownProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatalf("v18 to v17 fixture: %v", err)
	}
	if err := runner.DownProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatalf("down runtime ingest reconciliation: %v", err)
	}
	if err := runner.DownProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatalf("down runtime gateway reconciliation: %v", err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("down runtime data plane: %v", err)
	}
	if err := runner.DownProductionTypedInventoryCutover(ctx); err != nil {
		t.Fatalf("down typed inventory cutover: %v", err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("down production discovery execution: %v", err)
	}
	if err := runner.DownReferenceAuthorization(ctx); err != nil {
		t.Fatalf("down reference authorization: %v", err)
	}
	if err := runner.DownConnectorAuthorization(ctx); err != nil {
		t.Fatalf("down connector authorization: %v", err)
	}
	if err := runner.DownProductionDiscovery(ctx); err != nil {
		t.Fatalf("down discovery: %v", err)
	}
	if err := runner.DownProductionRiskProjection(ctx); err != nil {
		t.Fatalf("down risk projection: %v", err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("migrate v8 to v7 fixture: %v", err)
	}
	if err := runner.DownProductionAdministration(ctx); err != nil {
		t.Fatalf("migrate v7 to v6 fixture: %v", err)
	}
	return runner
}

func migrateToV5(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "baseline", run: runner.Up}, {name: "core", run: runner.UpCore}, {name: "workflows", run: runner.UpWorkflows},
		{name: "receipts", run: runner.UpWorkflowReceipts}, {name: "safety", run: runner.UpWorkflowReceiptSafety},
	} {
		if err := migration.run(ctx); err != nil {
			t.Fatalf("migrate %s to v5: %v", migration.name, err)
		}
	}
	return runner
}

func postgresBackendPID(t *testing.T, ctx context.Context, connection *pgx.Conn) int32 {
	t.Helper()
	var pid int32
	if err := connection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func awaitPostgresLockWait(t *testing.T, ctx context.Context, observer *pgx.Conn, pid int32, completed <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-completed:
			t.Fatalf("operation completed before required lock wait: %v", err)
		default:
		}
		var waiting bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type = 'Lock', false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatalf("observe lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d did not enter a bounded lock wait", pid)
}

func awaitMigrationResult(t *testing.T, completed <-chan error) error {
	t.Helper()
	select {
	case err := <-completed:
		return err
	case <-time.After(6 * time.Second):
		t.Fatal("concurrent migration operation exceeded bounded wait")
		return nil
	}
}

func assertConcurrentMutationCounts(t *testing.T, ctx context.Context, connection *pgx.Conn, fixture concurrentMutationFixture, records, audits, idempotency int) {
	t.Helper()
	var gotRecords, gotAudits, gotIdempotency int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='policy' AND id=$4),
		(SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$5),
		(SELECT count(*) FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$6 AND operation='createPolicy' AND idempotency_key=$7)`,
		fixture.organization, fixture.workspace, fixture.environment, fixture.id, fixture.auditID, fixture.principal, fixture.key).Scan(&gotRecords, &gotAudits, &gotIdempotency); err != nil {
		t.Fatalf("mutation counts: %v", err)
	}
	if gotRecords != records || gotAudits != audits || gotIdempotency != idempotency {
		t.Fatalf("mutation counts = (%d,%d,%d), want (%d,%d,%d)", gotRecords, gotAudits, gotIdempotency, records, audits, idempotency)
	}
}

func startMigrationPostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	ready, readyErr := exec.LookPath("pg_isready")
	ctl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop := exec.Command(ctl, "-D", data, "-m", "fast", "-w", "stop")
		if stop.Run() != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if exec.Command(ready, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}
