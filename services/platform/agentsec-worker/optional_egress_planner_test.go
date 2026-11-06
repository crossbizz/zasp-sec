package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Exercise both actual HTTP boundaries: current Temporal ordered transport
// and the retained raw/legacy prepared-plan interface.
func TestOptionalEgressPlannerActualSendBoundary(t *testing.T) {
	t.Run("raw-prepared-dispatch", func(t *testing.T) {
		transport := bindingResponseTransport()
		planner := requestBindingPlanner(t, transport)
		planner.optionalEgressEnabled = true
		planner.optionalEgressProfile = migrations.OptionalEgressProfileChecksum()
		prepared, err := planner.Prepare(context.Background(), testSecurityAgentPlannerContext())
		if err != nil {
			t.Fatal(err)
		}
		if result := prepared.Dispatch(context.Background()); result.Failure == "" || transport.calls != 0 {
			t.Fatal("enabled optional egress sent without current typed planner admission")
		}
	})
	t.Run("ordered-temporal-transport", func(t *testing.T) {
		transport := orderedBindingResponseTransport()
		planner := orderedRequestBindingPlanner(t, transport)
		planner.optionalEgressEnabled = true
		planner.optionalEgressProfile = migrations.OptionalEgressProfileChecksum()
		prepared, err := orderedPreparedPlanFixture(context.Background(), planner, orderedContextFixture().Context)
		if err != nil {
			t.Fatal(err)
		}
		credential, ok := orderedPreparedCredential(prepared)
		if !ok {
			t.Fatal("original credential binding unavailable")
		}
		if raw, err := sendSecurityAgentOrdered(context.Background(), prepared, credential); err == nil || len(raw) != 0 || transport.calls != 0 {
			t.Fatal("enabled optional egress bypassed admission at actual ordered HTTP boundary")
		}
	})
}

type optionalPlannerAuthorizerStub struct {
	calls      int
	operation  authorization.WorkerOperation
	request    json.RawMessage
	profilePin string
	err        error
}

type optionalPlanningDatabaseStub struct {
	authorizer *optionalPlannerAuthorizerStub
	family     workerPlanningFamily
	transport  *securityAgentPlannerTransport
	t          *testing.T
}

func (d *optionalPlanningDatabaseStub) AdmitOptionalPlannerDispatch(ctx context.Context, raw json.RawMessage, profilePin string) error {
	if d.transport.calls != 0 {
		d.t.Fatal("HTTP preceded current optional admission")
	}
	return admitBoundOptionalPlannerDispatch(ctx, d.authorizer, workerPlanningStartFixture(), d.family, raw, profilePin)
}

func (a *optionalPlannerAuthorizerStub) AdmitOptionalPlannerDispatch(_ context.Context, operation authorization.WorkerOperation, raw json.RawMessage, profilePin string) error {
	a.calls++
	a.operation, a.request = operation, bytes.Clone(raw)
	a.profilePin = profilePin
	return a.err
}

func optionalPlannerStartRequest(t *testing.T) json.RawMessage {
	t.Helper()
	q := temporalStartFields(workerPlanningStartFixture())
	delete(q, "input_digest")
	q["operation"], q["payload"] = "start", map[string]any{}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOptionalEgressPlannerTypedDispatchAndNoResend(t *testing.T) {
	for _, c := range []struct {
		name   string
		family workerPlanningFamily
		op     authorization.WorkerOperation
	}{{"ordered68", workerPlanningOrdered68, "ordered68.planning.start"}, {"test74", workerPlanningTest74, "test74.planning.start"}, {"finding78", workerPlanningFinding, "finding.planning.start"}} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			transport := orderedBindingResponseTransport()
			planner := orderedRequestBindingPlanner(t, transport)
			if configureOptionalPlannerEgress(planner, true, migrations.OptionalEgressAuditProfileChecksum()) != nil {
				t.Fatal("mode binding refused")
			}
			prepared, err := orderedPreparedPlanFixture(context.Background(), planner, orderedContextFixture().Context)
			if err != nil {
				t.Fatal(err)
			}
			credential, _ := orderedPreparedCredential(prepared)
			authorizer := &optionalPlannerAuthorizerStub{}
			original := optionalPlannerStartRequest(t)
			identity := temporalStartFields(workerPlanningStartFixture())
			delete(identity, "input_digest")
			admission := optionalTemporalPlannerAdmission(&optionalPlanningDatabaseStub{authorizer: authorizer, family: c.family, transport: transport, t: t}, identity, migrations.OptionalEgressAuditProfileChecksum())
			identity["organization_id"] = "changed-after-binding"
			if raw, err := sendSecurityAgentOrderedWithAdmission(ctx, prepared, credential, admission); err != nil || len(raw) == 0 || transport.calls != 1 || authorizer.calls != 1 || authorizer.operation != c.op || !bytes.Equal(authorizer.request, original) || authorizer.profilePin != migrations.OptionalEgressAuditProfileChecksum() {
				t.Fatal("typed current admission did not bind one actual send")
			}
			if _, err := sendSecurityAgentOrderedWithAdmission(ctx, prepared, credential, admission); err == nil || transport.calls != 1 || authorizer.calls != 1 {
				t.Fatal("consumed provider permit reacquired admission or resent")
			}
		})
	}
}

func TestOptionalEgressPlannerDisableRevocationAndUncertainty(t *testing.T) {
	for _, mode := range []string{"disabled-after-prepare", "revoked", "dependency-error", "unknown-commit", "cancel-before", "cancel-after-admission", "missing-adapter", "insufficient-headroom", "unbounded-context"} {
		t.Run(mode, func(t *testing.T) {
			transport := orderedBindingResponseTransport()
			planner := orderedRequestBindingPlanner(t, transport)
			if configureOptionalPlannerEgress(planner, true, migrations.OptionalEgressProfileChecksum()) != nil {
				t.Fatal("mode binding refused")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "insufficient-headroom" {
				bounded, stop := context.WithTimeout(ctx, 5*time.Second)
				defer stop()
				ctx = bounded
			}
			prepared, err := orderedPreparedPlanFixture(ctx, planner, orderedContextFixture().Context)
			if err != nil {
				t.Fatal(err)
			}
			credential, _ := orderedPreparedCredential(prepared)
			calls := 0
			var admission optionalPlannerDispatchAdmission = func(context.Context) error {
				calls++
				switch mode {
				case "disabled-after-prepare", "revoked":
					return authorization.ErrDenied
				case "dependency-error", "unknown-commit":
					return authorization.ErrUnavailable
				case "cancel-after-admission":
					cancel()
				}
				return nil
			}
			if mode == "cancel-before" {
				cancel()
			}
			if mode == "missing-adapter" {
				admission = optionalTemporalPlannerAdmission(struct{}{}, map[string]any{}, migrations.OptionalEgressProfileChecksum())
			}
			if _, err := sendSecurityAgentOrderedWithAdmission(ctx, prepared, credential, admission); err == nil || transport.calls != 0 {
				t.Fatal("refused or uncertain optional admission reached actual HTTP")
			}
			before := calls
			if _, err := sendSecurityAgentOrderedWithAdmission(ctx, prepared, credential, admission); err == nil || transport.calls != 0 || calls != before {
				t.Fatal("refused or uncertain admission retried a consumed permit")
			}
		})
	}
}

func TestOptionalEgressPlannerScopeAndPhaseBinding(t *testing.T) {
	valid := optionalPlannerStartRequest(t)
	for _, key := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "operation", "payload", "unknown"} {
		var q map[string]any
		if json.Unmarshal(valid, &q) != nil {
			t.Fatal("request fixture malformed")
		}
		q[key] = "foreign"
		raw, _ := json.Marshal(q)
		a := &optionalPlannerAuthorizerStub{}
		if admitBoundOptionalPlannerDispatch(context.Background(), a, workerPlanningStartFixture(), workerPlanningFinding, raw, migrations.OptionalEgressProfileChecksum()) == nil || a.calls != 0 {
			t.Fatal("changed scope, phase, payload or field reached the proof issuer")
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`{`), append(bytes.TrimSuffix(bytes.Clone(valid), []byte("}")), []byte(`,"operation":"start"}`)...)} {
		a := &optionalPlannerAuthorizerStub{}
		if admitBoundOptionalPlannerDispatch(context.Background(), a, workerPlanningStartFixture(), workerPlanningFinding, raw, migrations.OptionalEgressProfileChecksum()) == nil || a.calls != 0 {
			t.Fatal("malformed or duplicate input reached the proof issuer")
		}
	}
	a := &optionalPlannerAuthorizerStub{}
	if admitBoundOptionalPlannerDispatch(context.Background(), a, workerPlanningStartFixture(), workerPlanningFamily(99), valid, migrations.OptionalEgressProfileChecksum()) == nil || a.calls != 0 {
		t.Fatal("unknown family reached the proof issuer")
	}
	a.err = authorization.ErrDenied
	if !errors.Is(admitBoundOptionalPlannerDispatch(context.Background(), a, workerPlanningStartFixture(), workerPlanningFinding, valid, migrations.OptionalEgressProfileChecksum()), authorization.ErrDenied) || a.calls != 1 {
		t.Fatal("current permission refusal was hidden")
	}
	for _, pin := range []string{"", "unknown", "0000000000000000000000000000000000000000000000000000000000000000"} {
		a := &optionalPlannerAuthorizerStub{}
		if admitBoundOptionalPlannerDispatch(context.Background(), a, workerPlanningStartFixture(), workerPlanningFinding, valid, pin) == nil || a.calls != 0 {
			t.Fatal("uncompiled profile reached the proof issuer")
		}
	}
	for _, digest := range []string{"", "changed-input"} {
		start := workerPlanningStartFixture()
		start.InputDigest = digest
		a := &optionalPlannerAuthorizerStub{}
		if admitBoundOptionalPlannerDispatch(context.Background(), a, start, workerPlanningFinding, valid, migrations.OptionalEgressProfileChecksum()) == nil || a.calls != 0 {
			t.Fatal("malformed typed start reached the proof issuer")
		}
	}
}

func TestOptionalEgressPlannerFlagAndLegacyCompatibility(t *testing.T) {
	for _, value := range []string{"", "false", "true", "1", "TRUE", " false", "enabled"} {
		enabled, err := optionalPlannerEgressFlag(value)
		if value == "" || value == "false" || value == "true" {
			if err != nil || enabled != (value == "true") {
				t.Fatal("explicit compatibility or enabled mode refused")
			}
		} else if err == nil {
			t.Fatal("malformed optional egress mode silently selected")
		}
	}
	for _, pin := range []string{migrations.OptionalEgressProfileChecksum(), migrations.OptionalEgressAuditProfileChecksum()} {
		if !validOptionalPlannerEgressProfile(true, pin) || validOptionalPlannerEgressProfile(false, pin) {
			t.Fatal("explicit profile mode selection changed")
		}
	}
	if validOptionalPlannerEgressProfile(true, "") || validOptionalPlannerEgressProfile(true, "unknown") || !validOptionalPlannerEgressProfile(false, "") {
		t.Fatal("missing/unknown profile accepted or compatibility mode refused")
	}
	base := map[string]string{
		"ZASP_WORKER_MODE": "scheduler", "ZASP_POSTGRES_DSN": "postgres://scheduler@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_discovery_scheduler", "ZASP_WORKER_ID": "scheduler-01", "ZASP_POLL_INTERVAL": "250ms",
		"ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_DISCOVERY_PARSER_VERSION": "inventory-parser-2026.08.20", "ZASP_DISCOVERY_TOOL_VERSION": "collector-tool-2026.08.20",
		"ZASP_OPTIONAL_EGRESS_ENABLED": "true", "ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM": migrations.OptionalEgressAuditProfileChecksum(),
	}
	if config, err := loadWorkerRuntimeConfig(mapLookup(base)); err != nil || !config.OptionalEgressEnabled || config.OptionalEgressProfileChecksum != migrations.OptionalEgressAuditProfileChecksum() {
		t.Fatal("runtime loader lost the explicit optional profile")
	}
	for _, mode := range []string{"missing-pin", "disabled-with-pin", "malformed-flag"} {
		values := cloneStringMap(base)
		switch mode {
		case "missing-pin":
			delete(values, "ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM")
		case "disabled-with-pin":
			values["ZASP_OPTIONAL_EGRESS_ENABLED"] = "false"
		case "malformed-flag":
			values["ZASP_OPTIONAL_EGRESS_ENABLED"] = "TRUE"
		}
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err == nil {
			t.Fatal("invalid runtime mode silently fell back")
		}
	}
	transport := bindingResponseTransport()
	planner := requestBindingPlanner(t, transport)
	prepared, err := planner.Prepare(context.Background(), testSecurityAgentPlannerContext())
	if err != nil {
		t.Fatal(err)
	}
	if result := prepared.Dispatch(context.Background()); result.Failure != "" || transport.calls != 1 {
		t.Fatal("default compatibility mode changed original prepared dispatch")
	}
	transport = orderedBindingResponseTransport()
	planner = orderedRequestBindingPlanner(t, transport)
	ordered, err := orderedPreparedPlanFixture(context.Background(), planner, orderedContextFixture().Context)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := orderedPreparedCredential(ordered)
	if _, err := sendSecurityAgentOrderedWithAdmission(context.Background(), ordered, credential, func(context.Context) error {
		t.Fatal("compatibility mode unexpectedly contacted optional authority")
		return nil
	}); err != nil || transport.calls != 1 {
		t.Fatal("default compatibility mode changed original ordered dispatch")
	}
}
