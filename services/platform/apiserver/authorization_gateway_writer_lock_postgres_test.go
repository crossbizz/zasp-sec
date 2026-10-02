package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A row-capture trigger cannot establish organization-before-device ordering:
// the native writer must wait before taking its advisory lock or changing replay.
// This runs against registered gateway authority, not an owner-issued mutation.
func TestP7GatewayWriterOrganizationSerialization(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, _ string) {
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN;CREATE ROLE worker_test_compensation LOGIN;SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation')`); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		gateway, _, _, event := seedAutomaticRuntimeGateway(t, ctx, owner, o, w, e)
		apiConfig := owner.Config().Copy()
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&apiConfig.User); err != nil {
			t.Fatal("registered discovery API login", err)
		}
		api, err := pgx.ConnectConfig(ctx, apiConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		for _, writer := range []string{"api-create", "api-transition"} {
			t.Run(writer, func(t *testing.T) {
				assertGatewayReplayWaitsForOrganization(t, ctx, owner, api, o, w, e, event.CredentialID, event.DeviceID, writer, "unchanged")
			})
		}
		for _, writer := range []string{"api-issue", "api-revoke"} {
			t.Run(writer, func(t *testing.T) {
				changes := []string{"unchanged"}
				if writer == "api-issue" {
					changes = append(changes, "expired")
				}
				for _, change := range changes {
					t.Run(change, func(t *testing.T) {
						assertGatewayReplayWaitsForOrganization(t, ctx, owner, api, o, w, e, event.CredentialID, event.DeviceID, writer, change)
					})
				}
			})
		}
		for _, writer := range []string{"replay", "event", "event-v27", "enrollment"} {
			t.Run(writer, func(t *testing.T) {
				changes := []string{"unchanged", "revoked", "expired"}
				if writer == "enrollment" {
					changes = append(changes, "principal-revoked")
				}
				for _, change := range changes {
					t.Run(change, func(t *testing.T) {
						assertGatewayReplayWaitsForOrganization(t, ctx, owner, gateway, o, w, e, event.CredentialID, event.DeviceID, writer, change)
					})
				}
			})
		}
		// A separate device-lock holder can outlive credentials even after the
		// organization lock was acquired. Admission must remain fresh at use.
		for _, writer := range []string{"replay", "event", "event-v27", "enrollment"} {
			t.Run("device-wait-"+writer, func(t *testing.T) {
				changes := []string{"unchanged", "expired"}
				if writer == "enrollment" {
					changes = append(changes, "principal-revoked")
				}
				for _, change := range changes {
					t.Run(change, func(t *testing.T) {
						assertGatewayReplayWaitsForOrganization(t, ctx, owner, gateway, o, w, e, event.CredentialID, event.DeviceID, writer, change, "device")
					})
				}
			})
		}
		for _, writer := range []string{"api-create", "api-transition", "api-issue", "api-revoke"} {
			t.Run("secondary-wait-"+writer, func(t *testing.T) {
				wait := "device"
				if writer == "api-transition" {
					wait = "row"
				}
				for _, change := range []string{"unchanged", "principal-revoked"} {
					t.Run(change, func(t *testing.T) {
						assertGatewayReplayWaitsForOrganization(t, ctx, owner, api, o, w, e, event.CredentialID, event.DeviceID, writer, change, wait)
					})
				}
			})
		}
	})
}

func assertGatewayReplayWaitsForOrganization(t *testing.T, ctx context.Context, owner, gateway *pgx.Conn, o, w, e, credential, device, writer, change string, secondaryWait ...string) {
	t.Helper()
	deviceWait := len(secondaryWait) == 1 && secondaryWait[0] == "device"
	rowWait := len(secondaryWait) == 1 && secondaryWait[0] == "row"
	lockKind := "organization"
	if deviceWait {
		lockKind = "device advisory"
	} else if rowWait {
		lockKind = "device row"
	}
	bindingTable, bindingRole := "zasp_runtime_principal_bindings", "zasp_gateway_control"
	if strings.HasPrefix(writer, "api-") {
		bindingTable, bindingRole = "zasp_discovery_principal_bindings", "zasp_discovery_api"
	}
	query := `SELECT public.zasp_runtime_gateway_advance_replay($1,0,1,decode(repeat('42',32),'hex'))`
	args := []any{credential}
	authorityTable, authorityID := "zasp_gateway_credentials", credential
	var issuanceExpiry time.Time
	if writer == "api-issue" {
		issuanceExpiry = time.Now().UTC().Add(time.Hour)
		if change == "expired" {
			issuanceExpiry = time.Now().UTC().Add(time.Second)
		}
		query, args = `SELECT public.zasp_runtime_issue_gateway_enrollment($1,$2,$3,$4,$5,2,1,decode(repeat('81',32),'hex'),decode(repeat('82',32),'hex'),decode(repeat('83',32),'hex'),$6)`, []any{o, w, e, automaticSourceID(47), device, issuanceExpiry}
	}
	if writer == "api-revoke" {
		query, args = `SELECT public.zasp_runtime_revoke_gateway_enrollment($1,$2,$3,$4,$5)`, []any{o, w, e, device, automaticSourceID(41)}
	}
	if writer == "api-create" {
		// A new device must serialize before its first advisory lock. The
		// transaction is rolled back, so it must not leave a device row.
		device = automaticSourceID(46)
		query, args = `SELECT public.zasp_discovery_create_gateway_device($1,$2,$3,$4,'Organization wait device')`, []any{o, w, e, device}
	}
	if writer == "api-transition" {
		query, args = `SELECT public.zasp_discovery_transition_gateway_device($1,$2,$3,$4,1,'revoked')`, []any{o, w, e, device}
	}
	if writer == "event" || writer == "event-v27" {
		// Build a valid native event input so an unrelated digest rejection cannot
		// masquerade as authorization serialization. This is not a digest test.
		function, policyDoc, policyArg := "zasp_runtime_gateway_record_event", "", ""
		if writer == "event-v27" {
			function, policyDoc, policyArg = "zasp_runtime_gateway_record_event_v27", ",'policy_ids','[]'::jsonb", ",'[]'::jsonb"
		}
		classification := `'{"category":"runtime","route_class":"local","resource_class":"tool","outcome":"requested"}'::jsonb`
		query = `SELECT public.` + function + `($1::text,$3::text,0,1,digest(convert_to(jsonb_build_object('credential_id',$1::text,'device_id',$2::text,'event_id',$3::text,'expected_floor',0,'next_floor',1,'policy_version',1,'decision','monitor','action_kind','http','classification',` + classification + policyDoc + `,'occurred_at',to_char($4::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256'),1,'monitor','http',` + classification + policyArg + `,$4::timestamptz)`
		args = []any{credential, device, automaticSourceID(43), time.Now().UTC().Truncate(time.Second)}
	}
	if writer == "enrollment" {
		authorityTable, authorityID = "zasp_gateway_enrollment_tokens", automaticSourceID(41)
		locator, secret := bytes.Repeat([]byte{0x71}, 16), bytes.Repeat([]byte{0x72}, 32)
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_enrollment_tokens SET locator_digest=digest($1::bytea,'sha256'),token_hash=zasp_runtime_gateway_enrollment_secret_hash(audience,id,token_generation,salt,$2::bytea) WHERE id=$3`, locator, secret, authorityID); err != nil {
			t.Fatal("owned enrollment credential", err)
		}
		query, args = `SELECT public.zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`, []any{locator, secret}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if change == "principal-revoked" {
			if _, err := owner.Exec(cleanup, `UPDATE `+pgx.Identifier{bindingTable}.Sanitize()+` SET principal_name=$1 WHERE authority_role=$2`, gateway.Config().User, bindingRole); err != nil {
				t.Error("restore exact gateway login binding", err)
			}
		}
		if _, err := owner.Exec(cleanup, `UPDATE `+pgx.Identifier{authorityTable}.Sanitize()+` SET revoked_at=NULL,expires_at=date_trunc('second',clock_timestamp())+interval '1 hour' WHERE id=$1`, authorityID); err != nil {
			t.Error("restore owned gateway fixture", err)
		}
	}()
	var deviceExpiry time.Time
	if deviceWait && change == "expired" {
		// Change the fixture before the contender owns the organization row.
		// Expiry then happens naturally while it waits, without an owner update
		// trying to reverse the production organization/device lock order.
		if err := owner.QueryRow(ctx, `UPDATE `+pgx.Identifier{authorityTable}.Sanitize()+` SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING expires_at`, authorityID).Scan(&deviceExpiry); err != nil {
			t.Fatal("set secondary-wait credential lifetime", err)
		}
	}
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if deviceWait {
		if _, err := lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text),0))`, o, w, e, device); err != nil {
			t.Fatal("owned secondary device lock", err)
		}
	} else if rowWait {
		var retained string
		if err := lock.QueryRow(ctx, `SELECT state FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 FOR UPDATE`, o, w, e, device).Scan(&retained); err != nil || retained != "active" {
			t.Fatal("owned secondary device row", retained, err)
		}
	} else {
		var organization string
		if err := lock.QueryRow(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, o).Scan(&organization); err != nil {
			t.Fatal("owned organization lock", err)
		}
	}
	operation, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tx, err := gateway.Begin(operation)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback(context.Background())
		var result json.RawMessage
		err = tx.QueryRow(operation, query, args...).Scan(&result)
		// Always roll back the native writer, including the intentionally unsafe
		// predecessor result. No replay-floor change escapes this test.
		if rollbackErr := tx.Rollback(context.Background()); err == nil {
			err = rollbackErr
		}
		done <- err
	}()
	joined := false
	defer func() {
		cancel()
		_ = lock.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	blocked := false
	for !blocked && time.Now().Before(deadline) {
		select {
		case err := <-done:
			joined = true
			t.Fatalf("registered writer completed before %s lock release: %v", lockKind, err)
		default:
		}
		if err := lock.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, owner.PgConn().PID(), gateway.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal("observe actual "+lockKind+" wait", err)
		}
		if !blocked {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("registered writer did not wait on the owned " + lockKind + " lock")
	}
	if !deviceWait && !rowWait {
		var deviceLockFree bool
		if err := lock.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text),0))`, o, w, e, device).Scan(&deviceLockFree); err != nil || !deviceLockFree {
			t.Fatal("writer took device advisory before organization authority", deviceLockFree, err)
		}
	}
	if writer == "api-transition" {
		var retained string
		if err := lock.QueryRow(ctx, `SELECT state FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 FOR UPDATE NOWAIT`, o, w, e, device).Scan(&retained); err != nil || retained != "active" {
			t.Fatal("transition took device row before organization authority", retained, err)
		}
	}
	if change == "revoked" {
		if _, err := lock.Exec(ctx, `UPDATE `+pgx.Identifier{authorityTable}.Sanitize()+` SET revoked_at=clock_timestamp() WHERE id=$1`, authorityID); err != nil {
			t.Fatal(err)
		}
	}
	if change == "principal-revoked" {
		// Retain the function grant and socket while removing the login's actual
		// registration. Its already-started native call must recheck after wait.
		if tag, err := lock.Exec(ctx, `UPDATE `+pgx.Identifier{bindingTable}.Sanitize()+` SET principal_name='revoked_gateway_login' WHERE authority_role=$2 AND principal_name=$1`, gateway.Config().User, bindingRole); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("revoke exact gateway login registration", err)
		}
	}
	if change == "expired" && deviceWait {
		if remaining := time.Until(deviceExpiry) + 20*time.Millisecond; remaining > 0 {
			time.Sleep(remaining)
		}
	} else if change == "expired" && writer == "api-issue" {
		// Keep the real organization lock until the requested lifetime elapses.
		// transaction_timestamp remains before expiry in the waiting writer.
		if remaining := time.Until(issuanceExpiry) + 20*time.Millisecond; remaining > 0 {
			time.Sleep(remaining)
		}
	} else if change == "expired" {
		// This expiry is after the contender's transaction start. A retained
		// transaction_timestamp check would still admit it after this wait.
		if _, err := lock.Exec(ctx, `UPDATE `+pgx.Identifier{authorityTable}.Sanitize()+` SET expires_at=clock_timestamp() WHERE id=$1`, authorityID); err != nil {
			t.Fatal(err)
		}
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	if change == "unchanged" && err != nil {
		t.Fatal("registered writer after "+lockKind+" release", err)
	}
	if change != "unchanged" {
		var native *pgconn.PgError
		code := "28000"
		if change == "principal-revoked" {
			code = "42501"
		} else if writer == "api-issue" {
			code = "22023"
		}
		if !errors.As(err, &native) || native.Code != code {
			t.Fatal("changed authority must refuse after actual "+lockKind+" wait", change, err)
		}
	}
	var floor int64
	if writer == "api-issue" || writer == "api-revoke" {
		var inserted, revoked int64
		if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE id=$4),count(*) FILTER(WHERE id=$5 AND revoked_at IS NOT NULL) FROM zasp_gateway_enrollment_tokens WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e, automaticSourceID(47), automaticSourceID(41)).Scan(&inserted, &revoked); err != nil || inserted != 0 || revoked != 0 {
			t.Fatal("rollback-only enrollment mutation", inserted, revoked, err)
		}
	}
	if writer == "api-create" {
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, o, w, e, device).Scan(&floor); err != nil || floor != 0 {
			t.Fatal("rollback-only device creation", floor, err)
		}
		return
	}
	if err := owner.QueryRow(ctx, `SELECT replay_floor FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, o, w, e, device).Scan(&floor); err != nil || floor != 0 {
		t.Fatal(fmt.Sprintf("rollback-only replay floor=%d", floor), err)
	}
	if writer == "api-transition" {
		var state string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT state,version FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, o, w, e, device).Scan(&state, &version); err != nil || state != "active" || version != 1 {
			t.Fatal("rollback-only device transition", state, version, err)
		}
	}
}
