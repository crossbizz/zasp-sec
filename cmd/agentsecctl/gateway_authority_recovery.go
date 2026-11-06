package main

import (
	"context"
	"io"
	"net/http"
	"time"

	custody "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentcustody"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

const gatewayCommandAuthorityPath = "/internal/v1/runtime-gateway/authority"

// Recovery authenticates a current credential read with the retained key. It
// cannot reconstruct the original enrollment receipt or confirm its outcome.
func runGatewayAuthorityRecovery(output io.Writer, store *custody.Store, client *http.Client, q gatewayCommandOptions) (operationErr error) {
	recovery, err := store.BeginRecovery()
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	defer func() {
		if recovery.Close() != nil && operationErr == nil {
			operationErr = errGatewayEnrollment
		}
	}()
	endpoint, snapshot, err := recovery.Source()
	if err != nil || !gatewayCommandEndpoint(endpoint) {
		return gatewayCommandUnresolved(output, store)
	}
	sentAt := gatewayEnrollmentNow()
	if !snapshot.Request.ExpiresAt.After(sentAt) {
		return gatewayCommandUnresolved(output, store)
	}
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+gatewayCommandAuthorityPath, nil)
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if wire.SignAuthorityRequest(request, snapshot.Request, recovery.Sign, sentAt) != nil {
		return gatewayCommandUnresolved(output, store)
	}
	response, err := client.Do(request)
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return gatewayCommandUnresolved(output, store)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaximumBytes+1))
	observedAt := gatewayEnrollmentNow()
	if err != nil || len(raw) > wire.MaximumBytes || ctx.Err() != nil {
		return gatewayCommandUnresolved(output, store)
	}
	authority, err := wire.ParseCurrentAuthority(raw)
	if err != nil || !wire.CurrentAuthorityMatchesRequest(authority, snapshot.Request, observedAt) || recovery.Observe(raw, sentAt, observedAt) != nil {
		return gatewayCommandUnresolved(output, store)
	}
	if ctx.Err() != nil {
		return gatewayCommandUnresolved(output, store)
	}
	state := "current_authority_observed"
	if q.credentialOutput != "" {
		if ctx.Err() != nil || recovery.ExportCredential(q.credentialOutput, gatewayEnrollmentNow()) != nil {
			return gatewayCommandUnresolved(output, store)
		}
		state = "credential_exported_from_current_authority"
	}
	if ctx.Err() != nil {
		return gatewayCommandUnresolved(output, store)
	}
	outcome := "unknown"
	if snapshot.State == custody.StateAccepted {
		outcome = "confirmed"
	}
	return writeGatewayReport(output, gatewayCommandReport{State: state, Outcome: outcome, DeviceID: snapshot.Request.DeviceID, CredentialID: snapshot.Request.CredentialID, Source: "current_authority", ObservedAt: observedAt.UTC().Format(time.RFC3339)})
}
