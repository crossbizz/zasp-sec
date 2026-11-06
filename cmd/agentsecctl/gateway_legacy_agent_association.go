package main

import (
	"context"
	"io"
	"net/http"

	assoc "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	custody "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentcustody"
	enrollment "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

// A legacy credential supplies a key, not enrollment lineage or cached native
// identity. This invocation obtains current identity from the original API.
func runGatewayLegacyAgentAssociation(output io.Writer, q gatewayCommandOptions, envelope assoc.ChallengeEnvelope) (operationErr error) {
	report := gatewayAgentAssociationReport{State: "unresolved", Outcome: "unknown"}
	unresolved := func() error {
		if err := writeGatewayAgentAssociationReport(output, report); err != nil {
			return err
		}
		return errGatewayAgentAssociation
	}
	challenge, err := assoc.ChallengeFromEnvelope(envelope)
	if err != nil {
		return unresolved()
	}
	client, err := newGatewayEnrollmentHTTPClient(q)
	if err != nil {
		return unresolved()
	}
	defer client.CloseIdleConnections()
	// One operation deadline includes both HTTP exchanges and the intervening
	// durable preparation. A successful GET cannot reset the POST's deadline.
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()
	store, err := custody.OpenLegacyDevice(q.credentialFile, q.endpoint, q.associationStateFile)
	if err != nil {
		return unresolved()
	}
	defer func() {
		if store.Close() != nil && operationErr == nil {
			operationErr = errGatewayAgentAssociation
		}
	}()
	sentAt := gatewayEnrollmentNow()
	if !challenge.ExpiresAt.After(sentAt) || ctx.Err() != nil {
		return unresolved()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, q.endpoint+gatewayCommandAuthorityPath, nil)
	if err != nil {
		return unresolved()
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if store.SignAuthorityRequest(request, sentAt) != nil {
		return unresolved()
	}
	authority, err := readGatewayLegacyAuthority(ctx, client, request)
	observedAt := gatewayEnrollmentNow()
	if err != nil || ctx.Err() != nil || !authority.ExpiresAt.After(observedAt) || !challenge.ExpiresAt.After(observedAt) || request.Header.Get("Authorization") != "ZaspGatewayV1 "+authority.CredentialID || authority.OrganizationID != challenge.OrganizationID || authority.WorkspaceID != challenge.WorkspaceID || authority.EnvironmentID != challenge.EnvironmentID || authority.DeviceID != challenge.DeviceID {
		return unresolved()
	}
	// BeginAssociation compares every actual local credential/key/public fact to
	// this fresh response under its source guard. It does not prove that HTTP
	// occurred: this concrete TLS path and context are the provenance boundary.
	association, err := store.BeginAssociation(envelope, authority, observedAt)
	if err != nil {
		return unresolved()
	}
	defer func() {
		if association.Close() != nil && operationErr == nil {
			operationErr = errGatewayAgentAssociation
		}
	}()
	binding := assoc.DeviceBinding{OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, CredentialID: authority.CredentialID, CredentialGeneration: authority.CredentialGeneration, PublicKey: authority.PublicKey, ExpiresAt: authority.ExpiresAt}
	return runGatewayAgentAssociationPost(ctx, output, client, association, &binding)
}

func readGatewayLegacyAuthority(ctx context.Context, client *http.Client, request *http.Request) (enrollment.CurrentAuthority, error) {
	response, err := client.Do(request)
	if err != nil {
		return enrollment.CurrentAuthority{}, errGatewayAgentAssociation
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return enrollment.CurrentAuthority{}, errGatewayAgentAssociation
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, enrollment.MaximumBytes+1))
	if err != nil || len(raw) > enrollment.MaximumBytes || ctx.Err() != nil {
		return enrollment.CurrentAuthority{}, errGatewayAgentAssociation
	}
	authority, err := enrollment.ParseCurrentAuthority(raw)
	if err != nil {
		return enrollment.CurrentAuthority{}, errGatewayAgentAssociation
	}
	return authority, nil
}
