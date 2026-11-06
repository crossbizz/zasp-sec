package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	assoc "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	custody "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentcustody"
)

var errGatewayAgentAssociation = errors.New("gateway agent acceptance unresolved")

type gatewayAgentAssociationReport struct {
	State         string `json:"state"`
	Outcome       string `json:"outcome"`
	AssociationID string `json:"association_id,omitempty"`
	ChallengeID   string `json:"challenge_id,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
}

func writeGatewayAgentAssociationReport(output io.Writer, report gatewayAgentAssociationReport) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return errGatewayAgentAssociation
	}
	raw = append(raw, '\n')
	n, err := output.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

// Accept-agent records only Device possession for a pending administrative
// association. A human must separately authorize and confirm activation.
func runGatewayAgentAssociationCommand(output io.Writer, input io.Reader, q gatewayCommandOptions) (operationErr error) {
	report := gatewayAgentAssociationReport{State: "unresolved", Outcome: "unknown"}
	unresolved := func() error {
		if err := writeGatewayAgentAssociationReport(output, report); err != nil {
			return err
		}
		return errGatewayAgentAssociation
	}
	raw, err := io.ReadAll(io.LimitReader(input, assoc.MaximumBytes+1))
	if err != nil || len(raw) > assoc.MaximumBytes {
		return unresolved()
	}
	envelope, err := assoc.ParseChallengeEnvelope(raw)
	if err != nil {
		return unresolved()
	}
	if q.credentialFile != "" {
		return runGatewayLegacyAgentAssociation(output, q, envelope)
	}
	store, err := custody.Open(q.custodyFile)
	if err != nil {
		return unresolved()
	}
	defer func() {
		if store.Close() != nil && operationErr == nil {
			operationErr = errGatewayAgentAssociation
		}
	}()
	client, err := newGatewayEnrollmentHTTPClient(q)
	if err != nil {
		return unresolved()
	}
	defer client.CloseIdleConnections()
	association, err := store.BeginAssociation(envelope, gatewayEnrollmentNow())
	if err != nil {
		return unresolved()
	}
	defer func() {
		if association.Close() != nil && operationErr == nil {
			operationErr = errGatewayAgentAssociation
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()
	return runGatewayAgentAssociationPost(ctx, output, client, association, nil)
}

type gatewayAssociationHandle interface {
	Source() (string, custody.AssociationSnapshot, error)
	Sign([]byte) ([]byte, error)
	Confirm(assoc.AcceptResponse, time.Time) error
	Close() error
}

func runGatewayAgentAssociationPost(ctx context.Context, output io.Writer, client *http.Client, association gatewayAssociationHandle, expected *assoc.DeviceBinding) error {
	report := gatewayAgentAssociationReport{State: "unresolved", Outcome: "unknown"}
	unresolved := func() error {
		if err := writeGatewayAgentAssociationReport(output, report); err != nil {
			return err
		}
		return errGatewayAgentAssociation
	}
	endpoint, snapshot, err := association.Source()
	if err != nil || !gatewayCommandEndpoint(endpoint) || ctx.Err() != nil || expected != nil && !sameGatewayAssociationBinding(snapshot.Binding, *expected) {
		return unresolved()
	}
	report.AssociationID = snapshot.Challenge.AssociationID
	report.ChallengeID = snapshot.Challenge.ChallengeID
	report.AgentID = snapshot.Challenge.AgentID
	report.DeviceID = snapshot.Challenge.DeviceID
	sentAt := gatewayEnrollmentNow()
	if !snapshot.Challenge.ExpiresAt.After(sentAt) || !snapshot.Binding.ExpiresAt.After(sentAt) {
		return unresolved()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+assoc.AcceptPath, bytes.NewReader(snapshot.RequestRaw))
	if err != nil {
		return unresolved()
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if assoc.SignAcceptRequest(request, snapshot.RequestRaw, snapshot.Binding, association.Sign, sentAt) != nil {
		return unresolved()
	}
	// A saved receipt remains historical. Every explicit invocation needs this
	// live server check, including an exact retry after an uncertain commit.
	response, err := client.Do(request)
	if err != nil {
		return unresolved()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return unresolved()
	}
	responseRaw, err := io.ReadAll(io.LimitReader(response.Body, assoc.MaximumBytes+1))
	observedAt := gatewayEnrollmentNow()
	if err != nil || len(responseRaw) > assoc.MaximumBytes || ctx.Err() != nil {
		return unresolved()
	}
	receipt, err := assoc.ParseAcceptResponse(responseRaw)
	if err != nil || !assoc.AcceptResponseMatches(receipt, snapshot.RequestRaw, snapshot.Binding, observedAt) || association.Confirm(receipt, observedAt) != nil {
		return unresolved()
	}
	finalNow := gatewayEnrollmentNow()
	if ctx.Err() != nil || !assoc.AcceptResponseMatches(receipt, snapshot.RequestRaw, snapshot.Binding, finalNow) {
		return unresolved()
	}
	report.State = "device_accepted_pending_human"
	report.Outcome = "confirmed_device_acceptance"
	return writeGatewayAgentAssociationReport(output, report)
}

func sameGatewayAssociationBinding(a, b assoc.DeviceBinding) bool {
	return a.OrganizationID == b.OrganizationID && a.WorkspaceID == b.WorkspaceID && a.EnvironmentID == b.EnvironmentID && a.DeviceID == b.DeviceID && a.CredentialID == b.CredentialID && a.CredentialGeneration == b.CredentialGeneration && a.PublicKey == b.PublicKey && a.ExpiresAt.Equal(b.ExpiresAt)
}
