package redteamadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// validateWorkerCompletion consumes only captured completion metadata. It must
// not turn this receipt into an invocation observation or target resolution.
func validateWorkerCompletion(raw []byte, request JournalRequest, observation InvocationObservation) error {
	if len(raw) > 8192 || !temporalJournalRequestValid(request) || !validInvocationObservation(observation) || !validCredentialVersionDigest(observation.CredentialVersionDigest) {
		return ErrAdapter
	}
	fields, err := exactJournalObject(raw, "organization_id workspace_id environment_id parent_run_id test_run_id step_id effect_key category attempt state request_digest response_digest http_status protected credential_version_digest completed_at")
	if err != nil || len(fields) != 16 {
		return ErrAdapter
	}
	for _, value := range fields {
		if string(value) == "null" {
			return ErrAdapter
		}
	}
	var receipt struct {
		OrganizationID          string `json:"organization_id"`
		WorkspaceID             string `json:"workspace_id"`
		EnvironmentID           string `json:"environment_id"`
		ParentRunID             string `json:"parent_run_id"`
		TestRunID               string `json:"test_run_id"`
		StepID                  string `json:"step_id"`
		EffectKey               string `json:"effect_key"`
		Category                string `json:"category"`
		Attempt                 int    `json:"attempt"`
		State                   string `json:"state"`
		RequestDigest           string `json:"request_digest"`
		ResponseDigest          string `json:"response_digest"`
		HTTPStatus              int    `json:"http_status"`
		Protected               *bool  `json:"protected"`
		CredentialVersionDigest string `json:"credential_version_digest"`
		CompletedAt             string `json:"completed_at"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return ErrAdapter
	}
	scope := request.Invocation.Scope
	if receipt.OrganizationID != scope.OrganizationID().String() || receipt.WorkspaceID != scope.WorkspaceID().String() || receipt.EnvironmentID != scope.EnvironmentID().String() || receipt.TestRunID != request.Invocation.RunID || receipt.Category != request.Invocation.Category || receipt.Attempt != 1 || receipt.State != "completed" || receipt.EffectKey != request.EffectKey || receipt.RequestDigest != request.RequestDigest || receipt.ResponseDigest != observation.ResponseDigest || receipt.HTTPStatus != observation.HTTPStatus || receipt.Protected == nil || *receipt.Protected != *observation.Protected || receipt.CredentialVersionDigest != observation.CredentialVersionDigest {
		return ErrAdapter
	}
	if _, err := domain.ParseProductID(receipt.ParentRunID); err != nil {
		return ErrAdapter
	}
	if _, err := domain.ParseProductID(receipt.StepID); err != nil {
		return ErrAdapter
	}
	identity := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", receipt.OrganizationID, receipt.WorkspaceID, receipt.EnvironmentID, receipt.ParentRunID, receipt.StepID, "1"}, "\x1f")))
	if hex.EncodeToString(identity[:]) != request.EffectKey {
		return ErrAdapter
	}
	stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", receipt.CompletedAt)
	if err != nil || stamp.IsZero() || stamp.Format("2006-01-02T15:04:05.000000Z") != receipt.CompletedAt {
		return ErrAdapter
	}
	return nil
}
