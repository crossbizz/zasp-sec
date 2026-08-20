package collection

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestResultsMustMatchTheExactRequestedProviderSubject(t *testing.T) {
	for _, provider := range []Provider{ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta} {
		request := validRequest(t, provider, credentialForProvider(provider))
		manifest := validManifest(t, request)
		wrong := subjectForProvider(provider)
		switch provider {
		case ProviderAWS:
			wrong.ID = "210987654321"
		case ProviderKubernetes:
			wrong.ID = "cluster.example/other"
		case ProviderGitHub:
			wrong.ID = "654321"
		case ProviderOkta:
			wrong.ID = "other.okta.com"
		}
		candidate, err := NewSnapshotCandidate(provider, request.ParserVersion, request.ToolVersion, []byte(`[]`), []byte(`[]`), []byte(`[]`))
		if err != nil {
			t.Fatalf("%s NewSnapshotCandidate: %v", provider, err)
		}
		if _, err := NewCompleteResult(request, wrong, Cursor{Provider: provider, Version: "cursor_v1", Value: "next"}, manifest, candidate); !errors.Is(err, ErrContract) {
			t.Fatalf("%s accepted a different provider subject: %v", provider, err)
		}
		if _, err := NewPartialResult(request, wrong, Cursor{Provider: provider, Version: "cursor_v1", Value: "next"}, manifest, FailurePartial); !errors.Is(err, ErrContract) {
			t.Fatalf("%s partial accepted a different provider subject: %v", provider, err)
		}
	}
}

func TestProviderSubjectsUseExactProviderGrammar(t *testing.T) {
	invalid := map[Provider][]string{
		ProviderAWS:        {"123", "12345678901x"},
		ProviderKubernetes: {"https://cluster.example", "cluster example/customer"},
		ProviderGitHub:     {"0", "01", "installation-123", "9007199254740993"},
		ProviderOkta:       {"https://acme.okta.com", "ACME.okta.com", "evil.example.com", "okta.com"},
	}
	for provider, ids := range invalid {
		for _, id := range ids {
			binding := subjectForProvider(provider)
			binding.ID = id
			if binding.valid(provider) {
				t.Fatalf("%s accepted subject %q", provider, id)
			}
		}
	}
}

func TestCompleteAndPartialResultsAreStructurallyDisjoint(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	candidate, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`), []byte(`[]`), []byte(`[]`))
	if err != nil {
		t.Fatalf("NewSnapshotCandidate: %v", err)
	}
	manifest := validManifest(t, request)
	binding := SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	next := Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "page_2"}
	complete, err := NewCompleteResult(request, binding, next, manifest, candidate)
	if err != nil {
		t.Fatalf("NewCompleteResult: %v", err)
	}
	var outcome Outcome = complete
	applicable, ok := outcome.(ApplicableResult)
	if !ok || applicable.Snapshot().Source() != ProviderAWS || applicable.Snapshot().EntityCount() != 1 {
		t.Fatalf("complete outcome is not applicable: %#v", outcome)
	}
	partial, err := NewPartialResult(request, binding, next, manifest, FailurePartial)
	if err != nil {
		t.Fatalf("NewPartialResult: %v", err)
	}
	if _, ok := any(partial).(ApplicableResult); ok {
		t.Fatal("partial result exposed an applicable snapshot")
	}
	if partial.Reason() != FailurePartial {
		t.Fatalf("partial reason = %q", partial.Reason())
	}
	if _, err := NewCompleteResult(request, binding, Cursor{}, manifest, candidate); !errors.Is(err, ErrContract) {
		t.Fatalf("unversioned result cursor accepted: %v", err)
	}
	if _, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[{ "id":"pid_10000005-0000-4000-8000-000000000005"}]`), []byte(`[]`), []byte(`[]`)); !errors.Is(err, ErrContract) {
		t.Fatalf("non-canonical snapshot accepted: %v", err)
	}
}

func TestRawManifestRejectsUnversionedOrUnscopedArtifactBindings(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	object := RawObject{
		reference: mustEvidenceRef(t, "pid_10000006-0000-4000-8000-000000000006"),
		checksum:  [32]byte{1}, size: 128, mediaType: "application/json", schema: "raw_v1",
		parser: request.ParserVersion, tool: request.ToolVersion,
	}
	manifest := RawObject{
		reference: mustEvidenceRef(t, "pid_10000007-0000-4000-8000-000000000007"),
		checksum:  [32]byte{2}, size: 256, mediaType: "application/json", schema: "manifest_v1",
		parser: request.ParserVersion, tool: request.ToolVersion,
	}
	if _, err := NewRawManifest(manifest, []RawObject{object}); !errors.Is(err, ErrContract) {
		t.Fatalf("unversioned and unscoped manifest accepted: %v", err)
	}
}

func TestSnapshotEvidenceMustBeAnExactManifestArtifactMember(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	manifest := validManifest(t, request)
	entities := []byte(`[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`)
	exactObjectReference := "s3://zasp-evidence/organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000006-0000-4000-8000-000000000006"
	candidate, err := NewSnapshotCandidate(ProviderAWS, request.ParserVersion, request.ToolVersion, entities, []byte(`[]`), evidenceForArtifactBinding(exactObjectReference, "s3-version-object-1"))
	if err != nil {
		t.Fatalf("NewSnapshotCandidate exact: %v", err)
	}
	if _, err := NewCompleteResult(request, request.ExpectedSubject, Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "next"}, manifest, candidate); err != nil {
		t.Fatalf("exact manifest membership rejected: %v", err)
	}
	candidate, err = NewSnapshotCandidate(ProviderAWS, request.ParserVersion, request.ToolVersion, entities, []byte(`[]`), evidenceForArtifactBinding(exactObjectReference, "wrong-version"))
	if err != nil {
		t.Fatalf("NewSnapshotCandidate: %v", err)
	}
	if _, err := NewCompleteResult(request, request.ExpectedSubject, Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "next"}, manifest, candidate); !errors.Is(err, ErrContract) {
		t.Fatalf("evidence outside exact manifest membership accepted: %v", err)
	}
	candidate, err = NewSnapshotCandidate(ProviderAWS, request.ParserVersion, request.ToolVersion, entities, []byte(`[]`), evidenceForArtifactBinding("s3://other-bucket/organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000006-0000-4000-8000-000000000006", "s3-version-object-1"))
	if err != nil {
		t.Fatalf("NewSnapshotCandidate wrong object reference: %v", err)
	}
	if _, err := NewCompleteResult(request, request.ExpectedSubject, Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "next"}, manifest, candidate); !errors.Is(err, ErrContract) {
		t.Fatalf("evidence with mismatched object reference accepted: %v", err)
	}
}

func evidenceForArtifactBinding(objectReference, version string) []byte {
	return []byte(fmt.Sprintf(`[{"id":"pid_10000009-0000-4000-8000-000000000009","entity_id":"pid_10000005-0000-4000-8000-000000000005","object_reference":%q,"artifact_reference":"pid_10000006-0000-4000-8000-000000000006","artifact_key":"organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000006-0000-4000-8000-000000000006","artifact_version_id":%q,"checksum_hex":"0100000000000000000000000000000000000000000000000000000000000000","size_bytes":128,"media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1"}]`, objectReference, version))
}

func TestPartialResultRejectsCrossScopeManifest(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	manifest := validManifest(t, request)
	otherScope, err := domain.NewScope(
		mustID(t, "pid_10000020-0000-4000-8000-000000000020"),
		mustID(t, "pid_10000021-0000-4000-8000-000000000021"),
		mustID(t, "pid_10000022-0000-4000-8000-000000000022"),
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	request.Scope = otherScope
	if _, err := NewPartialResult(request, request.ExpectedSubject, Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "next"}, manifest, FailurePartial); !errors.Is(err, ErrContract) {
		t.Fatalf("cross-scope manifest accepted: %v", err)
	}
}

func TestSnapshotCandidateRejectsMissingUnknownAndDanglingNormalizedFields(t *testing.T) {
	validEntity := `{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`
	validSecond := `{"id":"pid_10000008-0000-4000-8000-000000000008","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"read","stable_fields":{},"attributes":{}}`
	for name, entities := range map[string]string{
		"missing fields": `[{"id":"pid_10000005-0000-4000-8000-000000000005"}]`,
		"unknown field":  `[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{},"access_token":"secret"}]`,
		"duplicate id":   `[` + validEntity + `,` + validEntity + `]`,
	} {
		if _, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(entities), []byte(`[]`), []byte(`[]`)); !errors.Is(err, ErrContract) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	dangling := `[{"id":"pid_10000009-0000-4000-8000-000000000009","kind":"uses_policy","source_native_id":"edge-1","from_entity_id":"pid_10000005-0000-4000-8000-000000000005","to_entity_id":"pid_10000009-0000-4000-8000-000000000009","attributes":{}}]`
	if _, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[`+validEntity+`,`+validSecond+`]`), []byte(dangling), []byte(`[]`)); !errors.Is(err, ErrContract) {
		t.Fatalf("dangling relationship accepted: %v", err)
	}
}

func TestSnapshotCandidateBindsCompleteTypedObservationEnvelopeToEvidence(t *testing.T) {
	entity := []byte(`[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{},"identity_namespace":"aws_account","identity_rule_version":1,"identity_priority":100,"product_kind":"asset","confidence_basis_points":9000,"observed_at":"2026-08-20T12:00:00Z","fresh_until":"2026-08-21T12:00:00Z","evidence_id":"pid_10000009-0000-4000-8000-000000000009","source_projection_version":1}]`)
	evidence := evidenceForArtifactBinding("s3://zasp-evidence/organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000006-0000-4000-8000-000000000006", "s3-version-object-1")

	candidate, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", entity, []byte(`[]`), evidence)
	if err != nil || !candidate.TypedObservations() {
		t.Fatalf("typed candidate = %#v, err=%v", candidate, err)
	}
	empty, err := NewTypedSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[]`), []byte(`[]`), []byte(`[]`))
	if err != nil || !empty.TypedObservations() {
		t.Fatalf("typed empty candidate = %#v, err=%v", empty, err)
	}
	legacy, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[]`), []byte(`[]`), []byte(`[]`))
	if err != nil || legacy.TypedObservations() {
		t.Fatalf("legacy candidate = %#v, err=%v", legacy, err)
	}

	for name, mutate := range map[string]func(string) string{
		"partial envelope": func(value string) string { return strings.Replace(value, `,"source_projection_version":1`, "", 1) },
		"wrong evidence": func(value string) string {
			return strings.Replace(value, "pid_10000009-0000-4000-8000-000000000009", "pid_10000019-0000-4000-8000-000000000019", 1)
		},
		"noncanonical time": func(value string) string {
			return strings.Replace(value, "2026-08-20T12:00:00Z", "2026-08-20T12:00:00.000Z", 1)
		},
		"closed product kind": func(value string) string {
			return strings.Replace(value, `"product_kind":"asset"`, `"product_kind":"server"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(mutate(string(entity))), []byte(`[]`), evidence); !errors.Is(err, ErrContract) {
				t.Fatalf("invalid typed envelope accepted: %v", err)
			}
		})
	}
	if _, err := NewTypedSnapshotCandidate(ProviderAWS, "parser_v1", "tool_v1", []byte(`[{"id":"pid_10000005-0000-4000-8000-000000000005","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`), []byte(`[]`), []byte(`[]`)); !errors.Is(err, ErrContract) {
		t.Fatalf("typed constructor accepted legacy entity: %v", err)
	}
}

func TestRegistryRequiresExactFirstPartyProviderVersionAndIsolatesReadiness(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	checks := map[Provider]int{}
	registrations := make([]Registration, 0, 4)
	for _, provider := range []Provider{ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta} {
		provider := provider
		status := Readiness{Provider: provider, CollectorVersion: "collector_v1", Ready: true, CheckedAt: now}
		if provider == ProviderGitHub {
			status.Ready = false
			status.Code = ReadinessDependencyUnavailable
		}
		registrations = append(registrations, Registration{
			Provider: provider, CollectorVersion: "collector_v1", CredentialClass: credentialForProvider(provider),
			Collector:        collectorFunc(func(context.Context, Request) (Outcome, error) { return PartialResult{}, errors.New("unused") }),
			ReadinessTimeout: 100 * time.Millisecond,
			Readiness:        readinessFunc(func(context.Context) Readiness { checks[provider]++; return status }),
		})
	}
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	github := registry.CheckReadiness(context.Background(), ProviderGitHub, "collector_v1")
	aws := registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v1")
	if github.Ready || github.Code != ReadinessDependencyUnavailable || !aws.Ready || aws.Code != ReadinessReady {
		t.Fatalf("isolated readiness github=%#v aws=%#v", github, aws)
	}
	if checks[ProviderGitHub] != 1 || checks[ProviderAWS] != 1 || checks[ProviderKubernetes] != 0 || checks[ProviderOkta] != 0 {
		t.Fatalf("readiness probes were not isolated: %#v", checks)
	}
	if status := registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v2"); status.Code != ReadinessUnconfigured {
		t.Fatalf("unknown version status = %#v", status)
	}
	hostile := append([]Registration(nil), registrations...)
	hostile[0].Provider = Provider("nango:github")
	if _, err := NewRegistry(hostile); !errors.Is(err, ErrContract) {
		t.Fatalf("Nango registered as first party: %v", err)
	}
}

func TestRegistryBoundsEachProviderReadinessProbe(t *testing.T) {
	registrations := validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) { return nil, nil }))
	registrations[0].Readiness = readinessFunc(func(ctx context.Context) Readiness {
		<-ctx.Done()
		return Readiness{}
	})
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	started := time.Now()
	status := registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v1")
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond || status.Ready || status.Code != ReadinessDependencyUnavailable || status.CheckedAt.IsZero() || status.CheckedAt.Location() != time.UTC {
		t.Fatalf("bounded readiness elapsed=%s status=%#v", elapsed, status)
	}
}

func TestRegistryRejectsSecretBearingRequestsAndHostileCollectorResults(t *testing.T) {
	request := validRequest(t, ProviderOkta, CredentialOktaRefresh)
	collectorCalls := 0
	registrations := validRegistrations(t, collectorFunc(func(ctx context.Context, input Request) (Outcome, error) {
		collectorCalls++
		return PartialResult{}, nil
	}))
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	request.CredentialReference = "inline-refresh-token"
	if _, err := registry.Collect(context.Background(), request); !errors.Is(err, ErrContract) || collectorCalls != 0 {
		t.Fatalf("secret-bearing request reached collector: calls=%d err=%v", collectorCalls, err)
	}
	request = validRequest(t, ProviderOkta, CredentialOktaRefresh)
	if _, err := registry.Collect(context.Background(), request); !errors.Is(err, ErrContract) || collectorCalls != 1 {
		t.Fatalf("hostile result accepted: calls=%d err=%v", collectorCalls, err)
	}
	var typedNil *CompleteResult
	registrations = validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) { return typedNil, nil }))
	registry, _ = NewRegistry(registrations)
	if _, err := registry.Collect(context.Background(), request); !errors.Is(err, ErrContract) {
		t.Fatalf("typed-nil result accepted or panicked: %v", err)
	}
}

func TestFailuresAreStableRedactedAndRetryTimesAreCanonical(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for _, code := range []FailureCode{FailureRetryable, FailureRateLimited, FailureDenied, FailureRevoked, FailureMalformed, FailurePartial, FailureTerminal, FailureCancelled, FailureOutcomeUnknown} {
		retryAt := time.Time{}
		if code == FailureRateLimited {
			retryAt = now.Add(time.Minute)
		}
		failure, err := NewFailure(code, retryAt)
		if err != nil || failure.Code() != code || failure.Error() != "collection failed: "+string(code) {
			t.Fatalf("failure %q = %#v, %v", code, failure, err)
		}
		if !failure.RetryAt().IsZero() && failure.RetryAt().Location() != time.UTC {
			t.Fatalf("retry time is not UTC: %v", failure.RetryAt())
		}
	}
	if _, err := NewFailure(FailureRetryable, now); !errors.Is(err, ErrContract) {
		t.Fatalf("retryable failure accepted retry_at: %v", err)
	}
	if _, err := NewFailure(FailureRateLimited, time.Time{}); !errors.Is(err, ErrContract) {
		t.Fatalf("rate-limited failure accepted empty retry_at: %v", err)
	}
}

func TestWorkerCredentialMaterialIsReferenceBoundAndZeroizedAfterUse(t *testing.T) {
	request := validRequest(t, ProviderKubernetes, CredentialKubernetesCluster)
	credentialRequest := CredentialRequest{
		Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID,
		JobID: request.JobID, Attempt: request.Attempt, Provider: request.Provider,
		Class: request.CredentialClass, Reference: request.CredentialReference, ExpectedSubject: request.ExpectedSubject,
	}
	if _, err := NewCredentialMaterial(credentialRequest, []byte("already-expired"), time.Now().Add(-time.Second)); !errors.Is(err, ErrCredential) {
		t.Fatalf("expired material accepted: %v", err)
	}
	material, err := NewCredentialMaterial(credentialRequest, []byte("worker-only-secret"), time.Date(2030, 8, 19, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewCredentialMaterial: %v", err)
	}
	var borrowed []byte
	if err := material.Use(credentialRequest, func(value []byte) error {
		borrowed = value
		if string(value) != "worker-only-secret" {
			t.Fatalf("material = %q", value)
		}
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	for index, value := range borrowed {
		if value != 0 {
			t.Fatalf("borrowed material byte %d was not zeroized", index)
		}
	}
	material.Destroy()
	if err := material.Use(credentialRequest, func([]byte) error { return nil }); !errors.Is(err, ErrCredential) {
		t.Fatalf("destroyed material reused: %v", err)
	}
	wrong := credentialRequest
	wrong.JobID = mustID(t, "pid_10000009-0000-4000-8000-000000000009")
	second, _ := NewCredentialMaterial(credentialRequest, []byte("worker-only-secret"), time.Date(2030, 8, 19, 13, 0, 0, 0, time.UTC))
	defer second.Destroy()
	if err := second.Use(wrong, func([]byte) error { return nil }); !errors.Is(err, ErrCredential) {
		t.Fatalf("cross-job credential material accepted: %v", err)
	}
}

func TestProviderAdapterResolvesOnlyTheExactWorkerCredentialAndZeroizesBorrow(t *testing.T) {
	for _, provider := range []Provider{ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta} {
		provider := provider
		request := validRequest(t, provider, credentialForProvider(provider))
		manifest := validManifest(t, request)
		binding := subjectForProvider(provider)
		partial, err := NewPartialResult(request, binding, Cursor{Provider: provider, Version: "cursor_v1", Value: "next"}, manifest, FailurePartial)
		if err != nil {
			t.Fatalf("%s partial: %v", provider, err)
		}
		var resolved CredentialRequest
		var material *CredentialMaterial
		resolver := resolverFunc(func(_ context.Context, input CredentialRequest) (*CredentialMaterial, error) {
			resolved = input
			var err error
			material, err = NewCredentialMaterial(input, []byte("ephemeral-provider-credential"), time.Now().Add(time.Hour))
			return material, err
		})
		var borrowed []byte
		client := providerClientFunc(func(_ context.Context, input Request, credential []byte) (Outcome, error) {
			if input != request || string(credential) != "ephemeral-provider-credential" {
				t.Fatalf("%s client input=%#v credential=%q", provider, input, credential)
			}
			borrowed = credential
			return partial, nil
		})
		adapter, err := NewProviderAdapter(provider, credentialForProvider(provider), resolver, client)
		if err != nil {
			t.Fatalf("%s NewProviderAdapter: %v", provider, err)
		}
		outcome, err := adapter.Collect(context.Background(), request)
		if err != nil || outcome == nil || resolved.Reference != request.CredentialReference {
			t.Fatalf("%s outcome=%#v resolved=%#v err=%v", provider, outcome, resolved, err)
		}
		for index, value := range borrowed {
			if value != 0 {
				t.Fatalf("%s borrowed byte %d was not zeroized", provider, index)
			}
		}
		if material == nil || material.Use(resolved, func([]byte) error { return nil }) == nil {
			t.Fatalf("%s material was not destroyed", provider)
		}
		wrong := request
		wrong.Provider = ProviderAWS
		if provider == ProviderAWS {
			wrong.Provider = ProviderGitHub
		}
		if _, err := adapter.Collect(context.Background(), wrong); !errors.Is(err, ErrContract) {
			t.Fatalf("%s accepted cross-provider request: %v", provider, err)
		}
	}
}

func TestProviderAdapterDestroysMaterialReturnedWithResolverFailure(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	credentialRequest := CredentialRequest{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, Provider: request.Provider, Class: request.CredentialClass, Reference: request.CredentialReference, ExpectedSubject: request.ExpectedSubject}
	material, err := NewCredentialMaterial(credentialRequest, []byte("ephemeral-provider-credential"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("NewCredentialMaterial: %v", err)
	}
	failure, _ := NewFailure(FailureDenied, time.Time{})
	adapter, err := NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(context.Context, CredentialRequest) (*CredentialMaterial, error) {
		return material, failure
	}), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		t.Fatal("provider client called after resolver failure")
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("NewProviderAdapter: %v", err)
	}
	if _, err := adapter.Collect(context.Background(), request); !errors.Is(err, failure) {
		t.Fatalf("resolver failure = %v", err)
	}
	if err := material.Use(credentialRequest, func([]byte) error { return nil }); !errors.Is(err, ErrCredential) {
		t.Fatalf("failed resolver material remained usable: %v", err)
	}
}

func TestProviderAdapterRejectsHostileClientOutcomeBeforeReturningIt(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	credentialRequest := credentialRequestFor(request)
	adapter, err := NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(context.Context, CredentialRequest) (*CredentialMaterial, error) {
		return NewCredentialMaterial(credentialRequest, []byte("ephemeral-provider-credential"), time.Now().Add(time.Hour))
	}), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		return PartialResult{}, nil
	}))
	if err != nil {
		t.Fatalf("NewProviderAdapter: %v", err)
	}
	if _, err := adapter.Collect(context.Background(), request); !errors.Is(err, ErrContract) {
		t.Fatalf("hostile client outcome returned: %v", err)
	}
}

func TestProviderAdapterClonesValidatedClientOutcome(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	credentialRequest := credentialRequestFor(request)
	partial, err := NewPartialResult(request, request.ExpectedSubject, Cursor{Provider: ProviderAWS, Version: "cursor_v1", Value: "next"}, validManifest(t, request), FailurePartial)
	if err != nil {
		t.Fatalf("NewPartialResult: %v", err)
	}
	adapter, err := NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(context.Context, CredentialRequest) (*CredentialMaterial, error) {
		return NewCredentialMaterial(credentialRequest, []byte("ephemeral-provider-credential"), time.Now().Add(time.Hour))
	}), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		return partial, nil
	}))
	if err != nil {
		t.Fatalf("NewProviderAdapter: %v", err)
	}
	outcome, err := adapter.Collect(context.Background(), request)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	partial.manifest.objects[0].versionID = "mutated-after-return"
	returned, ok := outcome.(PartialResult)
	if !ok || returned.Manifest().Objects()[0].VersionID() != "s3-version-object-1" {
		t.Fatalf("adapter returned mutable provider outcome: %#v", outcome)
	}
}

func TestCollectionCancellationAndDeadlineHaveStableFailureCodes(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	adapter, err := NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(context.Context, CredentialRequest) (*CredentialMaterial, error) {
		t.Fatal("resolver called for cancelled collection")
		return nil, nil
	}), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		t.Fatal("provider called for cancelled collection")
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("NewProviderAdapter: %v", err)
	}
	if _, err := adapter.Collect(cancelled, request); failureCode(err) != FailureCancelled {
		t.Fatalf("cancelled collection error = %v", err)
	}

	request.Bounds.Timeout = 100 * time.Millisecond
	adapter, err = NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(ctx context.Context, _ CredentialRequest) (*CredentialMaterial, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		t.Fatal("provider called after resolver deadline")
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("NewProviderAdapter deadline: %v", err)
	}
	if _, err := adapter.Collect(context.Background(), request); failureCode(err) != FailureRetryable {
		t.Fatalf("deadline collection error = %v", err)
	}
}

func TestRegistryMapsCollectorCancellationAndDeadline(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	registrations := validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) {
		t.Fatal("collector called for an already-cancelled request")
		return nil, nil
	}))
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := registry.Collect(cancelled, request); failureCode(err) != FailureCancelled {
		t.Fatalf("cancelled registry collection error = %v", err)
	}

	registrations = validRegistrations(t, collectorFunc(func(ctx context.Context, _ Request) (Outcome, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	registry, err = NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry deadline: %v", err)
	}
	deadline, deadlineCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer deadlineCancel()
	if _, err := registry.Collect(deadline, request); failureCode(err) != FailureRetryable {
		t.Fatalf("deadline registry collection error = %v", err)
	}
}

func TestReadinessIsSingleFlightAndRegistryOwnsTimestamp(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	registrations := validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) { return nil, nil }))
	registrations[0].Readiness = readinessFunc(func(context.Context) Readiness {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return Readiness{Provider: ProviderAWS, CollectorVersion: "collector_v1", Ready: true, Code: ReadinessReady, CheckedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.FixedZone("hostile", 3600))}
	})
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	startedAt := time.Now().UTC()
	results := make(chan Readiness, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v1")
		}()
	}
	<-entered
	time.Sleep(25 * time.Millisecond)
	close(release)
	group.Wait()
	close(results)
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent readiness probes = %d, want 1", got)
	}
	var checkedAt time.Time
	for status := range results {
		if !status.Ready || status.Code != ReadinessReady || status.CheckedAt.Before(startedAt) || status.CheckedAt.Location() != time.UTC {
			t.Fatalf("registry readiness = %#v", status)
		}
		if checkedAt.IsZero() {
			checkedAt = status.CheckedAt
		} else if status.CheckedAt != checkedAt {
			t.Fatalf("single flight returned different timestamps: %s != %s", status.CheckedAt, checkedAt)
		}
	}
}

func TestReadinessIgnoringContextIsBoundedWithoutProbeAccumulation(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	defer close(release)
	registrations := validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) { return nil, nil }))
	registrations[0].ReadinessTimeout = 100 * time.Millisecond
	registrations[0].Readiness = readinessFunc(func(context.Context) Readiness {
		calls.Add(1)
		<-release
		return Readiness{Provider: ProviderAWS, CollectorVersion: "collector_v1", Ready: true, Code: ReadinessReady}
	})
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		started := time.Now()
		status := registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v1")
		if elapsed := time.Since(started); elapsed > 300*time.Millisecond || status.Ready || status.Code != ReadinessDependencyUnavailable {
			t.Fatalf("attempt %d elapsed=%s status=%#v", attempt, elapsed, status)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("noncooperative readiness probes = %d, want one fenced probe", got)
	}
}

func TestReadinessLeaderCancellationDoesNotCancelLiveFollower(t *testing.T) {
	var calls atomic.Int32
	var enteredOnce sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	registrations := validRegistrations(t, collectorFunc(func(context.Context, Request) (Outcome, error) { return nil, nil }))
	registrations[0].Readiness = readinessFunc(func(context.Context) Readiness {
		calls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
		return Readiness{Provider: ProviderAWS, CollectorVersion: "collector_v1", Ready: true, Code: ReadinessReady}
	})
	registry, err := NewRegistry(registrations)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan Readiness, 1)
	go func() { leader <- registry.CheckReadiness(leaderContext, ProviderAWS, "collector_v1") }()
	<-entered
	cancelLeader()
	if status := <-leader; status.Code != ReadinessCancelled {
		t.Fatalf("cancelled leader status = %#v", status)
	}
	follower := make(chan Readiness, 1)
	go func() { follower <- registry.CheckReadiness(context.Background(), ProviderAWS, "collector_v1") }()
	time.Sleep(25 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("follower started a second readiness probe before shared completion: %d", got)
	}
	close(release)
	status := <-follower
	if !status.Ready || status.Code != ReadinessReady || calls.Load() != 1 {
		t.Fatalf("live follower status=%#v calls=%d", status, calls.Load())
	}
}

func failureCode(err error) FailureCode {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code()
	}
	return ""
}

func credentialRequestFor(request Request) CredentialRequest {
	return CredentialRequest{
		Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID,
		JobID: request.JobID, Attempt: request.Attempt, Provider: request.Provider,
		Class: request.CredentialClass, Reference: request.CredentialReference, ExpectedSubject: request.ExpectedSubject,
	}
}

type collectorFunc func(context.Context, Request) (Outcome, error)

func (function collectorFunc) Collect(ctx context.Context, request Request) (Outcome, error) {
	return function(ctx, request)
}

type readinessFunc func(context.Context) Readiness

func (function readinessFunc) Check(ctx context.Context) Readiness { return function(ctx) }

type resolverFunc func(context.Context, CredentialRequest) (*CredentialMaterial, error)

func (function resolverFunc) ResolveCollectionCredential(ctx context.Context, request CredentialRequest) (*CredentialMaterial, error) {
	return function(ctx, request)
}

type providerClientFunc func(context.Context, Request, []byte) (Outcome, error)

func (function providerClientFunc) CollectWithCredential(ctx context.Context, request Request, credential []byte) (Outcome, error) {
	return function(ctx, request, credential)
}

func validRegistrations(t *testing.T, collector Collector) []Registration {
	t.Helper()
	registrations := make([]Registration, 0, 4)
	for _, provider := range []Provider{ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta} {
		registrations = append(registrations, Registration{
			Provider: provider, CollectorVersion: "collector_v1", CredentialClass: credentialForProvider(provider), Collector: collector,
			ReadinessTimeout: 100 * time.Millisecond,
			Readiness: readinessFunc(func(context.Context) Readiness {
				return Readiness{Provider: provider, CollectorVersion: "collector_v1", Ready: true, CheckedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
			}),
		})
	}
	return registrations
}

func credentialForProvider(provider Provider) CredentialClass {
	switch provider {
	case ProviderAWS:
		return CredentialAWSAssumeRole
	case ProviderKubernetes:
		return CredentialKubernetesCluster
	case ProviderGitHub:
		return CredentialGitHubInstallation
	case ProviderOkta:
		return CredentialOktaRefresh
	default:
		return ""
	}
}

func subjectForProvider(provider Provider) SubjectBinding {
	switch provider {
	case ProviderAWS:
		return SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	case ProviderKubernetes:
		return SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/customer"}
	case ProviderGitHub:
		return SubjectBinding{Kind: "github_installation", ID: "123456"}
	case ProviderOkta:
		return SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	default:
		return SubjectBinding{}
	}
}

func validRequest(t *testing.T, provider Provider, class CredentialClass) Request {
	t.Helper()
	return Request{
		Scope: mustScope(t), IntegrationID: mustID(t, "pid_10000001-0000-4000-8000-000000000001"),
		ConnectionID: mustID(t, "pid_10000002-0000-4000-8000-000000000002"), JobID: mustID(t, "pid_10000003-0000-4000-8000-000000000003"),
		Attempt: 1, Provider: provider, CollectorVersion: "collector_v1", CredentialClass: class,
		CredentialReference: "ref:" + string(provider) + "/connection/customer-0001",
		ExpectedSubject:     subjectForProvider(provider),
		Cursor:              Cursor{Provider: provider, Version: "cursor_v1", Value: "initial"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1",
		Bounds: Bounds{MaxPages: 10, MaxItems: 1000, MaxRawBytes: 8 * 1024 * 1024, Timeout: 30 * time.Second},
	}
}

func validManifest(t *testing.T, request Request) RawManifest {
	t.Helper()
	objectReference := mustEvidenceRef(t, "pid_10000006-0000-4000-8000-000000000006")
	objectKey := "organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000006-0000-4000-8000-000000000006"
	object, err := NewRawObject(request.Scope, objectReference, objectKey, "s3-version-object-1", "s3://zasp-evidence/"+objectKey, [32]byte{1}, 128, "application/json", "raw_v1", request.ParserVersion, request.ToolVersion)
	if err != nil {
		t.Fatalf("NewRawObject: %v", err)
	}
	manifestReference := mustEvidenceRef(t, "pid_10000007-0000-4000-8000-000000000007")
	manifestKey := "organizations/pid_10000010-0000-4000-8000-000000000010/workspaces/pid_10000011-0000-4000-8000-000000000011/environments/pid_10000012-0000-4000-8000-000000000012/artifacts/pid_10000007-0000-4000-8000-000000000007"
	manifestObject, err := NewRawObject(request.Scope, manifestReference, manifestKey, "s3-version-manifest-1", "s3://zasp-evidence/"+manifestKey, [32]byte{2}, 256, "application/json", "manifest_v1", request.ParserVersion, request.ToolVersion)
	if err != nil {
		t.Fatalf("NewRawObject manifest: %v", err)
	}
	manifest, err := NewRawManifest(manifestObject, []RawObject{object})
	if err != nil {
		t.Fatalf("NewRawManifest: %v", err)
	}
	return manifest
}

func mustScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(mustID(t, "pid_10000010-0000-4000-8000-000000000010"), mustID(t, "pid_10000011-0000-4000-8000-000000000011"), mustID(t, "pid_10000012-0000-4000-8000-000000000012"))
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	return scope
}

func mustID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", value, err)
	}
	return id
}

func mustEvidenceRef(t *testing.T, value string) domain.EvidenceRef {
	t.Helper()
	reference, err := domain.ParseEvidenceRef(value)
	if err != nil {
		t.Fatalf("ParseEvidenceRef(%q): %v", value, err)
	}
	return reference
}
