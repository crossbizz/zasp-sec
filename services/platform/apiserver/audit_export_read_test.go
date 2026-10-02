package apiserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are persisted SQL receipt envelopes, not proof of provider contents.
func auditExportReadyReadFixture(t *testing.T, identity RequestIdentity, create AuditExportCreate, ordinal int64) (AuditExportDescriptor, auditExportReadAuthority) {
	t.Helper()
	var descriptor AuditExportDescriptor
	if err := json.Unmarshal(auditExportQueuedFixture(t, identity, create), &descriptor); err != nil {
		t.Fatal(err)
	}
	events, chunks, size := int64(3), int64(2), int64(6000)
	if ordinal == 0 {
		events, chunks, size = 0, 0, 0
	}
	descriptor.Status, descriptor.CapturedAt = "ready", "2026-09-12T10:00:01.000000Z"
	descriptor.EventCount, descriptor.ChunkCount, descriptor.ChunkBytes = &events, &chunks, &size
	descriptor.ManifestSHA256 = strings.Repeat("a", 64)
	binding := audit.ExportBinding{OrganizationID: descriptor.OrganizationID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID, ExportID: create.ExportID, CaptureID: "pid_72000020-0000-4000-8000-000000000020"}
	_, policy := auditExportPolicyFixture(t)
	receipt := func(id, digest string, size int64) auditExportArtifactAuthority {
		return auditExportArtifactAuthority{ArtifactID: id, ObjectReference: "s3://" + policy.Bucket + "/organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/" + id, VersionID: "owned-version-1", SHA256: digest, SizeBytes: size}
	}
	authority := auditExportReadAuthority{StoragePolicy: policy, Binding: binding, Manifest: receipt("pid_72000021-0000-4000-8000-000000000021", descriptor.ManifestSHA256, 512)}
	if ordinal != 0 {
		first, count, previous, bytes := int64(1), int64(2), audit.ExportZeroDigest, int64(4000)
		if ordinal == 2 {
			first, count, previous, bytes = 3, 1, strings.Repeat("c", 64), 2000
		}
		authority.Chunk = &auditExportChunkAuthority{auditExportArtifactAuthority: receipt("pid_72000022-0000-4000-8000-000000000022", strings.Repeat("b", 64), bytes), Ordinal: ordinal, FirstEvent: first, EventCount: count, PreviousDigest: previous}
	}
	return descriptor, authority
}

func auditExportReadEnvelope(t *testing.T, descriptor AuditExportDescriptor, authority any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{"export": descriptor, "authority": authority})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAuditExportReadAcceptsBoundedReadyAuthority(t *testing.T) {
	for _, ordinal := range []int64{0, 1, 2} {
		t.Run([]string{"empty", "first", "later"}[ordinal], func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			descriptor, authority := auditExportReadyReadFixture(t, identity, create, ordinal)
			input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: max(1, ordinal)}
			if ordinal == 2 {
				input.ManifestSHA256, _ = hex.DecodeString(descriptor.ManifestSHA256)
			}
			database.responses[postgresAuditExportGetSQL] = auditExportReadEnvelope(t, descriptor, authority)
			got, err := repository.Get(context.Background(), identity, input)
			if err != nil || got.authority == nil || !reflect.DeepEqual(*got.authority, authority) || !reflect.DeepEqual(got.export, descriptor) {
				t.Fatalf("valid persisted ready authority refused: %v", err)
			}
			if body, err := json.Marshal(got); err != nil || string(body) != `{}` {
				t.Fatal("ready authority leaked through result serialization")
			}
		})
	}
}

func TestAuditExportReadRequiresStoragePolicy(t *testing.T) {
	repository, database, identity, create := auditExportRepositoryFixture(t)
	descriptor, authority := auditExportReadyReadFixture(t, identity, create, 0)
	_, policy := auditExportPolicyFixture(t)
	input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}
	database.responses[postgresAuditExportGetSQL] = auditExportReadEnvelope(t, descriptor, map[string]any{"binding": authority.Binding, "manifest": authority.Manifest, "chunk": nil, "storage_policy": policy})
	if _, err := repository.Get(context.Background(), identity, input); err != nil {
		t.Fatal("valid pinned storage policy rejected", err)
	}
}

func TestAuditExportReadRejectsPolicyArtifactMismatch(t *testing.T) {
	for _, kind := range []string{"bucket", "chunk bucket", "export quota"} {
		t.Run(kind, func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			descriptor, authority := auditExportReadyReadFixture(t, identity, create, 1)
			config, _ := auditExportPolicyFixture(t)
			switch kind {
			case "bucket":
				config.Bucket = "other-export-bucket"
				authority.StoragePolicy.Bucket = config.Bucket
			case "chunk bucket":
				authority.Chunk.ObjectReference = strings.Replace(authority.Chunk.ObjectReference, config.Bucket, "other-export-bucket", 1)
			case "export quota":
				config.MaximumExportBytes = *descriptor.ChunkBytes + authority.Manifest.SizeBytes - 1
				authority.StoragePolicy.MaximumExportBytes = config.MaximumExportBytes
			}
			digest, err := migrations.AuditExportPolicyDigest(config)
			if err != nil {
				t.Fatal(err)
			}
			authority.StoragePolicy.PolicyDigest = digest
			database.responses[postgresAuditExportGetSQL] = auditExportReadEnvelope(t, descriptor, authority)
			if _, err := repository.Get(context.Background(), identity, AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("accepted policy/artifact mismatch", err)
			}
		})
	}
}

func TestAuditExportReadRejectsMismatchedReadyAuthority(t *testing.T) {
	for _, kind := range []string{"binding organization", "binding workspace", "binding environment", "binding export", "capture alias", "capture malformed", "manifest hash", "cursor hash", "zero manifest hash", "manifest empty", "manifest large", "manifest artifact alias", "manifest artifact malformed", "manifest version empty", "manifest version null", "manifest version control", "manifest version unicode", "manifest version long", "wrong object key", "legacy object key", "object query", "object escaped", "object user", "object scheme", "bucket invalid", "chunk missing", "chunk ordinal", "chunk first", "chunk count zero", "chunk count large", "chunk previous", "chunk hash", "chunk empty", "chunk large", "chunk bytes total", "artifact collision", "range beyond total", "nonterminal exhausted", "nonterminal remaining capacity", "later prior missing", "later prior capacity", "terminal short", "terminal previous zero", "empty chunk", "empty later"} {
		t.Run(kind, func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			ordinal := int64(1)
			if strings.HasPrefix(kind, "later ") || strings.HasPrefix(kind, "terminal ") {
				ordinal = 2
			}
			if strings.HasPrefix(kind, "empty ") {
				ordinal = 0
			}
			descriptor, authority := auditExportReadyReadFixture(t, identity, create, ordinal)
			input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: max(1, ordinal)}
			if ordinal == 2 {
				input.ManifestSHA256, _ = hex.DecodeString(descriptor.ManifestSHA256)
			}
			other := "pid_72000099-0000-4000-8000-000000000099"
			switch kind {
			case "binding organization":
				authority.Binding.OrganizationID = other
			case "binding workspace":
				authority.Binding.WorkspaceID = other
			case "binding environment":
				authority.Binding.EnvironmentID = other
			case "binding export":
				authority.Binding.ExportID = other
			case "capture alias":
				authority.Binding.CaptureID = authority.Binding.ExportID
			case "capture malformed":
				authority.Binding.CaptureID = "not-an-id"
			case "manifest hash":
				authority.Manifest.SHA256 = strings.Repeat("b", 64)
			case "cursor hash":
				input.ManifestSHA256 = make([]byte, 32)
				input.ManifestSHA256[0] = 1
			case "zero manifest hash":
				descriptor.ManifestSHA256 = audit.ExportZeroDigest
				authority.Manifest.SHA256 = audit.ExportZeroDigest
			case "manifest empty":
				authority.Manifest.SizeBytes = 0
			case "manifest large":
				authority.Manifest.SizeBytes = 2049
			case "manifest artifact alias":
				authority.Manifest.ArtifactID = authority.Binding.ExportID
			case "manifest artifact malformed":
				authority.Manifest.ArtifactID = "not-an-id"
			case "manifest version empty":
				authority.Manifest.VersionID = ""
			case "manifest version null":
				authority.Manifest.VersionID = "null"
			case "manifest version control":
				authority.Manifest.VersionID = "version\n"
			case "manifest version unicode":
				authority.Manifest.VersionID = "é"
			case "manifest version long":
				authority.Manifest.VersionID = strings.Repeat("v", 1025)
			case "wrong object key":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, authority.Binding.WorkspaceID, other, 1)
			case "legacy object key":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, "/exports/", "/artifacts/", 1)
			case "object query":
				authority.Manifest.ObjectReference += "?versionId=other"
			case "object escaped":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, "exports", "%65xports", 1)
			case "object user":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, "s3://", "s3://user@", 1)
			case "object scheme":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, "s3://", "https://", 1)
			case "bucket invalid":
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, authority.StoragePolicy.Bucket, "UPPERCASE", 1)
			case "chunk missing":
				authority.Chunk = nil
			case "chunk ordinal":
				authority.Chunk.Ordinal = 2
			case "chunk first":
				authority.Chunk.FirstEvent = 2
			case "chunk count zero":
				authority.Chunk.EventCount = 0
			case "chunk count large":
				authority.Chunk.EventCount = 1001
			case "chunk previous":
				authority.Chunk.PreviousDigest = strings.Repeat("c", 64)
			case "chunk hash":
				authority.Chunk.SHA256 = strings.Repeat("B", 64)
			case "chunk empty":
				authority.Chunk.SizeBytes = 0
			case "chunk large":
				authority.Chunk.SizeBytes = 1048577
			case "chunk bytes total":
				authority.Chunk.SizeBytes = 6000
			case "artifact collision":
				authority.Chunk.ArtifactID = authority.Manifest.ArtifactID
			case "range beyond total":
				authority.Chunk.EventCount = 4
			case "nonterminal exhausted":
				authority.Chunk.EventCount = 3
			case "nonterminal remaining capacity":
				*descriptor.EventCount = 2000
			case "later prior missing":
				authority.Chunk.FirstEvent = 1
			case "later prior capacity":
				*descriptor.EventCount = 2000
				authority.Chunk.FirstEvent = 2000
			case "terminal short":
				authority.Chunk.FirstEvent = 2
			case "terminal previous zero":
				authority.Chunk.PreviousDigest = audit.ExportZeroDigest
			case "empty chunk":
				_, populated := auditExportReadyReadFixture(t, identity, create, 1)
				authority.Chunk = populated.Chunk
			case "empty later":
				input.ChunkOrdinal = 2
				input.ManifestSHA256, _ = hex.DecodeString(descriptor.ManifestSHA256)
			}
			database.responses[postgresAuditExportGetSQL] = auditExportReadEnvelope(t, descriptor, authority)
			got, err := repository.Get(context.Background(), identity, input)
			if !errors.Is(err, ErrRepositoryUnavailable) || got.authority != nil || got.export.ID != "" {
				t.Fatal("accepted mismatched persisted authority", err)
			}
		})
	}
}

func TestAuditExportReadRejectsNestedWireAliases(t *testing.T) {
	for _, field := range []string{"binding", "organization_id", "capture_id", "manifest", "artifact_id", "object_reference", "version_id", "sha256", "size_bytes", "chunk", "ordinal", "first_event", "event_count", "previous_digest", "storage_policy", "schema", "policy_id", "policy_digest", "bucket", "expected_bucket_owner", "kms_key_arn", "maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds"} {
		for _, kind := range []string{"alias", "alias overwrite", "duplicate", "missing", "null"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				repository, database, identity, create := auditExportRepositoryFixture(t)
				descriptor, authority := auditExportReadyReadFixture(t, identity, create, 1)
				body := string(auditExportReadEnvelope(t, descriptor, authority))
				// Mutate only the authority, not the descriptor's shared key names.
				wire, err := json.Marshal(authority)
				if err != nil {
					t.Fatal(err)
				}
				original := string(wire)
				key := `"` + field + `":`
				valueStart := strings.Index(original, key) + len(key)
				var raw json.RawMessage
				if err := json.NewDecoder(strings.NewReader(original[valueStart:])).Decode(&raw); err != nil {
					t.Fatal(err)
				}
				valueEnd := valueStart + len(raw)
				switch kind {
				case "alias":
					wire = []byte(strings.Replace(original, key, `"`+strings.ToUpper(field)+`":`, 1))
				case "duplicate":
					wire = []byte(strings.Replace(original, key, key+`null,`+key, 1))
				case "alias overwrite":
					wire = []byte(strings.Replace(original, key, key+`null,"`+strings.ToUpper(field)+`":`, 1))
				case "missing":
					start, end := valueStart-len(key), valueEnd
					if original[end] == ',' {
						end++
					} else {
						start--
					}
					wire = []byte(original[:start] + original[end:])
				case "null":
					wire = []byte(original[:valueStart] + `null` + original[valueEnd:])
				}
				body = strings.Replace(body, original, string(wire), 1)
				database.responses[postgresAuditExportGetSQL] = json.RawMessage(body)
				if got, err := repository.Get(context.Background(), identity, AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}); !errors.Is(err, ErrRepositoryUnavailable) || got.authority != nil {
					t.Fatal("accepted nonclosed authority JSON", err)
				}
			})
		}
	}
}

func TestAuditExportReadReadyBoundsAndImmutableScope(t *testing.T) {
	for _, kind := range []string{"maximum chunk", "org-wide stored scope", "pinned empty", "jsonb whitespace", "query-selected chunk receipt alias"} {
		t.Run(kind, func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			ordinal := int64(1)
			if kind == "pinned empty" {
				ordinal = 0
			}
			descriptor, authority := auditExportReadyReadFixture(t, identity, create, ordinal)
			input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}
			switch kind {
			case "maximum chunk":
				*descriptor.EventCount, *descriptor.ChunkCount, *descriptor.ChunkBytes = 1000, 1, 1048576
				authority.Chunk.EventCount, authority.Chunk.SizeBytes = 1000, 1048576
				authority.Manifest.SizeBytes = 2048
				authority.Manifest.VersionID = strings.Repeat("v", 1024)
			case "org-wide stored scope":
				stored := "pid_72000090-0000-4000-8000-000000000090"
				authority.Manifest.ObjectReference = strings.Replace(authority.Manifest.ObjectReference, descriptor.WorkspaceID, stored, 1)
				authority.Chunk.ObjectReference = strings.Replace(authority.Chunk.ObjectReference, descriptor.WorkspaceID, stored, 1)
				descriptor.WorkspaceID, authority.Binding.WorkspaceID = stored, stored
			case "pinned empty":
				input.ManifestSHA256, _ = hex.DecodeString(descriptor.ManifestSHA256)
			}
			body := auditExportReadEnvelope(t, descriptor, authority)
			if kind == "jsonb whitespace" {
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, body, "", "  "); err != nil {
					t.Fatal(err)
				}
				body = pretty.Bytes()
			}
			if kind == "query-selected chunk receipt alias" {
				chunk, _ := json.Marshal(authority.Chunk)
				aliased := bytes.Replace(chunk, []byte(`"version_id":`), []byte(`"VERSION_ID":`), 1)
				body = bytes.Replace(body, chunk, aliased, 1)
			}
			database.responses[postgresAuditExportGetSQL] = body
			got, err := repository.Get(context.Background(), identity, input)
			if kind == "query-selected chunk receipt alias" {
				if !errors.Is(err, ErrRepositoryUnavailable) {
					t.Fatal("chunk receipt alias accepted", err)
				}
				return
			}
			if err != nil || got.authority == nil || !reflect.DeepEqual(got.export, descriptor) || !reflect.DeepEqual(*got.authority, authority) {
				t.Fatal("valid bounded authority refused", err)
			}
		})
	}
}

func TestAuditExportReadBindsCurrentSessionWithoutFreshness(t *testing.T) {
	repository, database, identity, create := auditExportRepositoryFixture(t)
	identity.FreshAuthenticated = false
	input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}
	database.responses[postgresAuditExportGetSQL] = append(append(json.RawMessage(`{"export":`), database.responses[postgresAuditExportCreateSQL]...), []byte(`,"authority":null}`)...)
	got, err := repository.Get(context.Background(), identity, input)
	if err != nil || got.export.ID != input.ExportID || got.authority != nil {
		t.Fatalf("read: %#v %v", got, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.SessionDigest, identity.CSRFToken, input.ExportID, int64(1), []byte(nil), repository.checksum, repository.fingerprint}
	if database.query != postgresAuditExportGetSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatal("read lost exact authority arguments")
	}
	if body, err := json.Marshal(got); err != nil || string(body) != `{}` {
		t.Fatal("private read result can leak through HTTP serialization")
	}
}

func TestAuditExportReadRefusesInvalidCursorBeforeQuery(t *testing.T) {
	for _, kind := range []string{"zero ordinal", "later unpinned", "short pin", "zero pin", "bearer", "permission", "digest"} {
		t.Run(kind, func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			input := AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}
			switch kind {
			case "zero ordinal":
				input.ChunkOrdinal = 0
			case "later unpinned":
				input.ChunkOrdinal = 2
			case "short pin":
				input.ManifestSHA256 = []byte{1}
			case "zero pin":
				input.ManifestSHA256 = make([]byte, 32)
			case "bearer":
				identity.CredentialKind = CredentialBearerToken
			case "permission":
				identity.Permissions = nil
			case "digest":
				input.SessionDigest = nil
			}
			before := len(database.queries)
			if _, err := repository.Get(context.Background(), identity, input); err == nil || len(database.queries) != before {
				t.Fatal("invalid read queried provider", err)
			}
		})
	}
}

func TestAuditExportReadCancellationAtResponseBoundary(t *testing.T) {
	repository, database, identity, create := auditExportRepositoryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	database.responses[postgresAuditExportGetSQL] = append(append(json.RawMessage(`{"export":`), database.responses[postgresAuditExportCreateSQL]...), []byte(`,"authority":null}`)...)
	repository.database = &cancelingAuditExportDatabase{discoveryCallDatabase: database, cancel: cancel, queryToCancel: postgresAuditExportGetSQL}
	if _, err := repository.Get(ctx, identity, AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled response accepted", err)
	}
}

func TestAuditExportReadPreservesOrganizationWideArtifactScope(t *testing.T) {
	repository, database, identity, create := auditExportRepositoryFixture(t)
	body := string(database.responses[postgresAuditExportCreateSQL])
	storedWorkspace := "pid_72000010-0000-4000-8000-000000000010"
	body = strings.Replace(body, identity.Scope.WorkspaceID().String(), storedWorkspace, 1)
	database.responses[postgresAuditExportGetSQL] = json.RawMessage(`{"export":` + body + `,"authority":null}`)
	got, err := repository.Get(context.Background(), identity, AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1})
	if err != nil || got.export.WorkspaceID != storedWorkspace {
		t.Fatal("organization-wide read rewrote or refused immutable scope", err)
	}
	if database.args[1] != identity.Scope.WorkspaceID().String() {
		t.Fatal("read substituted artifact scope for current session scope")
	}
}

func TestAuditExportReadRejectsUntrustedEnvelope(t *testing.T) {
	for _, kind := range []string{"duplicate", "alias", "missing", "extra", "foreign organization", "different export", "pending authority", "null export", "trailing", "oversized", "unverified ready"} {
		t.Run(kind, func(t *testing.T) {
			repository, database, identity, create := auditExportRepositoryFixture(t)
			body := `{"export":` + string(database.responses[postgresAuditExportCreateSQL]) + `,"authority":null}`
			switch kind {
			case "duplicate":
				body = strings.Replace(body, `"authority":null`, `"authority":{},"authority":null`, 1)
			case "alias":
				body = strings.Replace(body, `"export":`, `"Export":`, 1)
			case "missing":
				body = `{"export":` + string(database.responses[postgresAuditExportCreateSQL]) + `}`
			case "extra":
				body = strings.Replace(body, `{"export":`, `{"private":null,"export":`, 1)
			case "foreign organization":
				body = strings.Replace(body, identity.Scope.OrganizationID().String(), "pid_72000011-0000-4000-8000-000000000011", 1)
			case "different export":
				body = strings.Replace(body, create.ExportID, "pid_72000012-0000-4000-8000-000000000012", 1)
			case "pending authority":
				body = strings.Replace(body, `"authority":null`, `"authority":{}`, 1)
			case "null export":
				body = `{"export":null,"authority":null}`
			case "trailing":
				body += `{}`
			case "oversized":
				body += strings.Repeat(" ", 16384)
			case "unverified ready":
				body = strings.Replace(body, `"status":"queued","event_count":null`, `"status":"ready","event_count":0,"captured_at":"2026-09-12T10:00:01.000000Z","chunk_count":0,"chunk_bytes":0,"manifest_sha256":"`+strings.Repeat("a", 64)+`"`, 1)
			}
			database.responses[postgresAuditExportGetSQL] = json.RawMessage(body)
			if _, err := repository.Get(context.Background(), identity, AuditExportRead{ExportID: create.ExportID, SessionDigest: create.SessionDigest, ChunkOrdinal: 1}); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("accepted untrusted read envelope", err)
			}
		})
	}
}
