package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The actual Node artifact builder consumes the original persisted input and
// receipts from the completed HTTPS invocation. Native validation is separate.
func assertWorkerRecoveredArtifactNative(t *testing.T, ctx context.Context, owner *pgx.Conn, child string) {
	t.Helper()
	var comparisonDigest string
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.test_comparison_binding(jsonb_build_object('schema_version','red-team-target-comparison-v1','organization_id','pid_99400001-0000-4000-8000-000000000001','workspace_id','pid_99400002-0000-4000-8000-000000000002','environment_id','pid_99400003-0000-4000-8000-000000000003','test_definition_id','pid_99400004-0000-4000-8000-000000000004','test_definition_version',7,'target_id','pid_99400005-0000-4000-8000-000000000005','target_kind','agent_endpoint','categories','["prompt_injection","tool_abuse"]'::jsonb,'safety_digest',repeat('a',64),'endpoint_digest',repeat('b',64),'configuration_digest',repeat('c',64),'credential_binding_id','pid_99400006-0000-4000-8000-000000000006','credential_binding_version',11,'credential_binding_digest',repeat('d',64)))`).Scan(&comparisonDigest); err != nil || comparisonDigest != "35b24189b40cce9e16339d0380cfe8a5fb8d38ef216990df5b79fd1914d47309" {
		t.Fatal("native independently pinned comparison encoding", err)
	}
	var o, w, e, parent, step string
	var inputBody []byte
	var manifest, authority, receipts json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,i.body,i.manifest,
 jsonb_build_object('parent_run_id',i.run_id,'step_id',i.step_id,'generation',1,'effect_key',x.effect_key)
 FROM zasp_temporal74.test_inputs i JOIN zasp_temporal74.effects x USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE i.test_run_id=$1`, child).Scan(&o, &w, &e, &parent, &step, &inputBody, &manifest, &authority); err != nil {
		t.Fatal("recovered original input", err)
	}
	if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'parent_run_id',x.run_id,'test_run_id',j.test_run_id,'step_id',x.step_id,'effect_key',j.effect_key,'category',j.category,'attempt',j.attempt,'state',j.state,'request_digest',encode(j.request_digest,'hex'),'response_digest',encode(j.response_digest,'hex'),'http_status',j.http_status,'protected',j.protected,'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_digest',encode(j.input_digest,'hex'),'generation',1,'captured_resolution_digest',encode(digest(convert_to(j.target_resolution::text,'UTF8'),'sha256'),'hex')) ORDER BY c.ordinality)
 FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id)
 JOIN public.zasp_security_agent_test_links l ON(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)
 CROSS JOIN LATERAL jsonb_array_elements_text(l.test_categories) WITH ORDINALITY c(category,ordinality) WHERE j.test_run_id=$1 AND j.category=c.category`, child).Scan(&receipts); err != nil {
		t.Fatal("recovered native receipt set", err)
	}
	module, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"input": json.RawMessage(inputBody), "authority": authority, "receipts": receipts})
	command := exec.CommandContext(ctx, "node", "--input-type=module", "-e", `import {pathToFileURL} from 'node:url';let s='';for await(const b of process.stdin)s+=b;const q=JSON.parse(s);const r=await import(pathToFileURL(process.argv[2]));process.stdout.write(JSON.stringify(r.buildCompletedReceiptArtifact(q.input,q.authority,q.receipts)));`, "owned-fixture", module)
	command.Stdin = bytes.NewReader(request)
	intermediate, err := command.Output()
	if err != nil {
		t.Fatal("actual Node recovered artifact", err)
	}
	var artifact map[string]json.RawMessage
	if json.Unmarshal(intermediate, &artifact) != nil || len(artifact) != 6 {
		t.Fatal("recovered intermediate shape")
	}
	artifact["input_artifact"] = manifest
	body, _ := json.Marshal(artifact)
	digest := sha256.Sum256(body)
	outputManifest, _ := json.Marshal(map[string]any{"reference": "s3://worker-artifacts/organizations/" + o + "/workspaces/" + w + "/environments/" + e + "/artifacts/" + child, "version_id": "recovered-v1", "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(body)})
	var summary json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT zasp_temporal74.test_validate_output($1,$2,$3,$4,$5,$6::jsonb,$7::bytea,$8::jsonb,$9::bytea)`, o, w, e, parent, step, manifest, inputBody, outputManifest, body).Scan(&summary); err != nil {
		t.Fatal("actual Node recovered artifact native validation", err)
	}
	var value struct {
		Schema  string `json:"schema_version"`
		Verdict string `json:"verdict"`
	}
	if json.Unmarshal(summary, &value) != nil || value.Schema != "red-team-completed-evidence-v1" || value.Verdict != "pass" {
		t.Fatal("native recovered summary")
	}
	// Recompute the manifest hash/size for every changed body. These cases must
	// fail the native evidence binding, not merely the outer artifact checksum.
	mutations := []string{"schema_version", "run_id", "input_digest", "input_artifact", "captured_evaluation_identity", "summary", "receipts", "extra", "duplicate", "trailing", "image", "engine", "check", "summary_verdict"}
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "parent_run_id", "test_run_id", "step_id", "effect_key", "generation", "category", "input_digest", "request_digest", "state", "attempt", "http_status", "protected", "response_digest", "credential_version_digest", "completed_at", "captured_resolution_digest"} {
		mutations = append(mutations, "receipt_"+field)
	}
	for _, mutation := range mutations {
		t.Run("native_recovered_artifact_"+mutation, func(t *testing.T) {
			var doc map[string]any
			if json.Unmarshal(body, &doc) != nil {
				t.Fatal("valid recovered body")
			}
			switch {
			case strings.HasPrefix(mutation, "receipt_"):
				doc["receipts"].([]any)[0].(map[string]any)[strings.TrimPrefix(mutation, "receipt_")] = nil
			case mutation == "extra":
				doc["unexpected"] = true
			case mutation == "image":
				doc["captured_evaluation_identity"].(map[string]any)["runner_image_digest"] = "sha256:" + strings.Repeat("0", 64)
			case mutation == "engine":
				doc["captured_evaluation_identity"].(map[string]any)["engine_version"] = "0.0.0"
			case mutation == "check":
				doc["captured_evaluation_identity"].(map[string]any)["checks"].([]any)[0].(map[string]any)["assertion_digest"] = strings.Repeat("0", 64)
			case mutation == "summary_verdict":
				doc["summary"].(map[string]any)["verdict"] = "fail"
			case mutation == "duplicate", mutation == "trailing":
			default:
				doc[mutation] = nil
			}
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "duplicate" {
				changed = append([]byte(`{"schema_version":"red-team-completed-receipts-v1",`), changed[1:]...)
			}
			if mutation == "trailing" {
				changed = append(changed, []byte(` {}`)...)
			}
			hash := sha256.Sum256(changed)
			var changedManifest map[string]any
			if json.Unmarshal(outputManifest, &changedManifest) != nil {
				t.Fatal("valid output manifest")
			}
			changedManifest["sha256"], changedManifest["size_bytes"] = hex.EncodeToString(hash[:]), len(changed)
			encodedManifest, _ := json.Marshal(changedManifest)
			var refused json.RawMessage
			err = owner.QueryRow(ctx, `SELECT zasp_temporal74.test_validate_output($1,$2,$3,$4,$5,$6::jsonb,$7::bytea,$8::jsonb,$9::bytea)`, o, w, e, parent, step, manifest, inputBody, encodedManifest, changed).Scan(&refused)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "22023" && native.Code != "40001" {
				t.Fatalf("native changed evidence refusal: %v", err)
			}
		})
	}
}

func runWorkerRecoveredProductChild(t *testing.T, ctx context.Context, owner *pgx.Conn, parent string) {
	runWorkerTest74ProductChild(t, ctx, owner, parent, "TestP7WorkerSingleTestRecoveredProductNative")
}

func runWorkerTest74ProductChild(t *testing.T, ctx context.Context, owner *pgx.Conn, parent, name string) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "recovered-product-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../agentsec-worker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("recovered product build: %v\n%s", err, output)
	}
	child := exec.CommandContext(ctx, binary, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ZASP_") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "ZASP_P7_WORKER_OWNER_DSN="+owner.Config().ConnString(), "ZASP_P7_WORKER_PARENT="+parent)
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("actual recovered product child: %v\n%s", err, output)
	}
	t.Logf("actual recovered product child joined: %s", output)
}
