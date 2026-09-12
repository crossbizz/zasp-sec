package sandboxcutover

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This executes the real Node bridge against declared11 controlled kubectl
// resources. It is not the later HTTPS/full-composition or live-cluster proof.
func newQueryObservationFixture(t *testing.T) (*observationFixture, func(string)) {
	t.Helper()
	f := newObservationFixture(t)
	modePath := filepath.Join(filepath.Dir(f.log), "query-mode")
	program, err := os.ReadFile(f.config.KubectlExecutable)
	if err != nil {
		t.Fatal(err)
	}
	queryTemplate := strings.Replace(oldAPITemplate, "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", 1)
	change := `const mode=fs.readFileSync(` + strconv.Quote(modePath) + `,'utf8');if(mode!=='backfill'){
const api=docs.deployment.find(d=>d.metadata.name==='agentsec-api');
const rs=docs.replicaset.find(r=>r.metadata.name==='agentsec-api-rs');
const pod=docs.pod.find(p=>p.metadata.name==='agentsec-api-pod');
const old=structuredClone(rs);old.metadata.name='agentsec-api-old-rs';old.metadata.uid='agentsec-api-old-rs';
const target=` + queryTemplate + `;
api.spec.template=structuredClone(target);api.metadata.resourceVersion='opaque:query/rv';rs.spec.template=structuredClone(target);pod.spec=structuredClone(target.spec);
if(mode==='old-api-replicas')docs.replicaset.push(old);
if(mode==='old-api-pod')pod.spec=` + oldAPITemplate + `.spec;
if(mode==='non-api-template')docs.deployment.find(d=>d.metadata.name==='agentsec-runtime-archive').spec.template.metadata.annotations['fixture-drift']='true';
if(mode==='non-api-image')docs.pod.find(p=>p.metadata.name==='agentsec-runtime-archive-pod').status.containerStatuses[0].imageID='example/archive@sha256:'+ 'b'.repeat(64);
if(mode==='missing-target-worker')docs.deployment=docs.deployment.filter(d=>d.metadata.name!=='agentsec-runtime-session-index-v2');
}
`
	marker := "const a=process.argv.slice(2);"
	if bytes.Count(program, []byte(marker)) != 1 {
		t.Fatal("query fixture insertion boundary changed")
	}
	program = bytes.Replace(program, []byte(marker), []byte(change+marker), 1)
	if err := os.WriteFile(f.config.KubectlExecutable, program, 0700); err != nil {
		t.Fatal(err)
	}
	setMode := func(mode string) {
		if err := os.WriteFile(modePath, []byte(mode), 0600); err != nil {
			t.Fatal(err)
		}
	}
	setMode("query")
	return f, setMode
}

func queryObservationClient(t *testing.T, config ObservationConfig) (*ObservationClient, QueryObserver) {
	t.Helper()
	client, err := NewObservation(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	query, ok := any(client).(QueryObserver)
	if !ok {
		t.Fatal("configured observer lacks the explicit query observation capability")
	}
	return client, query
}

func TestObservationQueryUsesFixedTargetWithFreshReadOnlyBridge(t *testing.T) {
	f, _ := newQueryObservationFixture(t)
	client, query := queryObservationClient(t, f.config)
	expectedBefore, _ := json.Marshal(client.expected)
	for range 2 {
		value, err := query.ObserveQuery(context.Background(), f.config.Binding)
		if err != nil || value.API != (APIIdentity{UID: "agentsec-api-deployment", ResourceVersion: "opaque:query/rv", TemplateDigest: f.config.Binding.To.APITemplateDigest}) || !fresh(value.ObservedAt, time.Now()) || !digest(value.IdentityDigest) {
			t.Fatal("valid query rollout did not yield exact fresh target evidence", value, err)
		}
		if len(client.previous) != 0 {
			t.Fatal("query observation filled backfill cache")
		}
		before, _ := os.ReadFile(f.log)
		if _, err := client.RevalidateBackfill(context.Background(), f.config.Binding, value); err == nil {
			t.Fatal("query snapshot authorized backfill revalidation")
		}
		after, _ := os.ReadFile(f.log)
		if !bytes.Equal(before, after) {
			t.Fatal("query snapshot started backfill revalidation reads")
		}
	}
	expectedAfter, _ := json.Marshal(client.expected)
	if !bytes.Equal(expectedBefore, expectedAfter) {
		t.Fatal("query mutated immutable backfill pins")
	}
	assertQueryObservationReads(t, f.log, 10)
}

func TestObservationQueryRefusesOldReplicasAndOtherConsumerDrift(t *testing.T) {
	for _, mode := range []string{"backfill", "old-api-replicas", "old-api-pod", "non-api-template", "non-api-image", "missing-target-worker"} {
		t.Run(mode, func(t *testing.T) {
			f, setMode := newQueryObservationFixture(t)
			setMode(mode)
			client, query := queryObservationClient(t, f.config)
			if value, err := query.ObserveQuery(context.Background(), f.config.Binding); err == nil || value != (Observation{}) {
				t.Fatal("incomplete or drifted query rollout became evidence", value, err)
			}
			if len(client.previous) != 0 {
				t.Fatal("failed query retained backfill evidence")
			}
			calls, _ := os.ReadFile(f.log)
			if len(calls) == 0 {
				t.Fatal("negative fixture did not reach actual bridge reads")
			}
			assertQueryObservationReads(t, f.log, -1)
		})
	}
}

func TestObservationQueryIgnoresFullBackfillCacheWithoutChangingIt(t *testing.T) {
	f, setMode := newQueryObservationFixture(t)
	setMode("backfill")
	client, query := queryObservationClient(t, f.config)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for range 8 {
		if _, err := client.ObserveBackfill(ctx, f.config.Binding); err != nil {
			t.Fatal("backfill cache setup", err)
		}
	}
	if len(client.previous) != 8 {
		t.Fatal("fixture did not establish a full backfill cache")
	}
	before := make(map[Observation]string, len(client.previous))
	for key, value := range client.previous {
		before[key] = value
	}
	setMode("query")
	if value, err := query.ObserveQuery(ctx, f.config.Binding); err != nil || value.API.TemplateDigest != f.config.Binding.To.APITemplateDigest {
		t.Fatal("full backfill cache blocked query", value, err)
	}
	if !reflect.DeepEqual(before, client.previous) {
		t.Fatal("query read/pruned/changed backfill cache")
	}
	// Expired backfill entries are private cache state too. A query must not
	// run the backfill pruning path even when such an entry is present.
	for key, value := range before {
		delete(before, key)
		delete(client.previous, key)
		key.ObservedAt = time.Now().Add(-time.Minute)
		before[key], client.previous[key] = value, value
		break
	}
	if _, err := query.ObserveQuery(ctx, f.config.Binding); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, client.previous) {
		t.Fatal("query pruned expired backfill evidence")
	}
	assertQueryObservationReads(t, f.log, 50)
}

func TestObservationQueryCancellationJoinsReadAndRemovesCredentials(t *testing.T) {
	f, _ := newQueryObservationFixture(t)
	client, query := queryObservationClient(t, f.config)
	if err := os.WriteFile(f.log+".pause", nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		value Observation
		err   error
	}
	done := make(chan outcome, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("query task did not join")
			}
		}
	})
	go func() { value, err := query.ObserveQuery(ctx, f.config.Binding); done <- outcome{value, err} }()
	entered := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		if _, err := os.Stat(f.log + ".entered"); err == nil {
			entered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !entered {
		t.Fatal("query never reached owned active read")
	}
	cancel()
	select {
	case got := <-done:
		joined = true
		if got.err == nil || got.value != (Observation{}) {
			t.Fatal("canceled query returned evidence", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("query did not stop after cancellation")
	}
	if len(client.previous) != 0 {
		t.Fatal("canceled query retained backfill evidence")
	}
	assertQueryObservationReads(t, f.log, -1)
}

func TestObservationQueryPreservesBoundBindingAndLifetime(t *testing.T) {
	f, _ := newQueryObservationFixture(t)
	client, query := queryObservationClient(t, f.config)
	changed := f.config.Binding
	changed.To.APITemplateDigest = changed.From.APITemplateDigest
	if _, err := query.ObserveQuery(context.Background(), changed); err == nil {
		t.Fatal("caller replaced target pin")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := query.ObserveQuery(canceled, f.config.Binding); err == nil {
		t.Fatal("canceled query accepted")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := query.ObserveQuery(context.Background(), f.config.Binding); err == nil {
		t.Fatal("closed observer admitted query")
	}
	if _, err := os.Stat(f.log); !os.IsNotExist(err) {
		t.Fatal("invalid binding/lifetime started cluster reads")
	}
}

func assertQueryObservationReads(t *testing.T, path string, count int) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if count >= 0 && len(lines) != count {
		t.Fatal("query did not perform the full fresh read sequence", len(lines), count)
	}
	for i, line := range lines {
		var call struct {
			Args       []string
			Kubeconfig string
		}
		if json.Unmarshal([]byte(line), &call) != nil || len(call.Args) < 6 {
			t.Fatal("invalid controlled read log")
		}
		if count >= 0 && call.Args[5] != []string{"namespace", "deployment", "replicaset", "pod", "namespace"}[i%5] {
			t.Fatal("wrong read-only sequence", call.Args)
		}
		if _, err := os.Stat(filepath.Dir(call.Kubeconfig)); !os.IsNotExist(err) {
			t.Fatal("query retained private credentials/request directory")
		}
	}
}
