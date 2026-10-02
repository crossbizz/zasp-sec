package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentRuntimeOutboxUsesClosedPrivateLifecycle(t *testing.T) {
	db := &discoveryCallDatabase{responses: map[string]json.RawMessage{`SELECT to_jsonb(zasp_authorization80_runtime.ready($1,$2))`: json.RawMessage(`true`)}}
	repository, err := NewCurrentRuntimeOutboxRepository(db)
	if err != nil {
		t.Fatal("current profile constructor rejected", err, db.queries)
	}
	identity := fixtureRequestIdentity(t)
	id := "pid_75000003-0000-4000-8000-000000000003"
	_, _ = repository.ClaimOutboxTopic(context.Background(), RuntimeOutboxTopic, "current-worker", "current-worker-token", 30, 1)
	_, _ = repository.HeartbeatOutboxTopic(context.Background(), RuntimeOutboxTopic, "current-worker", "current-worker-token", 30, 1)
	_, _ = repository.AcknowledgeOutboxTopic(context.Background(), RuntimeOutboxTopic, identity.Scope, id, "current-worker", "current-worker-token", "sha256:"+strings.Repeat("a", 64))
	_, _ = repository.RetryOutboxTopic(context.Background(), RuntimeOutboxTopic, identity.Scope, id, "current-worker", "current-worker-token", 30, "queue_publish_unknown")
	if len(db.queries) != 9 {
		t.Fatal("publication lost fresh mutation admission", db.queries)
	}
	for _, q := range db.queries {
		if !strings.Contains(q, "zasp_authorization80_runtime.") {
			t.Fatal("publication escaped current profile", q)
		}
	}
	db.responses[`SELECT to_jsonb(zasp_authorization80_runtime.ready($1,$2))`] = json.RawMessage(`false`)
	before := len(db.queries)
	if _, err := repository.ClaimOutboxTopic(context.Background(), RuntimeOutboxTopic, "current-worker", "current-worker-token", 30, 1); err == nil || len(db.queries) != before+1 {
		t.Fatal("closed current publication fell back", err, db.queries)
	}
}
