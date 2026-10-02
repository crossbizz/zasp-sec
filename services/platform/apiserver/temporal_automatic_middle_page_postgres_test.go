package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestTemporalAutomaticMiddlePagePostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE middle_page_executor LOGIN;CREATE ROLE middle_page_compensation LOGIN;SELECT zasp_temporal68.register_principals('middle_page_executor','middle_page_compensation');SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":86400,"enabled":true}');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 26; i++ {
			createAutomaticPageDefinition(t, ctx, api, o, w, e, actor, automaticSourceID(9000+i*20), base, 9001+i*20)
		}
		finding := automaticSourceID(9600)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Native page fixture','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		var event string
		if err := owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE source_id=$1`, finding).Scan(&event); err != nil {
			t.Fatal(err)
		}
		ref := orchestration.AutomaticSourceRef{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, EventID: event}
		rawRef, _ := json.Marshal(ref)
		namespace := fmt.Sprintf("automatic-pages77-%d", time.Now().UnixNano())
		nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
		if err != nil {
			t.Fatal(err)
		}
		err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
		nc.Close()
		if err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(t.TempDir(), "automatic-worker.test")
		build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "./agentsec-worker")
		build.Dir = ".."
		build.WaitDelay = 5 * time.Second
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatal("owned worker binary build", string(output), err)
		}
		dsn, err := url.Parse(owner.Config().ConnString())
		if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") {
			t.Fatal("owned fixture requires PostgreSQL URL", err)
		}
		dsn.User = url.User("middle_page_executor")
		env := append(os.Environ(), "ZASP_TEST77_PAGE_DSN="+dsn.String(), "ZASP_TEST77_PAGE_REF="+string(rawRef), "ZASP_TEST77_NAMESPACE="+namespace, "ZASP_TEST77_ADDRESS=127.0.0.1:7233")
		command := func(phase string) *exec.Cmd {
			c := exec.CommandContext(ctx, binary, "-test.run=^TestTemporalAutomaticMiddlePageWorker$", "-test.v", "-test.timeout=5m")
			c.Env = append(append([]string{}, env...), "ZASP_TEST77_PAGE_PHASE="+phase)
			c.WaitDelay = 5 * time.Second
			return c
		}
		first := command("block")
		pipe, err := first.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		first.Stderr = &stderr
		if err := first.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		readDone := make(chan struct{})
		var output bytes.Buffer
		go func() {
			defer close(readDone)
			scanner := bufio.NewScanner(pipe)
			seen := false
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Fprintln(&output, line)
				if line == "AUTOMATIC77_MIDDLE_PAGE_READY" && !seen {
					seen = true
					close(ready)
				}
			}
		}()
		joined := false
		defer func() {
			if !joined {
				_ = first.Process.Kill()
				_ = first.Wait()
				<-readDone
			}
		}()
		select {
		case <-ready:
		case <-readDone:
			t.Fatal("owned first worker exited before middle page", output.String(), stderr.String())
		case <-ctx.Done():
			t.Fatal("middle-page barrier deadline", ctx.Err())
		}
		var firstCount, accepted int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal77.occurrences WHERE event_id=$1 AND disposition='admitted'),(SELECT count(*) FROM zasp_temporal77.source_acceptances WHERE event_id=$1)`, event).Scan(&firstCount, &accepted); err != nil || firstCount != 5 || accepted != 1 {
			t.Fatal("not a committed acknowledged middle page", firstCount, accepted, err)
		}
		temporalClient, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
		if err != nil {
			t.Fatal(err)
		}
		defer temporalClient.Close()
		workflowID, _ := orchestration.AutomaticSourceWorkflowID(ref)
		before, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
		if err != nil {
			t.Fatal(err)
		}
		originalRun := before.WorkflowExecutionInfo.GetExecution().GetRunId()
		history := temporalClient.GetWorkflowHistory(ctx, workflowID, originalRun, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
		completedPage := false
		for history.HasNext() {
			ev, err := history.Next()
			if err != nil {
				t.Fatal(err)
			}
			if ev.GetActivityTaskCompletedEventAttributes() != nil {
				completedPage = true
			}
		}
		if !completedPage {
			t.Fatal("first page has no completed native Activity history")
		}
		// Exact PID belongs to the directly spawned test binary. The retained
		// Temporal server and PostgreSQL are untouched by this injected crash.
		pid := first.Process.Pid
		if err := first.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		waitErr := first.Wait()
		<-readDone
		joined = true
		if waitErr == nil {
			t.Fatal("owned crash process unexpectedly exited cleanly")
		}
		t.Logf("joined intentionally killed owned worker pid=%d after first5 receipts: %v\n%s\n%s", pid, waitErr, output.String(), stderr.String())
		second := command("recover")
		recovered, err := second.CombinedOutput()
		t.Log(string(recovered))
		if err != nil || !strings.Contains(string(recovered), "--- PASS: TestTemporalAutomaticMiddlePageWorker") || strings.Contains(string(recovered), "--- SKIP:") {
			t.Fatal("replacement worker did not finish native pages", err)
		}
		after, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
		if err != nil || after.WorkflowExecutionInfo.GetExecution().GetWorkflowId() != workflowID || after.WorkflowExecutionInfo.GetExecution().GetRunId() != originalRun || after.WorkflowExecutionInfo.GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED {
			t.Fatal("replacement opened a new logical execution", err)
		}
		var occurrences, runs, receipts, last int
		if err := owner.QueryRow(ctx, `SELECT count(*),count(DISTINCT run_id),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE trigger_id=$2),count(*) FILTER(WHERE definition_id=$3) FROM zasp_temporal77.occurrences WHERE event_id=$1 AND disposition='admitted'`, event, finding, automaticSourceID(9500)).Scan(&occurrences, &runs, &receipts, &last); err != nil || occurrences != 26 || runs != 26 || receipts != 26 || last != 1 {
			t.Fatal("native restart skipped26th or duplicated admission", occurrences, runs, receipts, last, err)
		}
		t.Log("native middle-page process crash recovered all26 definitions with one receipt each", namespace)
	})
}
