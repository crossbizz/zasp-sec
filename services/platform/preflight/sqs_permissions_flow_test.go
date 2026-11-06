package preflight

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type sqsPermissionCase struct {
	purpose, queue, container, mode, env, extraKey, extraValue string
	producer                                                   bool
}

// This finite roster is checked against the actual TF/chart contract, not an
// operator-provided action/resource list.
var sqsPermissionCases = []sqsPermissionCase{
	{`aws_iam_role.runtime["outbox"]`, "runtime-events", "runtime-outbox", "runtime-outbox", "ZASP_RUNTIME_QUEUE_URL", "", "", true},
	{`aws_iam_role.runtime["coordinator"]`, "runtime-events", "runtime-coordinator", "runtime-coordinator", "ZASP_RUNTIME_QUEUE_URL", "", "", false},
	{`aws_iam_role.outbox`, "discovery-jobs", "outbox-publisher", "outbox", "ZASP_DISCOVERY_QUEUE_URL", "", "", true},
	{`aws_iam_role.worker`, "discovery-jobs", "discovery-worker", "discovery", "ZASP_DISCOVERY_QUEUE_URL", "", "", false},
	{`aws_iam_role.recovery["recovery_backup_outbox"]`, "recovery-backup-jobs", "worker", "recovery-outbox", "ZASP_RECOVERY_QUEUE_URL", "ZASP_RECOVERY_OUTBOX_TOPIC", "recovery-backup-jobs", true},
	{`aws_iam_role.recovery["recovery_restore_outbox"]`, "recovery-restore-jobs", "worker", "recovery-outbox", "ZASP_RECOVERY_QUEUE_URL", "ZASP_RECOVERY_OUTBOX_TOPIC", "recovery-restore-jobs", true},
	{`aws_iam_role.recovery["recovery_backup"]`, "recovery-backup-jobs", "worker", "recovery", "ZASP_RECOVERY_QUEUE_URL", "ZASP_RECOVERY_OPERATION_KIND", "backup", false},
	{`aws_iam_role.recovery["recovery_restore"]`, "recovery-restore-jobs", "worker", "recovery", "ZASP_RECOVERY_QUEUE_URL", "ZASP_RECOVERY_OPERATION_KIND", "restore", false},
	{`aws_iam_role.red_team["outbox"]`, "red-team-tests", "worker", "red-team-outbox", "ZASP_RED_TEAM_QUEUE_URL", "", "", true},
	{`aws_iam_role.red_team["worker"]`, "red-team-tests", "worker", "red-team", "ZASP_RED_TEAM_QUEUE_URL", "", "", false},
	{`aws_iam_role.attack_lab["outbox"]`, "attack-lab-jobs", "outbox", "attack-lab-outbox", "ZASP_ATTACK_LAB_QUEUE_URL", "", "", true},
	{`aws_iam_role.attack_lab["controller"]`, "attack-lab-jobs", "controller", "attack-lab-controller", "ZASP_ATTACK_LAB_QUEUE_URL", "", "", false},
}

func sqsPermissionFixture(t *testing.T, row sqsPermissionCase) (Config, SQSConfig, AWSSelectedWorkload, sqsPermissionWorkload) {
	t.Helper()
	c := sdkContractConfig(t)
	c.Features.AttackLab = "enabled"
	selected := AWSSelectedWorkload{Purpose: row.purpose, PodName: "selected-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
	_, sa := openSearchSubject(row.purpose)
	image := SQSConfig{Image: "registry.example/worker@sha256:" + strings.Repeat("a", 64)}
	q := Queue{Purpose: "consumer", URL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-" + row.queue, ARN: "arn:aws:sqs:us-west-2:123456789012:agentsec-" + row.queue}
	if row.producer {
		q.Purpose = "producer"
	}
	c.AWS.Queues = []Queue{q}
	c.AWSAuthority = &AWSAuthorityConfig{Selected: &selected, Roles: []AWSRoleBinding{{Purpose: row.purpose, RoleARN: "arn:aws:iam::123456789012:role/selected-worker"}}}
	c.Credentials.Kind = "workload_web_identity"
	c.Credentials.ExpectedRoleARN = "arn:aws:iam::123456789012:role/selected-worker"
	w := sqsPermissionWorkload{Namespace: "agentsec", PodName: selected.PodName, PodUID: selected.PodUID, ServiceAccount: sa, Purpose: row.purpose, Container: row.container, Image: image.Image, Env: map[string]string{"ZASP_WORKER_MODE": row.mode, row.env: q.URL}}
	if row.extraKey != "" {
		w.Env[row.extraKey] = row.extraValue
	}
	return c, image, selected, w
}
func TestSQSSelectedPermissionFootprintUsesOriginalPurposeAndActualLiteralQueue(t *testing.T) {
	for _, row := range sqsPermissionCases {
		t.Run(row.purpose, func(t *testing.T) {
			c, image, selected, w := sqsPermissionFixture(t, row)
			got, e := deriveSQSPermissionFootprint(c, image, selected, w)
			want := []string{"sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"}
			if row.producer {
				want = []string{"sqs:SendMessage", "sqs:GetQueueAttributes"}
			}
			if e != nil || got.Purpose != row.purpose || got.QueueARN != c.AWS.Queues[0].ARN || got.QueueURL != c.AWS.Queues[0].URL || got.RoleARN != c.Credentials.ExpectedRoleARN || !reflect.DeepEqual(got.Actions, want) {
				t.Fatal("actual selected workload did not yield exact original queue action footprint")
			}
		})
	}
	for _, mode := range []string{"foreign-pod", "foreign-sa", "foreign-image", "mutable-image", "oversize-image", "wrong-mode", "wrong-queue", "duplicate-queue", "wrong-purpose", "indirect-env", "envfrom", "missing-operation", "unsupported-purpose", "attack-disabled", "wrong-selected-role"} {
		t.Run(mode, func(t *testing.T) {
			row := sqsPermissionCases[4]
			c, image, selected, w := sqsPermissionFixture(t, row)
			switch mode {
			case "foreign-pod":
				w.PodUID = "44444444-4444-4444-8444-444444444444"
			case "foreign-sa":
				w.ServiceAccount = "foreign"
			case "foreign-image":
				w.Image = "registry.example/foreign@sha256:" + strings.Repeat("b", 64)
			case "mutable-image":
				image.Image = "registry.example/worker:latest"
				w.Image = image.Image
			case "oversize-image":
				image.Image = strings.Repeat("a", 513) + "@sha256:" + strings.Repeat("a", 64)
				w.Image = image.Image
			case "wrong-mode":
				w.Env["ZASP_WORKER_MODE"] = "scheduler"
			case "wrong-queue":
				w.Env[row.env] = strings.ReplaceAll(w.Env[row.env], "123456789012", "999999999999")
			case "duplicate-queue":
				c.AWS.Queues = append(c.AWS.Queues, c.AWS.Queues[0])
			case "wrong-purpose":
				c.AWS.Queues[0].Purpose = "runtime-events"
			case "indirect-env":
				w.IndirectEnv = true
			case "envfrom":
				w.EnvFrom = true
			case "missing-operation":
				delete(w.Env, row.extraKey)
			case "unsupported-purpose":
				selected.Purpose = "aws_iam_role.api"
				w.Purpose = selected.Purpose
			case "attack-disabled":
				c, image, selected, w = sqsPermissionFixture(t, sqsPermissionCases[10])
				c.Features.AttackLab = "disabled"
			case "wrong-selected-role":
				c.Credentials.ExpectedRoleARN = "arn:aws:iam::123456789012:role/foreign"
			}
			if _, e := deriveSQSPermissionFootprint(c, image, selected, w); e == nil {
				t.Fatal("unbound workload accepted a queue permission footprint")
			}
		})
	}
}

type sqsSimulationTransport struct {
	mode    string
	calls   int
	invalid bool
}

func (tr *sqsSimulationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.calls++
	body, _ := io.ReadAll(io.LimitReader(req.Body, 65537))
	form, e := url.ParseQuery(string(body))
	actions := []string{"sqs:SendMessage", "sqs:GetQueueAttributes"}
	queue := "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs"
	if e != nil || req.Method != "POST" || req.URL.Scheme != "https" || req.URL.Host != "iam.amazonaws.com" || req.URL.Path != "/" || form.Get("Action") != "SimulatePrincipalPolicy" || form.Get("PolicySourceArn") != "arn:aws:iam::123456789012:role/selected-worker" || form.Get("ResourceArns.member.1") != queue || form.Get("ResourceArns.member.2") != "" || form.Get("ActionNames.member.1") != actions[0] || form.Get("ActionNames.member.2") != actions[1] || form.Get("ActionNames.member.3") != "" || form.Get("PolicyInputList.member.1") != "" || form.Get("ResourcePolicy") != "" || form.Get("CallerArn") != "" || form.Get("ContextEntries.member.1.ContextKeyName") != "" || !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		tr.invalid = true
	}
	status := 200
	result := ""
	for i, action := range actions {
		if tr.mode == "missing-action" && i == 1 {
			continue
		}
		decision := "allowed"
		if i == 0 && tr.mode == "explicit-deny" {
			decision = "explicitDeny"
		}
		if i == 0 && tr.mode == "implicit-deny" {
			decision = "implicitDeny"
		}
		resourceDecision := decision
		if i == 0 && tr.mode == "contradiction" {
			resourceDecision = "explicitDeny"
		}
		resource := queue
		if tr.mode == "foreign-resource" {
			resource += "-foreign"
		}
		resources := fmt.Sprintf("<member><EvalResourceName>%s</EvalResourceName><EvalResourceDecision>%s</EvalResourceDecision>", resource, resourceDecision)
		if tr.mode == "resource-context" {
			resources += "<MissingContextValues><member>aws:SourceVpce</member></MissingContextValues>"
		}
		if tr.mode == "resource-boundary" {
			resources += "<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>"
		}
		resources += "</member>"
		if tr.mode == "duplicate-resource" {
			resources += resources
		}
		if tr.mode == "missing-resource" {
			resources = ""
		}
		member := "<member><EvalActionName>" + action + "</EvalActionName><EvalResourceName>arn:${Partition}:sqs:${Region}:${Account}:${QueueName}</EvalResourceName><EvalDecision>" + decision + "</EvalDecision><ResourceSpecificResults>" + resources + "</ResourceSpecificResults>"
		if tr.mode == "top-context" {
			member += "<MissingContextValues><member>aws:SourceIp</member></MissingContextValues>"
		}
		if tr.mode == "top-boundary" {
			member += "<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>"
		}
		if tr.mode == "organization-deny" {
			member += "<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>"
		}
		member += "</member>"
		result += member
		if tr.mode == "duplicate-action" && i == 0 {
			result += member
		}
	}
	answer := "<SimulatePrincipalPolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><SimulatePrincipalPolicyResult><EvaluationResults>" + result + "</EvaluationResults>"
	if tr.mode == "truncated" {
		answer += "<IsTruncated>true</IsTruncated><Marker>next</Marker>"
	} else {
		answer += "<IsTruncated>false</IsTruncated>"
	}
	answer += "</SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>"
	if tr.mode == "malformed" {
		answer = "<broken"
	}
	if tr.mode == "http-denied" {
		status = 403
		answer = "<ErrorResponse><Error><Code>AccessDenied</Code><Message>DO_NOT_REFLECT_POLICY_TEXT</Message></Error></ErrorResponse>"
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(answer)), Request: req}, nil
}
func TestSQSOfficialSimulationRequiresCompletePerResourceDecisions(t *testing.T) {
	for _, mode := range []string{"allow-template", "explicit-deny", "implicit-deny", "missing-action", "duplicate-action", "missing-resource", "duplicate-resource", "foreign-resource", "contradiction", "top-context", "resource-context", "top-boundary", "resource-boundary", "organization-deny", "truncated", "malformed", "http-denied"} {
		t.Run(mode, func(t *testing.T) {
			tr := &sqsSimulationTransport{mode: mode}
			sdk := aws.Config{Region: "us-west-2", HTTPClient: &http.Client{Transport: tr}, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture-secret"}, nil
			}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
			f := sqsPermissionFootprint{Purpose: "aws_iam_role.outbox", RoleARN: "arn:aws:iam::123456789012:role/selected-worker", QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", QueueARN: "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs", Actions: []string{"sqs:SendMessage", "sqs:GetQueueAttributes"}}
			got, e := simulateSQSQueuePermissions(context.Background(), sdk, f)
			if tr.calls != 1 || tr.invalid {
				t.Fatal("diagnostic bypassed exact signed official SDK action/resource request")
			}
			known := mode == "allow-template" || mode == "explicit-deny" || mode == "implicit-deny"
			if known {
				want := "allowed"
				if mode == "explicit-deny" {
					want = "explicitDeny"
				}
				if mode == "implicit-deny" {
					want = "implicitDeny"
				}
				if e != nil || len(got.Decisions) != 2 || got.Decisions[0].Action != "sqs:SendMessage" || got.Decisions[0].Decision != want || got.Decisions[1].Decision != "allowed" {
					t.Fatal("complete per-resource diagnostics lost exact action decision")
				}
			} else if e == nil || len(got.Decisions) != 0 {
				t.Fatal("partial or contradictory simulation accepted as permission evidence")
			}
		})
	}
}
