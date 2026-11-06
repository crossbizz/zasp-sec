package preflight

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// SQSConfig binds an intended immutable worker image, never caller actions.
type SQSConfig struct {
	Image string `json:"image"`
}
type sqsPermissionWorkload struct {
	Namespace, PodName, PodUID, ServiceAccount, Purpose, Container, Image string
	Env                                                                   map[string]string
	EnvFrom, IndirectEnv                                                  bool
	ReadAttempted                                                         bool
}
type sqsPermissionFootprint struct {
	Purpose, RoleARN, QueueURL, QueueARN string
	Actions                              []string
}
type SQSPermissionDecision struct {
	Action   string `json:"action"`
	Decision string `json:"decision"`
}
type sqsPermissionDecision = SQSPermissionDecision

// Diagnostic policies never establish effective queue or workload authority.
type SQSPermissionDiagnostic struct {
	AuthorityObservation       *Observation            `json:"authority_observation,omitempty"`
	Observation                Observation             `json:"observation"`
	Decisions                  []SQSPermissionDecision `json:"decisions,omitempty"`
	EffectiveAuthorityObserved bool                    `json:"effective_authority_observed"`
}
type sqsPermissionEvaluation struct{ Decisions []sqsPermissionDecision }

type sqsPermissionRequirement struct {
	purpose, topic, container, mode, queueEnv, extraKey, extraValue string
	producer                                                        bool
}

// Fixed original TF policy and chart contract; unsupported roles are unknown.
var sqsPermissionRequirements = [...]sqsPermissionRequirement{
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

func sqsRequirement(purpose string) (sqsPermissionRequirement, bool) {
	for _, row := range sqsPermissionRequirements {
		if row.purpose == purpose {
			return row, true
		}
	}
	return sqsPermissionRequirement{}, false
}
func sqsRequirementActions(row sqsPermissionRequirement) []string {
	if row.producer {
		return []string{"sqs:SendMessage", "sqs:GetQueueAttributes"}
	}
	return []string{"sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"}
}
func validSQSConfig(c *SQSConfig) bool {
	return c == nil || len(c.Image) <= 512 && regexp.MustCompile(`^[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}$`).MatchString(c.Image)
}
func deriveSQSPermissionFootprint(c Config, image SQSConfig, selected AWSSelectedWorkload, observed sqsPermissionWorkload) (sqsPermissionFootprint, error) {
	row, ok := sqsRequirement(selected.Purpose)
	if !ok || !validSQSConfig(&image) || c.AWSAuthority == nil || c.AWSAuthority.Selected == nil || *c.AWSAuthority.Selected != selected || c.Credentials.Kind != "workload_web_identity" || strings.HasPrefix(row.purpose, "aws_iam_role.attack_lab[") && c.Features.AttackLab != "enabled" {
		return sqsPermissionFootprint{}, ErrRejected
	}
	namespace, sa := openSearchSubject(selected.Purpose)
	if namespace == "" || selected.PodName == "" || selected.PodUID == "" || observed.Namespace != namespace || observed.ServiceAccount != sa || observed.PodName != selected.PodName || observed.PodUID != selected.PodUID || observed.Purpose != selected.Purpose || observed.Container != row.container || observed.Image != image.Image || observed.EnvFrom || observed.IndirectEnv || observed.Env["ZASP_WORKER_MODE"] != row.mode || row.extraKey != "" && observed.Env[row.extraKey] != row.extraValue {
		return sqsPermissionFootprint{}, ErrRejected
	}
	role := ""
	for _, binding := range c.AWSAuthority.Roles {
		if binding.Purpose == selected.Purpose {
			if role != "" {
				return sqsPermissionFootprint{}, ErrRejected
			}
			role = binding.RoleARN
		}
	}
	if role == "" || role != c.Credentials.ExpectedRoleARN {
		return sqsPermissionFootprint{}, ErrRejected
	}
	purpose := "consumer"
	if row.producer {
		purpose = "producer"
	}
	expectedARN := "arn:" + c.Deployment.Partition + ":sqs:" + c.Deployment.Region + ":" + c.Deployment.AccountID + ":agentsec-" + row.topic
	var matched *Queue
	for i := range c.AWS.Queues {
		q := &c.AWS.Queues[i]
		if q.ARN == expectedARN || q.URL == observed.Env[row.queueEnv] {
			if matched != nil || q.Purpose != purpose || q.ARN != expectedARN || q.URL != observed.Env[row.queueEnv] || !validQueue(c, q.URL, q.ARN) {
				return sqsPermissionFootprint{}, ErrRejected
			}
			matched = q
		}
	}
	if matched == nil {
		return sqsPermissionFootprint{}, ErrRejected
	}
	return sqsPermissionFootprint{Purpose: row.purpose, RoleARN: role, QueueURL: matched.URL, QueueARN: matched.ARN, Actions: sqsRequirementActions(row)}, nil
}

// This is identity-policy simulation only, not exercised queue authority. The
// caller retains all real write/consume and network observations as unknown.
func simulateSQSQueuePermissions(ctx context.Context, sdk aws.Config, footprint sqsPermissionFootprint) (sqsPermissionEvaluation, error) {
	row, ok := sqsRequirement(footprint.Purpose)
	parts := strings.SplitN(footprint.QueueARN, ":", 6)
	if ctx == nil || ctx.Err() != nil || sdk.HTTPClient == nil || sdk.Credentials == nil || !ok || !reflect.DeepEqual(footprint.Actions, sqsRequirementActions(row)) || len(parts) != 6 || parts[2] != "sqs" || parts[3] != sdk.Region || !accountPattern.MatchString(parts[4]) || parts[5] != "agentsec-"+row.topic || !strings.HasPrefix(footprint.RoleARN, "arn:"+parts[1]+":iam::"+parts[4]+":role/") {
		return sqsPermissionEvaluation{}, ErrRejected
	}
	binding := Config{Deployment: Deployment{Partition: parts[1], Region: parts[3], AccountID: parts[4]}}
	if !partitionRegion(parts[1], parts[3]) || !validQueue(binding, footprint.QueueURL, footprint.QueueARN) {
		return sqsPermissionEvaluation{}, ErrRejected
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, e := iam.NewFromConfig(sdk).SimulatePrincipalPolicy(bounded, &iam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String(footprint.RoleARN), ActionNames: append([]string(nil), footprint.Actions...), ResourceArns: []string{footprint.QueueARN}})
	if e != nil {
		return sqsPermissionEvaluation{}, e
	}
	if bounded.Err() != nil {
		return sqsPermissionEvaluation{}, bounded.Err()
	}
	if out == nil || out.IsTruncated || aws.ToString(out.Marker) != "" || len(out.EvaluationResults) != len(footprint.Actions) {
		return sqsPermissionEvaluation{}, ErrRejected
	}
	decisions := map[string]string{}
	for _, result := range out.EvaluationResults {
		action := aws.ToString(result.EvalActionName)
		requested := false
		for _, a := range footprint.Actions {
			requested = requested || a == action
		}
		if !requested || decisions[action] != "" || len(result.MissingContextValues) != 0 || len(result.EvalDecisionDetails) != 0 || len(result.ResourceSpecificResults) != 1 {
			return sqsPermissionEvaluation{}, ErrRejected
		}
		resource := result.ResourceSpecificResults[0]
		decision := string(resource.EvalResourceDecision)
		if aws.ToString(resource.EvalResourceName) != footprint.QueueARN || len(resource.MissingContextValues) != 0 || len(resource.EvalDecisionDetails) != 0 || string(result.EvalDecision) != decision {
			return sqsPermissionEvaluation{}, ErrRejected
		}
		switch resource.EvalResourceDecision {
		case iamtypes.PolicyEvaluationDecisionTypeAllowed, iamtypes.PolicyEvaluationDecisionTypeExplicitDeny, iamtypes.PolicyEvaluationDecisionTypeImplicitDeny:
		default:
			return sqsPermissionEvaluation{}, ErrRejected
		}
		if decision == "allowed" && (result.PermissionsBoundaryDecisionDetail != nil && !result.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary || resource.PermissionsBoundaryDecisionDetail != nil && !resource.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary || result.OrganizationsDecisionDetail != nil && !result.OrganizationsDecisionDetail.AllowedByOrganizations) {
			return sqsPermissionEvaluation{}, ErrRejected
		}
		decisions[action] = decision
	}
	evaluation := sqsPermissionEvaluation{}
	for _, action := range footprint.Actions {
		decision := decisions[action]
		if decision == "" {
			return sqsPermissionEvaluation{}, ErrRejected
		}
		evaluation.Decisions = append(evaluation.Decisions, sqsPermissionDecision{Action: action, Decision: decision})
	}
	return evaluation, nil
}
