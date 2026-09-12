package sandboxcutover

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

const (
	Complete Rollout = "complete"
	Failed   Rollout = "failed"
)

// QueryObserver is a trusted, constructor-bound full11-consumer observer, not
// caller-supplied evidence or permission to dispatch a transition.
type QueryObserver interface {
	ObserveQuery(context.Context, ReleaseBinding) (Observation, error)
}

type RolloutResult struct {
	Outcome               Outcome
	Rollout               Rollout
	Audit                 Audit
	ResultResourceVersion string
}

// ReconcileSandboxQueryRollout only reads. It cannot retry a PATCH or confer
// authority on a later invocation. Cleanup from the original dispatch is unknown.
func ReconcileSandboxQueryRollout(ctx context.Context, binding ReleaseBinding, audit Audit, client *KubernetesClient, observer QueryObserver) RolloutResult {
	result := RolloutResult{Outcome: Indeterminate, Rollout: Pending, Audit: audit}
	if ctx == nil || ctx.Err() != nil || client == nil || nilValue(observer) || !client.validCall(ctx, binding, audit) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, fenceLifetime)
	defer cancel()
	if client.namespace(ctx) != nil {
		return result
	}
	code, body, err := client.request(ctx, http.MethodGet, client.deploymentPath(), nil)
	if err != nil || code != 200 {
		return result
	}
	applied, err := client.applied(body, audit)
	if err != nil || ctx.Err() != nil {
		return result
	}
	result.Outcome, result.ResultResourceVersion = Applied, applied.API.ResourceVersion
	deployment, err := client.validDeployment(body)
	if err != nil {
		return result
	}
	metadata := deployment["metadata"].(map[string]any)
	status, ok := deployment["status"].(map[string]any)
	generation := rolloutGeneration(metadata["generation"])
	if !ok || generation == 0 || rolloutGeneration(status["observedGeneration"]) != generation {
		return result
	}
	conditions, ok := status["conditions"].([]any)
	if status["conditions"] != nil && !ok {
		return result
	}
	progressing, failed := false, false
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			return result
		}
		kind, ok := condition["type"].(string)
		if !ok || kind == "" {
			return result
		}
		if kind != "Progressing" {
			continue
		}
		if progressing {
			return result
		}
		progressing = true
		state, stateOK := condition["status"].(string)
		reason, reasonOK := condition["reason"].(string)
		if !stateOK || !reasonOK || reason == "" || (state != "True" && state != "False" && state != "Unknown") {
			return result
		}
		failed = state == "False" && reason == "ProgressDeadlineExceeded"
	}
	if ctx.Err() != nil {
		return result
	}
	if failed {
		result.Rollout = Failed
		return result
	}
	observation, err := observer.ObserveQuery(ctx, binding)
	queryBinding := binding
	queryBinding.From.APITemplateDigest = binding.To.APITemplateDigest
	if err != nil || ctx.Err() != nil || !validObservation(observation, queryBinding, time.Now()) || observation.API.UID != audit.APIUID {
		return result
	}
	current, err := client.Reconcile(ctx, binding, audit)
	if err != nil || current.API != observation.API || ctx.Err() != nil || !validObservation(observation, queryBinding, time.Now()) {
		return result
	}
	result.Rollout, result.ResultResourceVersion = Complete, current.API.ResourceVersion
	return result
}

func rolloutGeneration(value any) int64 {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	parsed, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || parsed < 1 {
		return 0
	}
	return parsed
}
