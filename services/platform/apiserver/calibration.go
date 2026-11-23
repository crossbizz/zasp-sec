package apiserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/calibration"
	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

const calibrationMetricsSQL = "SELECT zasp_authorization80.calibration_metrics($1,$2,$3)"
const suppressionReadSQL = "SELECT zasp_authorization80.calibration_action($1,$2,$3,$4,'getRuleSuppressionMode',$5,NULL,NULL,NULL,NULL)"
const suppressionWriteSQL = "SELECT zasp_authorization80.calibration_action($1,$2,$3,$4,'putRuleSuppressionMode',$5,NULL,$6,$7,$8)"
const analystFeedbackSQL = "SELECT zasp_authorization80.calibration_action($1,$2,$3,$4,'submitAnalystFeedback',$5,$6,$7,NULL,$8)"

func init() {
	productStatementRules[calibrationMetricsSQL] = productStatementRule{operations: []string{"getCalibrationMetrics"}, arguments: 3, scope: 1, browserOnly: true}
	productStatementRules[suppressionReadSQL] = productStatementRule{operations: []string{"getRuleSuppressionMode"}, arguments: 5, scope: 1, actor: 4, browserOnly: true, object: 5, parameter: "ruleId"}
	productStatementRules[suppressionWriteSQL] = productStatementRule{operations: []string{"putRuleSuppressionMode"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, fresh: true, object: 5, parameter: "ruleId"}
	productStatementRules[analystFeedbackSQL] = productStatementRule{operations: []string{"submitAnalystFeedback"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, fresh: true}
}

type analystFeedback struct {
	DecisionID string `json:"decision_id"`
	RuleID     string `json:"rule_id"`
	Label      string `json:"label"`
}

func serveCalibration(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := IdentityFromRequest(r)
	if !ok || id.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	env := id.Scope.EnvironmentID().String()
	args := []any{id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), env}
	if route.OperationID == "getCalibrationMetrics" {
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		raw, err := db.QueryJSON(r.Context(), calibrationMetricsSQL, args...)
		if err != nil {
			writeProductionError(w, r, discoveryProviderError(err))
			return
		}
		serveCalibrationMetrics(w, r, env, raw)
		return
	}
	args = append(args, id.PrincipalID.String())
	query, more := calibrationAction(r, route)
	if query == "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, append(args, more...)...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	case `"invalid"`:
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if route.OperationID != "submitAnalystFeedback" {
		var state struct {
			Rule    string `json:"rule_id"`
			Version int64  `json:"version"`
		}
		if json.Unmarshal(raw, &state) != nil || state.Rule != route.PathParameters["ruleId"] || state.Version < 0 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		w.Header().Set("ETag", quoteVersion(state.Version))
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}

func calibrationAction(r *http.Request, route RoutedOperation) (string, []any) {
	if route.OperationID == "submitAnalystFeedback" {
		keys := r.Header.Values("Idempotency-Key")
		var f analystFeedback
		if r.Method != http.MethodPost || len(keys) != 1 || !validPublicIdempotency(keys[0]) || decodeProductionJSON(r, &f) != nil || !validProductID(f.DecisionID) || !stringIn(f.Label, "confirm_tp", "mark_fp") {
			return "", nil
		}
		if _, ok := guardrail.RuleByID(f.RuleID); !ok {
			return "", nil
		}
		return analystFeedbackSQL, []any{f.RuleID, f.DecisionID, f.Label, keys[0]}
	}
	rule := route.PathParameters["ruleId"]
	if _, ok := guardrail.RuleByID(rule); !ok {
		return "", nil
	}
	if route.OperationID == "getRuleSuppressionMode" && r.Method == http.MethodGet {
		return suppressionReadSQL, []any{rule}
	}
	var in struct {
		Mode string `json:"mode"`
	}
	key, version, ok := discoveryMutationHeaders(r, true)
	if route.OperationID != "putRuleSuppressionMode" || r.Method != http.MethodPut || !ok || decodeProductionJSON(r, &in) != nil || !stringIn(in.Mode, "off", "shadow", "active") {
		return "", nil
	}
	return suppressionWriteSQL, []any{rule, in.Mode, version, key}
}

type recentMatch struct {
	DecisionID string    `json:"decision_id"`
	RuleID     string    `json:"rule_id"`
	Label      *string   `json:"label"`
	OccurredAt time.Time `json:"occurred_at"`
}
type discoveryMeasurement struct {
	calibration.Counts
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
}

func serveCalibrationMetrics(w http.ResponseWriter, r *http.Request, env string, raw json.RawMessage) {
	var db struct {
		Environment string               `json:"environment_id"`
		Labelled    int64                `json:"labelled"`
		Evaluated   int64                `json:"evaluated"`
		Buckets     []calibration.Bucket `json:"buckets"`
		Discovery   calibration.Counts   `json:"discovery"`
		Recent      []recentMatch        `json:"recent"`
	}
	if decodeStrictDiscovery(raw, &db) != nil || db.Environment != env || db.Buckets == nil || db.Recent == nil || len(db.Recent) > 30 || db.Labelled < 0 || db.Evaluated < 0 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	curves, ok := calibration.Compute(db.Buckets)
	if !ok {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	stats := db.Discovery
	writeJSONValue(w, r, http.StatusOK, struct {
		calibration.Curves
		Environment string               `json:"environment_id"`
		Days        int                  `json:"days"`
		Labelled    int64                `json:"labelled"`
		Evaluated   int64                `json:"evaluated"`
		Recent      []recentMatch        `json:"recent"`
		Discovery   discoveryMeasurement `json:"discovery"`
	}{curves, env, 30, db.Labelled, db.Evaluated, db.Recent, discoveryMeasurement{stats, calibration.Ratio(float64(stats.TP), stats.TP+stats.FP), calibration.Ratio(float64(stats.TP), stats.TP+stats.FN)}}, nil)
}
