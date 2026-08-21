package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var globalSearchQueryPattern = regexp.MustCompile(`^[A-Za-z0-9 .:_/-]{2,128}$`)

type riskRepository interface {
	coreRepository
	GetRiskFinding(context.Context, domain.Scope, string) (RiskFinding, error)
	ListRiskFindingPage(context.Context, domain.Scope, string, int) (RiskFindingPage, error)
	GetRiskAttackPath(context.Context, domain.Scope, string) (RiskAttackPath, error)
	ListRiskAttackPathPage(context.Context, domain.Scope, string, int) (RiskAttackPathPage, error)
	GetRiskBreakOptions(context.Context, domain.Scope, string) ([]RiskBreakOption, error)
	CountHighRiskPaths(context.Context, domain.Scope) (int64, error)
	MutateRiskFinding(context.Context, RequestIdentity, RiskFindingMutation) (RiskFindingMutationResult, error)
	SearchGlobal(context.Context, domain.Scope, string, int) (GlobalSearchPage, error)
}

type FindingTicket struct {
	TicketID string `json:"ticket_id"`
}

type FindingTicketCommand struct {
	Identity        RequestIdentity
	FindingID       string
	ExpectedVersion int64
	IdempotencyKey  string
	CorrelationID   string
}

type FindingTicketCreator interface {
	CreateFindingTicket(context.Context, FindingTicketCommand) (FindingTicket, error)
}

type FindingTicketCreatorFunc func(context.Context, FindingTicketCommand) (FindingTicket, error)

func (creator FindingTicketCreatorFunc) CreateFindingTicket(ctx context.Context, command FindingTicketCommand) (FindingTicket, error) {
	return creator(ctx, command)
}

type riskHTTPHandler struct {
	repository riskRepository
	tickets    FindingTicketCreator
	signingKey []byte
	now        func() time.Time
}

func newRiskHTTPHandler(repository riskRepository, signingKey []byte, now func() time.Time, tickets FindingTicketCreator) (*riskHTTPHandler, error) {
	if nilInterface(repository) || nilInterface(tickets) || len(signingKey) < 32 || len(signingKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if now().IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return &riskHTTPHandler{repository: repository, tickets: tickets, signingKey: append([]byte(nil), signingKey...), now: now}, nil
}

func (handler *riskHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "getHomeSummary":
		handler.home(writer, request, identity)
	case "listFindings":
		handler.findingPage(writer, request, identity, routed)
	case "getFinding":
		handler.finding(writer, request, identity, routed)
	case "updateFinding", "acceptFindingRisk":
		handler.mutateFinding(writer, request, identity, routed)
	case "createFindingTicket":
		handler.createFindingTicket(writer, request, identity, routed)
	case "listAttackPaths":
		handler.pathPage(writer, request, identity, routed)
	case "getAttackPath":
		handler.path(writer, request, identity, routed)
	case "getAttackPathBreakOptions":
		handler.breakOptions(writer, request, identity, routed)
	case "globalSearch":
		handler.globalSearch(writer, request, identity)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *riskHTTPHandler) createFindingTicket(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id := routed.PathParameters["id"]
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || !validProductID(id) || request.ContentLength != 0 || request.Header.Get("Content-Type") != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) {
		writeProductionStatusError(writer, request, http.StatusBadRequest, "operation_rejected", "Operation rejected", false)
		return
	}
	expectedVersion, err := parseVersion(request.Header.Get("If-Match"))
	if err != nil {
		writeWorkflowMutationError(writer, request, errPreconditionRequired)
		return
	}
	ticket, err := handler.tickets.CreateFindingTicket(request.Context(), FindingTicketCommand{Identity: identity, FindingID: id, ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey, CorrelationID: correlationIDFromContext(request.Context())})
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	if len(ticket.TicketID) < 1 || len(ticket.TicketID) > 128 || strings.TrimSpace(ticket.TicketID) != ticket.TicketID {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(writer, request, http.StatusCreated, ticket, nil)
}

func (handler *riskHTTPHandler) globalSearch(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"q": 128, "limit": 3})
	values, present := query["q"]
	if !ok || !present || len(values) != 1 || strings.TrimSpace(values[0]) != values[0] || !globalSearchQueryPattern.MatchString(values[0]) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit := 20
	if limits, present := query["limit"]; present {
		if len(limits) != 1 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		parsed, err := strconv.Atoi(limits[0])
		if err != nil || parsed < 1 || parsed > 100 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		limit = parsed
	}
	page, err := handler.repository.SearchGlobal(request.Context(), identity.Scope, values[0], limit)
	writeJSONValue(writer, request, http.StatusOK, page, err)
}

func (handler *riskHTTPHandler) home(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	payload, err := handler.repository.Read(request.Context(), identity.Scope, "home")
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	count, err := handler.repository.CountHighRiskPaths(request.Context(), identity.Scope)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var summary map[string]any
	if decodeStrictRisk(payload, &summary) != nil || summary == nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	summary["high_risk_paths"] = count
	writeJSONValue(writer, request, http.StatusOK, summary, nil)
}

type riskCursorPayload struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	Operation      string `json:"op"`
	Limit          int    `json:"l"`
	AfterID        string `json:"a"`
}

func (handler *riskHTTPHandler) findingPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	query, afterID, limit, ok := handler.riskPageQuery(request, identity.Scope, routed.OperationID)
	_ = query
	if !ok {
		writeRiskCursorError(writer, request)
		return
	}
	page, err := handler.repository.ListRiskFindingPage(request.Context(), identity.Scope, afterID, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	handler.writeRiskPage(writer, request, identity.Scope, routed.OperationID, limit, page.Items, page.NextID)
}

func (handler *riskHTTPHandler) pathPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	_, afterID, limit, ok := handler.riskPageQuery(request, identity.Scope, routed.OperationID)
	if !ok {
		writeRiskCursorError(writer, request)
		return
	}
	page, err := handler.repository.ListRiskAttackPathPage(request.Context(), identity.Scope, afterID, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	handler.writeRiskPage(writer, request, identity.Scope, routed.OperationID, limit, page.Items, page.NextID)
}

func (handler *riskHTTPHandler) riskPageQuery(request *http.Request, scope domain.Scope, operation string) (map[string][]string, string, int, bool) {
	if request.Method != http.MethodGet {
		return nil, "", 0, false
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	if !ok {
		return nil, "", 0, false
	}
	limit, ok := workflowPageLimit(query)
	if !ok {
		return nil, "", 0, false
	}
	afterID := ""
	if cursorValues, present := query["cursor"]; present {
		if len(cursorValues) != 1 || cursorValues[0] == "" {
			return query, "", 0, false
		}
		cursor := cursorValues[0]
		afterID, ok = handler.decodeRiskCursor(cursor, scope, operation, limit)
		if !ok {
			return query, "", 0, false
		}
	}
	return query, afterID, limit, true
}

func (handler *riskHTTPHandler) writeRiskPage(writer http.ResponseWriter, request *http.Request, scope domain.Scope, operation string, limit int, items any, nextID string) {
	pageInfo := map[string]any{"next_cursor": nil, "has_more": false}
	if nextID != "" {
		pageInfo["next_cursor"] = handler.encodeRiskCursor(scope, operation, limit, nextID)
		pageInfo["has_more"] = true
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": items, "page_info": pageInfo}, nil)
}

func (handler *riskHTTPHandler) encodeRiskCursor(scope domain.Scope, operation string, limit int, afterID string) string {
	payload, _ := json.Marshal(riskCursorPayload{Version: 1, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), Operation: operation, Limit: limit, AfterID: afterID})
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *riskHTTPHandler) decodeRiskCursor(value string, scope domain.Scope, operation string, limit int) (string, bool) {
	if len(value) < 2 || len(value) > 512 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return "", false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", false
	}
	var cursor riskCursorPayload
	if decodeStrictRisk(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != scope.OrganizationID().String() || cursor.WorkspaceID != scope.WorkspaceID().String() || cursor.EnvironmentID != scope.EnvironmentID().String() || cursor.Operation != operation || cursor.Limit != limit || !validProductID(cursor.AfterID) {
		return "", false
	}
	return cursor.AfterID, true
}

func writeRiskCursorError(writer http.ResponseWriter, request *http.Request) {
	if _, err := request.URL.Query()["cursor"]; err {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	writeProductionError(writer, request, ErrRepositoryOperation)
}

func (handler *riskHTTPHandler) finding(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id := routed.PathParameters["id"]
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	finding, err := handler.repository.GetRiskFinding(request.Context(), identity.Scope, id)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(finding.Version))
	writeJSONValue(writer, request, http.StatusOK, finding, nil)
}

func (handler *riskHTTPHandler) path(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id := routed.PathParameters["id"]
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	path, err := handler.repository.GetRiskAttackPath(request.Context(), identity.Scope, id)
	writeJSONValue(writer, request, http.StatusOK, path, err)
}

func (handler *riskHTTPHandler) breakOptions(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id := routed.PathParameters["id"]
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	options, err := handler.repository.GetRiskBreakOptions(request.Context(), identity.Scope, id)
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": options}, err)
}

func (handler *riskHTTPHandler) mutateFinding(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id := routed.PathParameters["id"]
	if !validProductID(id) || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) {
		writeProductionStatusError(writer, request, http.StatusBadRequest, "operation_rejected", "Operation rejected", false)
		return
	}
	expectedVersion, err := parseVersion(request.Header.Get("If-Match"))
	if err != nil {
		writeWorkflowMutationError(writer, request, errPreconditionRequired)
		return
	}
	status, reason := "", ""
	switch routed.OperationID {
	case "updateFinding":
		var input struct {
			Status string `json:"status"`
		}
		if request.Method != http.MethodPatch || decodeProductionJSON(request, &input) != nil || !stringIn(input.Status, "open", "under_review", "resolved") {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		status = input.Status
	case "acceptFindingRisk":
		var input struct {
			Reason string `json:"reason"`
		}
		if request.Method != http.MethodPost || decodeProductionJSON(request, &input) != nil || len(input.Reason) < 1 || len(input.Reason) > 512 || strings.TrimSpace(input.Reason) != input.Reason {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		status, reason = "accepted", input.Reason
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	receiptID := ""
	if identity.CredentialKind == CredentialBrowserSession {
		receiptID, err = newWorkflowProductID()
		if err != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
	}
	result, err := handler.repository.MutateRiskFinding(request.Context(), identity, RiskFindingMutation{Operation: routed.OperationID, FindingID: id, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, Status: status, Reason: reason, AuditID: auditID, CorrelationID: correlationIDFromContext(request.Context()), ReceiptID: receiptID})
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	handler.writeMutationResult(writer, request, result)
}

func (handler *riskHTTPHandler) writeMutationResult(writer http.ResponseWriter, request *http.Request, result RiskFindingMutationResult) {
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if result.ReceiptID != "" {
		writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	}
	writeJSONValue(writer, request, http.StatusOK, result.Body, nil)
}
