package apiserver

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const (
	endpointAdminSQL   = `SELECT zasp_authorization80.endpoint_admin($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`
	endpointMachineSQL = `SELECT zasp_authorization80.endpoint_machine($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`
)

var cohortLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type endpointFleetHandler struct {
	database JSONDatabase
	clock    func() time.Time
	newID    func() (string, error)
}

type endpointRegister struct {
	Credential string `json:"credential_id"`
	DeviceKey  []byte `json:"device_public_key"`
	PolicyKey  []byte `json:"policy_public_key,omitempty"`
	Cohort     string `json:"cohort,omitempty"`
}
type endpointKeyResponse struct {
	DeviceKey  []byte `json:"device_public_key"`
	PolicyKey  []byte `json:"policy_public_key"`
	Generation uint64 `json:"credential_generation"`
}

func (h *endpointFleetHandler) serve(w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthentication)
		return
	}
	var raw json.RawMessage
	var err error
	if i.CredentialKind == CredentialBrowserSession {
		raw, err = h.admin(r, op, i)
	} else {
		raw, err = h.machine(r, op, i)
	}
	if err != nil {
		writeWorkflowMutationError(w, r, err)
		return
	}
	if string(raw) == "null" || len(raw) == 0 {
		writeWorkflowMutationError(w, r, ErrRepositoryNotFound)
		return
	}
	if string(raw) == `"conflict"` {
		writeWorkflowMutationError(w, r, ErrRepositoryConflict)
		return
	}
	if string(raw) == `"forbidden"` {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	if string(raw) == `"capacity"` {
		writeWorkflowMutationError(w, r, ErrRepositoryUnavailable)
		return
	}
	if raw[0] != '{' || !json.Valid(raw) {
		writeWorkflowMutationError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}

func (h *endpointFleetHandler) admin(r *http.Request, op RoutedOperation, i RequestIdentity) (json.RawMessage, error) {
	a := i.PrincipalID.String()
	o, ws, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	id := op.PathParameters["id"]
	var payload any = struct{}{}
	var key string
	var revision int64
	var valid bool
	if r.URL.RawQuery != "" && op.OperationID != "listEndpointDevices" {
		return nil, ErrRepositoryOperation
	}
	switch op.OperationID {
	case "listEndpointDevices":
		query, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"after_id": 128, "limit": 3})
		if !ok {
			return nil, ErrRepositoryOperation
		}
		limit := 50
		if v := query.Get("limit"); v != "" {
			var err error
			limit, err = strconv.Atoi(v)
			if err != nil || limit < 1 || limit > 100 {
				return nil, ErrRepositoryOperation
			}
		}
		after := query.Get("after_id")
		if after != "" && !validProductID(after) {
			return nil, ErrRepositoryOperation
		}
		payload = map[string]any{"limit": limit, "after": after}
	case "getEndpointDevice":
		if !validProductID(id) {
			return nil, ErrRepositoryOperation
		}
	case "registerEndpointDevice", "rotateEndpointCredential", "retireEndpointDevice", "publishEndpointPolicy":
		if !i.FreshAuthenticated {
			return nil, ErrRepositoryAuthorization
		}
		if op.OperationID == "registerEndpointDevice" {
			key = r.Header.Get("Idempotency-Key")
			valid = len(r.Header.Values("Idempotency-Key")) == 1 && validPublicIdempotency(key)
			var err error
			id, err = h.newID()
			if err != nil {
				return nil, ErrRepositoryUnavailable
			}
		} else {
			key, revision, valid = discoveryMutationHeaders(r, true)
		}
		if !valid || !validProductID(id) {
			return nil, ErrRepositoryOperation
		}
		switch op.OperationID {
		case "registerEndpointDevice", "rotateEndpointCredential":
			var cfg endpointRegister
			if decodeProductionJSON(r, &cfg) != nil || !validProductID(cfg.Credential) || len(cfg.DeviceKey) != ed25519.PublicKeySize {
				return nil, ErrRepositoryOperation
			}
			if op.OperationID == "registerEndpointDevice" && (!cohortLabel.MatchString(cfg.Cohort) || len(cfg.PolicyKey) != ed25519.PublicKeySize) {
				return nil, ErrRepositoryOperation
			}
			if op.OperationID == "rotateEndpointCredential" && (cfg.Cohort != "" || cfg.PolicyKey != nil) {
				return nil, ErrRepositoryOperation
			}
			payload = cfg
		case "retireEndpointDevice":
			if r.ContentLength != 0 && decodeEmptyInput(r) != nil {
				return nil, ErrRepositoryOperation
			}
		case "publishEndpointPolicy":
			var signed endpointprotocol.Signed
			if decodeProductionJSON(r, &signed) != nil {
				return nil, ErrRepositoryOperation
			}
			keysRaw, err := h.database.QueryJSON(r.Context(), endpointAdminSQL, o, ws, e, a, op.OperationID, id, key, revision, `{"inspect":true}`)
			if err != nil {
				return nil, err
			}
			var keys endpointKeyResponse
			if json.Unmarshal(keysRaw, &keys) != nil || keys.Generation == 0 {
				return nil, ErrRepositoryNotFound
			}
			policy, ok := signed.PolicyFor(keys.PolicyKey, endpointprotocol.Binding{Organization: o, Workspace: ws, Environment: e, Device: id, Generation: keys.Generation}, h.clock())
			if !ok {
				return nil, ErrRepositoryOperation
			}
			payload = map[string]any{"bundle": signed, "policy_revision": policy.Revision, "expires_at": policy.ExpiresAt, "generation": keys.Generation}
		}
	default:
		return nil, ErrRepositoryAuthorization
	}
	body, _ := json.Marshal(payload)
	return h.database.QueryJSON(r.Context(), endpointAdminSQL, o, ws, e, a, op.OperationID, id, key, revision, string(body))
}

func (h *endpointFleetHandler) machine(r *http.Request, op RoutedOperation, i RequestIdentity) (json.RawMessage, error) {
	if i.CredentialKind != CredentialBearerToken || len(i.credentialBinding.PATCeiling) != 1 || i.credentialBinding.PATCeiling[0] != endpointprotocol.Permission {
		return nil, ErrRepositoryAuthorization
	}
	if r.URL.RawQuery != "" {
		return nil, ErrRepositoryOperation
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(body) > 65536 {
		return nil, ErrRepositoryOperation
	}
	if r.Method == http.MethodGet && len(body) != 0 {
		return nil, ErrRepositoryOperation
	}
	o, ws, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	p, raw, err := endpointprotocol.Parse(r.Header, o, ws, e, op.OperationID, body, h.clock())
	if err != nil || !validProductID(p.Binding.Device) || (op.PathParameters["id"] != "" && op.PathParameters["id"] != p.Binding.Device) {
		return nil, ErrRepositoryAuthorization
	}
	query := func(phase string, args any) (json.RawMessage, error) {
		value, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		return h.database.QueryJSON(r.Context(), endpointMachineSQL, o, ws, e, i.PrincipalID.String(), op.OperationID, p.Binding.Device, int64(p.Binding.Generation), phase, string(value))
	}
	keysRaw, err := query("key", struct{}{})
	if err != nil {
		return nil, err
	}
	var keys endpointKeyResponse
	if json.Unmarshal(keysRaw, &keys) != nil || !endpointprotocol.Verify(r.Header, keys.DeviceKey, raw) {
		return nil, ErrRepositoryAuthorization
	}
	var input any
	switch op.OperationID {
	case "fetchEndpointPolicy":
		input = struct{}{}
	case "exchangeEndpointEnrollment":
		var v struct{}
		if !endpointprotocol.Strict(body, &v) {
			return nil, ErrRepositoryOperation
		}
		input = v
	case "recordEndpointHeartbeat":
		var v endpointprotocol.Heartbeat
		if !endpointprotocol.Strict(body, &v) || !v.Valid() {
			return nil, ErrRepositoryOperation
		}
		input = v
	case "recordEndpointInventory":
		var v endpointprotocol.Inventory
		if !endpointprotocol.Strict(body, &v) || !v.Valid() {
			return nil, ErrRepositoryOperation
		}
		input = v
	case "recordEndpointObservations":
		var batch struct {
			Receipts []endpointprotocol.Signed `json:"receipts"`
		}
		if !endpointprotocol.Strict(body, &batch) || len(batch.Receipts) == 0 || len(batch.Receipts) > 16 {
			return nil, ErrRepositoryOperation
		}
		items := make([]endpointprotocol.Observation, 0, len(batch.Receipts))
		for _, s := range batch.Receipts {
			obs, ok := s.ObservationFor(keys.DeviceKey, p.Binding, h.clock())
			if !ok {
				return nil, ErrRepositoryOperation
			}
			items = append(items, obs)
		}
		input = items
	default:
		return nil, ErrRepositoryAuthorization
	}
	args := map[string]any{"nonce": p.Nonce, "digest": p.Digest, "unix": p.Unix, "verified_key": base64.StdEncoding.EncodeToString(keys.DeviceKey), "input": input}
	return query("apply", args)
}

func init() {
	adminOps := []string{"registerEndpointDevice", "rotateEndpointCredential", "retireEndpointDevice", "publishEndpointPolicy", "getEndpointDevice", "listEndpointDevices"}
	machineOps := []string{"fetchEndpointPolicy", "exchangeEndpointEnrollment", "recordEndpointHeartbeat", "recordEndpointInventory", "recordEndpointObservations"}
	check := func(g RequestAuthorization, args []any) bool {
		op, ok := args[4].(string)
		id, idOK := args[5].(string)
		path := g.PathParameters["id"]
		return ok && idOK && op == g.OperationID && (path == "" || path == id) && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) && (!requiresFreshAuthentication(op) || g.Identity.FreshAuthenticated)
	}
	productStatementRules[endpointAdminSQL] = productStatementRule{operations: adminOps, arguments: 9, scope: 1, actor: 4, browserOnly: true, check: check}
	productStatementRules[endpointMachineSQL] = productStatementRule{operations: machineOps, arguments: 9, scope: 1, actor: 4, check: func(g RequestAuthorization, args []any) bool {
		return check(g, args) && g.Identity.CredentialKind == CredentialBearerToken && len(g.Credential.PATCeiling) == 1 && g.Credential.PATCeiling[0] == endpointprotocol.Permission
	}}
}
