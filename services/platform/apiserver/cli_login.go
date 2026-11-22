package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cliApproveSQL = `SELECT zasp_authorization80.cli_approve($1,$2,$3,$4,$5,$6,$7,$8)`
const cliClientID = "zaspctl"

type cliStart struct {
	Client      string `json:"client_id"`
	Environment string `json:"environment_id"`
	Method      string `json:"code_challenge_method"`
	Challenge   string `json:"code_challenge"`
}
type cliApproval struct {
	Client      string `json:"client_id"`
	Environment string `json:"environment_id"`
	ID          string `json:"request_id"`
	Challenge   string `json:"code_challenge"`
	Proof       string `json:"request_proof"`
	Code        string `json:"comparison_code"`
}
type cliExchange struct {
	Client      string `json:"client_id"`
	Environment string `json:"environment_id"`
	ID          string `json:"request_id"`
	Verifier    string `json:"code_verifier"`
}

func decodeCLIInput(r *http.Request, target any, fields ...string) bool {
	var raw json.RawMessage
	return decodeProductionJSON(r, &raw) == nil && validAgentExportContentJSON(string(raw)) && exactJSONFields(raw, fields...) && json.Unmarshal(raw, target) == nil
}

func validCLIChallenge(v string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(b) == 32 && len(v) == 43
}

func cliMAC(key []byte, purpose string, fields ...string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("zasp-cli-v1:" + purpose))
	for _, s := range fields {
		m.Write([]byte{0})
		m.Write([]byte(s))
	}
	return m.Sum(nil)
}

func cliComparison(key []byte, id, env, challenge, expiry string) string {
	return hex.EncodeToString(cliMAC(key, "comparison", id, env, challenge, expiry)[:4])
}
func cliAccess(key []byte, id, env, challenge string) string {
	return "zasp_cli_" + base64.RawURLEncoding.EncodeToString(cliMAC(key, "access", id, env, challenge))
}
func cliStartProof(key []byte, id, env, challenge, expiry string) string {
	return expiry + "." + base64.RawURLEncoding.EncodeToString(cliMAC(key, "start", id, env, challenge, expiry))
}
func (approval cliApproval) verify(key []byte, now time.Time) (int64, bool) {
	expiry, _, ok := strings.Cut(approval.Proof, ".")
	when, err := strconv.ParseInt(expiry, 10, 64)
	if !ok || err != nil || strconv.FormatInt(when, 10) != expiry || when <= now.Unix() || when > now.Unix()+300 || approval.Client != cliClientID || !validProductID(approval.ID) || !validProductID(approval.Environment) || !validCLIChallenge(approval.Challenge) {
		return 0, false
	}
	return when, subtle.ConstantTimeCompare([]byte(approval.Proof), []byte(cliStartProof(key, approval.ID, approval.Environment, approval.Challenge, expiry))) == 1 &&
		subtle.ConstantTimeCompare([]byte(approval.Code), []byte(cliComparison(key, approval.ID, approval.Environment, approval.Challenge, expiry))) == 1
}

func (handler *identityHTTPHandler) serveCLILogin(w http.ResponseWriter, r *http.Request, op string, repo *PostgresRepository) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	key := handler.tokenRevealKey
	if len(key) != 32 || handler.now == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	now := handler.now().UTC()
	var reply any
	switch op {
	case "startCLILogin":
		var in cliStart
		if !decodeCLIInput(r, &in, "client_id", "environment_id", "code_challenge_method", "code_challenge") || in.Client != cliClientID || in.Method != "S256" || !validProductID(in.Environment) || !validCLIChallenge(in.Challenge) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		id, err := newWorkflowProductID()
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		until := now.Truncate(time.Second).Add(5 * time.Minute)
		exp := strconv.FormatInt(until.Unix(), 10)
		reply = map[string]any{"request_id": id, "expires_at": until, "request_proof": cliStartProof(key, id, in.Environment, in.Challenge, exp), "comparison_code": cliComparison(key, id, in.Environment, in.Challenge, exp)}
	case "approveCLILogin":
		id, ok := IdentityFromRequest(r)
		if !ok || id.CredentialKind != CredentialBrowserSession || !id.FreshAuthenticated {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
		var in cliApproval
		if !decodeCLIInput(r, &in, "client_id", "environment_id", "request_id", "request_proof", "code_challenge", "comparison_code") || in.Environment != id.Scope.EnvironmentID().String() {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		epoch, ok := in.verify(key, now)
		if !ok {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		// Separate key domains protect approval proofs, comparison codes and
		// bearer material. Only the credential digest is persisted.
		digest := sha256.Sum256([]byte(cliAccess(key, in.ID, in.Environment, in.Challenge)))
		raw, err := repo.database.QueryJSON(r.Context(), cliApproveSQL, id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), in.Environment, id.PrincipalID.String(), in.ID, in.Challenge, hex.EncodeToString(digest[:]), epoch)
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		var result struct {
			Approved bool `json:"approved"`
		}
		if json.Unmarshal(raw, &result) != nil || !result.Approved {
			writeProductionError(w, r, ErrRepositoryConflict)
			return
		}
		reply = result
	case "exchangeCLILogin":
		var in cliExchange
		if !decodeCLIInput(r, &in, "client_id", "environment_id", "request_id", "code_verifier") || in.Client != cliClientID || !validProductID(in.ID) || !validProductID(in.Environment) || !validCLIChallenge(in.Verifier) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		d, err := repo.nativeIdentityDatabase()
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		var grant struct {
			Expires time.Time `json:"expires_at"`
		}
		challenge := sha256.Sum256([]byte(in.Verifier))
		access := cliAccess(key, in.ID, in.Environment, base64.RawURLEncoding.EncodeToString(challenge[:]))
		digest := sha256.Sum256([]byte(access))
		raw, err := d.identityTransaction(r.Context(), identityCLILoginExchange, []any{in.ID, in.Environment, in.Verifier, hex.EncodeToString(digest[:])}, func(payload json.RawMessage) error {
			if string(payload) == "null" {
				return nil
			}
			if !exactJSONFields(payload, "expires_at") || json.Unmarshal(payload, &grant) != nil || !grant.Expires.After(now) || grant.Expires.After(now.Add(15*time.Minute+5*time.Second)) {
				return ErrRepositoryUnavailable
			}
			return nil
		})
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		if string(raw) == "null" {
			writeProductionError(w, r, ErrRepositoryConflict)
			return
		}
		reply = map[string]any{"access_token": access, "token_type": "Bearer", "scope": permissionSubmitAddonScans, "environment_id": in.Environment, "expires_at": grant.Expires.UTC()}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	encoded, err := json.Marshal(reply)
	writeProductionResponse(w, r, http.StatusOK, encoded, err)
}

func init() {
	productStatementRules[cliApproveSQL] = productStatementRule{operations: []string{"approveCLILogin"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, fresh: true, check: addonEnvAllowed}
}
