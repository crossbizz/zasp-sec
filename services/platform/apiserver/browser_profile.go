package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"time"
)

const permissionBrowserUsage = "report_browser_usage"
const browserProfileSQL = "SELECT zasp_authorization80.browser_profile($1,$2,$3,$4,$5,$6::jsonb)"

type browserDay struct {
	Origin string `json:"origin"`
	Day    string `json:"day"`
}
type browserReport struct {
	IssuedAt  int64        `json:"issued_at"`
	Nonce     string       `json:"nonce"`
	Days      []browserDay `json:"days"`
	Signature []byte       `json:"signature"`
}

var browserNonce = regexp.MustCompile("^[a-f0-9]{32}$")

func browserProvider(origin string) bool {
	return origin == "https://claude.ai" || origin == "https://chatgpt.com"
}
func (s browserReport) signingDigest(cred string, now time.Time) ([]byte, bool) {
	if len(s.Signature) != 64 || s.Days == nil || len(s.Days) > 60 || s.IssuedAt < now.Unix()-120 || s.IssuedAt > now.Unix()+30 || !browserNonce.MatchString(s.Nonce) {
		return nil, false
	}
	today := now.UTC().Truncate(24 * time.Hour)
	days := make([][2]string, 0, len(s.Days))
	seen := map[[2]string]bool{}
	for _, day := range s.Days {
		t, err := time.Parse("2006-01-02", day.Day)
		pair := [2]string{day.Origin, day.Day}
		if !browserProvider(day.Origin) || err != nil || t.After(today) || t.Before(today.AddDate(0, 0, -29)) || seen[pair] {
			return nil, false
		}
		days = append(days, pair)
		seen[pair] = true
	}
	raw, err := json.Marshal([]any{"zasp.browser-profile.v1", cred, s.IssuedAt, s.Nonce, days})
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

func browserPublic(raw []byte) *ecdsa.PublicKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil || y == nil {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func browserStatementAllowed(g RequestAuthorization, args []any) bool {
	if !authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) {
		return false
	}
	if g.OperationID == "recordBrowserOriginDays" {
		return g.Identity.CredentialKind == CredentialBearerToken && g.Credential.ID == args[4] && slices.Equal(g.Credential.PATCeiling, []string{permissionBrowserUsage})
	}
	return g.Identity.CredentialKind == CredentialBrowserSession && (g.OperationID == "getBrowserProfile" || g.Identity.FreshAuthenticated)
}

func serveBrowserProfile(db JSONDatabase, w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	id := op.PathParameters["id"]
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	o, ws, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	query := func(value any) (json.RawMessage, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return db.QueryJSON(r.Context(), browserProfileSQL, o, ws, e, i.PrincipalID.String(), id, string(raw))
	}
	var v any = struct{}{}
	machine := op.OperationID == "recordBrowserOriginDays"
	if machine {
		if i.CredentialKind != CredentialBearerToken || i.credentialBinding.ID != id || !slices.Equal(i.credentialBinding.PATCeiling, []string{permissionBrowserUsage}) {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		var report browserReport
		if r.Method != http.MethodPost || decodeProductionJSON(r, &report) != nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		digest, valid := report.signingDigest(id, time.Now())
		if !valid {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		raw, err := query(map[string]bool{"inspect": true})
		if err != nil {
			writeProductionError(w, r, discoveryProviderError(err))
			return
		}
		var keys struct {
			Key []byte `json:"public_key"`
		}
		if json.Unmarshal(raw, &keys) != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		pub := browserPublic(keys.Key)
		if pub == nil || !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(report.Signature[:32]), new(big.Int).SetBytes(report.Signature[32:])) {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		v = map[string]any{"public_key": base64.StdEncoding.EncodeToString(keys.Key), "days": report.Days, "issued_at": report.IssuedAt, "nonce": report.Nonce, "digest": hex.EncodeToString(digest)}
	} else {
		if i.CredentialKind != CredentialBrowserSession || op.OperationID != "getBrowserProfile" && !i.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		switch op.OperationID {
		case "registerBrowserProfile":
			var in struct {
				Key     []byte   `json:"public_key"`
				Origins []string `json:"origins"`
			}
			if r.Method != http.MethodPut || decodeProductionJSON(r, &in) != nil || browserPublic(in.Key) == nil || len(in.Origins) < 1 || len(in.Origins) > 2 {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
			slices.Sort(in.Origins)
			for j, x := range in.Origins {
				if !browserProvider(x) || j > 0 && in.Origins[j-1] == x {
					writeProductionError(w, r, ErrRepositoryOperation)
					return
				}
			}
			v = in
		case "retireBrowserProfile":
			if r.Method != http.MethodDelete || requireZeroByteInput(r) != nil {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
		case "getBrowserProfile":
			if r.Method != http.MethodGet {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
		default:
			writeProductionError(w, r, ErrRepositoryNotFound)
			return
		}
	}
	raw, err := query(v)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"stale"`, `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	case `"forbidden"`:
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	if !json.Valid(raw) || raw[0] != '{' {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, 200, raw, nil)
}
