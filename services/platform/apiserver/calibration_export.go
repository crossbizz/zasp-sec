package apiserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const calibrationExportPrefix = "SELECT zasp_authorization80.calibration_export($1,$2,$3,$4,$5,"
const calibrationExportCreate = calibrationExportPrefix + "'createCalibrationExport',$6,NULL)"
const calibrationExportGet = calibrationExportPrefix + "'getCalibrationExport',NULL,NULL)"
const calibrationGrantCreate = calibrationExportPrefix + "'createCalibrationDownloadGrant',NULL,$6)"
const calibrationGrantRead = calibrationExportPrefix + "'read',NULL,$6)"
const calibrationGrantConsume = calibrationExportPrefix + "'consume',NULL,$6)"

func init() {
	for _, rule := range []struct {
		query, op      string
		argc, object   int
		fresh, browser bool
	}{
		{calibrationExportCreate, "createCalibrationExport", 6, 0, true, true},
		{calibrationExportGet, "getCalibrationExport", 5, 5, false, true},
		{calibrationGrantCreate, "createCalibrationDownloadGrant", 6, 5, true, true},
		{calibrationGrantRead, "downloadCalibrationExport", 6, 5, false, false},
		{calibrationGrantConsume, "downloadCalibrationExport", 6, 5, false, false},
	} {
		productStatementRules[rule.query] = productStatementRule{operations: []string{rule.op}, arguments: rule.argc, scope: 1, actor: 4, object: rule.object, browserOnly: rule.browser, fresh: rule.fresh}
	}
}

func calibrationExportOperation(op string) bool {
	return stringIn(op, "createCalibrationExport", "getCalibrationExport", "createCalibrationDownloadGrant", "downloadCalibrationExport")
}

type calibrationExportHTTP struct {
	db     JSONDatabase
	reader complianceArtifactReader
}

func (h calibrationExportHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	if !ok || !routed || !currentRequestHasPermission(r.Context(), identity, "view_compliance") {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if h.db == nil || nilInterface(h.reader) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	id := route.PathParameters["id"]
	query, status := calibrationExportGet, http.StatusOK
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	var grant string
	switch route.OperationID {
	case "createCalibrationExport":
		var empty *struct{}
		keys := r.Header.Values("Idempotency-Key")
		if len(keys) != 1 || !validPublicIdempotency(keys[0]) || decodeProductionJSON(r, &empty) != nil || empty == nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		created, err := newWorkflowProductID()
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		args = append(args, created, keys[0])
		query = calibrationExportCreate
		status = http.StatusAccepted
	case "getCalibrationExport", "createCalibrationDownloadGrant", "downloadCalibrationExport":
		if !validProductID(id) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, id)
		if route.OperationID == "createCalibrationDownloadGrant" {
			var empty *struct{}
			if decodeProductionJSON(r, &empty) != nil || empty == nil {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
			var secret [32]byte
			if _, err := rand.Read(secret[:]); err != nil {
				writeProductionError(w, r, ErrRepositoryUnavailable)
				return
			}
			grant = hex.EncodeToString(secret[:])
			query = calibrationGrantCreate
		}
		if route.OperationID == "downloadCalibrationExport" {
			var input struct {
				Grant string `json:"grant"`
			}
			if decodeProductionJSON(r, &input) != nil || !validExistingTestPublicDigest(input.Grant) {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
			grant = input.Grant
			query = calibrationGrantRead
		}
		if grant != "" {
			digest := sha256.Sum256([]byte(grant))
			args = append(args, hex.EncodeToString(digest[:]))
		}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	fetch := func(statement string) (json.RawMessage, bool) {
		raw, err := h.db.QueryJSON(r.Context(), statement, args...)
		if err != nil {
			writeProductionError(w, r, discoveryProviderError(err))
			return nil, false
		}
		switch string(raw) {
		case "null":
			writeProductionError(w, r, ErrRepositoryNotFound)
			return nil, false
		case `"limit"`, `"unavailable"`:
			writeProductionError(w, r, ErrRepositoryConflict)
			return nil, false
		case `"invalid"`:
			writeProductionError(w, r, ErrRepositoryOperation)
			return nil, false
		}
		return raw, true
	}
	raw, ok := fetch(query)
	if !ok {
		return
	}
	switch query {
	case calibrationGrantCreate:
		var grantInfo struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		if json.Unmarshal(raw, &grantInfo) != nil || grantInfo.ExpiresAt.IsZero() {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeJSONValue(w, r, status, map[string]any{"grant": grant, "expires_at": grantInfo.ExpiresAt}, nil)
	case calibrationGrantRead:
		var pin struct {
			Version string `json:"version"`
			SHA     string `json:"sha256"`
			Size    int64  `json:"size"`
		}
		if json.Unmarshal(raw, &pin) != nil || !complianceVersion(pin.Version) || !validExistingTestPublicDigest(pin.SHA) || pin.Size < 1 || pin.Size > 1<<20 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		ref, err := domain.ParseEvidenceRef(id)
		if err != nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		locator := artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: pin.Version}
		obj, err := h.reader.Get(r.Context(), locator)
		sum := sha256.Sum256(obj.Body)
		if err != nil || obj.Locator != locator || obj.MediaType != "application/x-ndjson" || obj.Size != pin.Size || int64(len(obj.Body)) != pin.Size || obj.SHA256 != sum || hex.EncodeToString(sum[:]) != pin.SHA || !utf8.Valid(obj.Body) {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		consumed, ok := fetch(calibrationGrantConsume)
		if !ok {
			return
		}
		if !bytes.Equal(raw, consumed) {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeJSONValue(w, r, status, map[string]string{"environment_id": identity.Scope.EnvironmentID().String(), "filename": "calibration-" + id + ".jsonl", "jsonl": string(obj.Body), "sha256": pin.SHA}, nil)
	default:
		var out struct {
			ID          string `json:"id"`
			Environment string `json:"environment_id"`
		}
		if json.Unmarshal(raw, &out) != nil || !validProductID(out.ID) || out.Environment != identity.Scope.EnvironmentID().String() || (id != "" && id != out.ID) {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(w, r, status, raw, nil)
	}
}
