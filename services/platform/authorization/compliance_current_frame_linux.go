package authorization

// These private wire primitives authenticate bytes, never product permission,
// native facts, enrollment, readiness or a provider acknowledgement. Only the
// genuine authority builder may supply frames to a future effect consumer.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const complianceCurrentFrameDomain = "zasp-compliance-current-worker-frame-v1"
const complianceCurrentModuleProfile = "canonical61-temporal78-authorization79-80-compliance-current-v1"
const complianceCurrentFrameLimit = 32768

var complianceCurrentHex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var complianceCurrentProduct = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var complianceCurrentULID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var complianceCurrentPrincipal = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)
var complianceCurrentWorker = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var complianceCurrentResource = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var complianceCurrentFrameCommon = []string{"domain", "purpose", "key_version", "session_user", "database_id", "profile", "module_checksum", "operation", "lane", "subaction", "arguments_sha256", "issued_at", "expires_at", "authority_kind"}

type complianceCurrentArgumentSpec struct {
	Kind     byte
	Nullable bool
}

func complianceCurrentProductValid(s string) bool {
	if !complianceCurrentProduct.MatchString(s) {
		return false
	}
	compact := make([]byte, 0, 32)
	for _, c := range []byte(s[4:]) {
		if c != '-' {
			compact = append(compact, c)
		}
	}
	value, err := hex.DecodeString(string(compact))
	if err != nil || len(value) != 16 {
		return false
	}
	value[6] &= 0x0f
	value[8] &= 0x3f
	for _, b := range value {
		if b != 0 {
			return true
		}
	}
	return false
}
func complianceCurrentString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && utf8.ValidString(s)
}
func complianceCurrentInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.ParseInt(string(n), 10, 64)
	return i, e == nil && strconv.FormatInt(i, 10) == string(n)
}
func complianceCurrentObject(v any, keys ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, present := m[k]; !present {
			return nil, false
		}
	}
	return m, true
}
func complianceCurrentJSON(raw []byte, limit int) (any, error) {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	count := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		count++
		if depth > 32 || count > 8192 {
			return nil, ErrInvalid
		}
		token, err := d.Token()
		if err != nil {
			return nil, ErrInvalid
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delimiter {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				name, ok := k.(string)
				if e != nil || !ok || !utf8.ValidString(name) {
					return nil, ErrInvalid
				}
				if _, exists := m[name]; exists {
					return nil, ErrInvalid
				}
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				m[name] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	}
	v, err := value(0)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}
func complianceCurrentScope(v any) (map[string]any, bool) {
	m, ok := complianceCurrentObject(v, "organization_id", "workspace_id", "environment_id")
	if !ok {
		return nil, false
	}
	for _, k := range []string{"organization_id", "workspace_id", "environment_id"} {
		s, ok := complianceCurrentString(m[k])
		if !ok || !complianceCurrentProductValid(s) {
			return nil, false
		}
	}
	return m, true
}
func complianceCurrentHash(v any) bool {
	s, ok := complianceCurrentString(v)
	return ok && complianceCurrentHex.MatchString(s)
}
func complianceCurrentRequester(v any, scope map[string]any) bool {
	m, ok := complianceCurrentObject(v, "requester_id", "credential_digest", "revision", "checks", "native_facts_digest")
	if !ok {
		return false
	}
	requester, ok := complianceCurrentString(m["requester_id"])
	if !ok || !complianceCurrentProductValid(requester) || !complianceCurrentHash(m["credential_digest"]) || !complianceCurrentHash(m["native_facts_digest"]) {
		return false
	}
	r, ok := complianceCurrentObject(m["revision"], "organization_id", "desired", "applied", "generation", "store_id", "model_id")
	if !ok || r["organization_id"] != scope["organization_id"] {
		return false
	}
	desired, a := complianceCurrentInt(r["desired"])
	applied, b := complianceCurrentInt(r["applied"])
	generation, c := complianceCurrentInt(r["generation"])
	store, s := complianceCurrentString(r["store_id"])
	model, n := complianceCurrentString(r["model_id"])
	if !a || !b || !c || desired < 1 || desired != applied || generation < 1 || !s || !n || !complianceCurrentULID.MatchString(store) || !complianceCurrentULID.MatchString(model) {
		return false
	}
	checks, ok := m["checks"].([]any)
	if !ok || len(checks) < 3 || len(checks) > 384 || len(checks)%3 != 0 {
		return false
	}
	permissions := []string{"view", "view_audit", "view_compliance"}
	lastTarget := ""
	for i := 0; i < len(checks); i += 3 {
		target := ""
		for j, permission := range permissions {
			check, ok := complianceCurrentObject(checks[i+j], "request", "allowed", "model_id")
			if !ok || check["allowed"] != true || check["model_id"] != model {
				return false
			}
			q, ok := complianceCurrentObject(check["request"], "principal_kind", "principal_id", "organization_id", "workspace_id", "environment_id", "resource_type", "resource_id", "permission", "task_id")
			if !ok || q["principal_kind"] != "user" || q["principal_id"] != requester || q["permission"] != permission || q["task_id"] != "" {
				return false
			}
			for _, k := range []string{"organization_id", "workspace_id", "environment_id"} {
				if q[k] != scope[k] {
					return false
				}
			}
			kind, ok := complianceCurrentString(q["resource_type"])
			id, valid := complianceCurrentString(q["resource_id"])
			if !ok || !valid || !complianceCurrentResource.MatchString(kind) || !complianceCurrentProductValid(id) {
				return false
			}
			if kind == "environment" && id != scope["environment_id"] || kind == "workspace" && id != scope["workspace_id"] || kind == "organization" && id != scope["organization_id"] {
				return false
			}
			current := kind + "\x00" + id
			if j == 0 {
				target = current
			} else if current != target {
				return false
			}
		}
		if i > 0 && target <= lastTarget {
			return false
		}
		lastTarget = target
	}
	return true
}
func complianceCurrentFrameValid(k *ComplianceCurrentKey, body []byte, now time.Time) bool {
	if k == nil || !validComplianceCurrentPurpose(k.purpose) || !complianceCurrentHex.MatchString(k.version) {
		return false
	}
	derived := sha256.Sum256(k.key[:])
	if k.version != hex.EncodeToString(derived[:]) {
		return false
	}
	parsed, err := complianceCurrentJSON(body, complianceCurrentFrameLimit)
	if err != nil {
		return false
	}
	m, ok := parsed.(map[string]any)
	if !ok {
		return false
	}
	canonical, err := json.Marshal(parsed)
	if err != nil || !bytes.Equal(canonical, body) {
		return false
	}
	kind, ok := complianceCurrentString(m["authority_kind"])
	if !ok {
		return false
	}
	extra := []string{}
	switch kind {
	case "no_lease":
		extra = []string{"scope", "global_head", "request_id"}
	case "acquire":
		extra = []string{"scope", "export_id", "origin_digest", "request_id", "worker_id"}
		if k.purpose == ComplianceCurrentExecution {
			extra = append(extra, "requester_decision")
		} else {
			extra = append(extra, "debt_digest")
		}
	case "execute_pre_capture_lease", "execute_lease":
		if k.purpose != ComplianceCurrentExecution {
			return false
		}
		extra = []string{"scope", "export_id", "origin_digest", "request_id", "worker_id", "lease_token", "generation", "attempt", "lease_expires_at", "requester_decision"}
		if kind == "execute_lease" {
			extra = append(extra, "capture_digest", "package_digest", "provider_coordinates")
		}
	case "debt_lease":
		if k.purpose != ComplianceCurrentCleanup {
			return false
		}
		extra = []string{"scope", "export_id", "origin_digest", "request_id", "worker_id", "lease_token", "generation", "attempt", "lease_expires_at", "captured_proof_digest", "debt_digest", "package_digest", "provider_coordinates"}
	default:
		return false
	}
	fields := append(append([]string(nil), complianceCurrentFrameCommon...), extra...)
	if _, ok = complianceCurrentObject(m, fields...); !ok {
		return false
	}
	if m["domain"] != complianceCurrentFrameDomain || m["purpose"] != string(k.purpose) || m["key_version"] != k.version || m["profile"] != complianceCurrentModuleProfile {
		return false
	}
	principal, ok := complianceCurrentString(m["session_user"])
	if !ok || !complianceCurrentPrincipal.MatchString(principal) || len(principal) >= 5 && principal[:5] == "zasp_" {
		return false
	}
	for _, field := range []string{"database_id", "module_checksum", "arguments_sha256"} {
		if !complianceCurrentHash(m[field]) {
			return false
		}
	}
	lane, ok := complianceCurrentString(m["lane"])
	if !ok || k.purpose == ComplianceCurrentExecution && lane != "execute" || k.purpose == ComplianceCurrentCleanup && lane != "reconcile" && lane != "cleanup" {
		return false
	}
	op, a := complianceCurrentString(m["operation"])
	sub, b := complianceCurrentString(m["subaction"])
	if !a || !b {
		return false
	}
	allowed := false
	switch kind {
	case "no_lease":
		allowed = op == "candidates" && sub == "list" || k.purpose == ComplianceCurrentCleanup && op == "maintenance" && sub == "maintain"
	case "acquire":
		allowed = op == "claim" && sub == "acquire"
	default:
		allowed = op == "heartbeat" && sub == "renew" || op == "retry" && sub == "unknown"
		if kind == "execute_pre_capture_lease" {
			allowed = allowed || op == "capture" && sub == "capture"
		}
		if kind == "execute_lease" {
			allowed = allowed || op == "prepare" && (sub == "read" || sub == "write") || op == "finish" && sub == "acknowledged"
		}
		if kind == "debt_lease" && lane == "reconcile" {
			allowed = allowed || op == "prepare" && sub == "read" || op == "observe_storage" && sub == "acknowledged"
		}
		if kind == "debt_lease" && lane == "cleanup" {
			allowed = allowed || op == "cleanup" && sub == "confirm_absent"
		}
	}
	if !allowed {
		return false
	}
	nowMS := now.UnixMilli()
	if nowMS < 0 || nowMS > math.MaxInt64-65000 {
		return false
	}
	issued, a := complianceCurrentInt(m["issued_at"])
	expires, b := complianceCurrentInt(m["expires_at"])
	if !a || !b || issued > nowMS+5000 || expires <= nowMS || expires <= issued || issued < expires-60000 {
		return false
	}
	scope, ok := complianceCurrentScope(m["scope"])
	if !ok {
		return false
	}
	requestID, ok := complianceCurrentString(m["request_id"])
	if !ok || !complianceCurrentProductValid(requestID) {
		return false
	}
	if kind == "no_lease" {
		head, ok := complianceCurrentString(m["global_head"])
		return ok && complianceCurrentProductValid(head)
	}
	exportID, ok := complianceCurrentString(m["export_id"])
	worker, w := complianceCurrentString(m["worker_id"])
	if !ok || !w || !complianceCurrentProductValid(exportID) || !complianceCurrentWorker.MatchString(worker) || !complianceCurrentHash(m["origin_digest"]) {
		return false
	}
	if k.purpose == ComplianceCurrentExecution {
		if !complianceCurrentRequester(m["requester_decision"], scope) {
			return false
		}
	} else if !complianceCurrentHash(m["debt_digest"]) {
		return false
	}
	if kind == "acquire" {
		return true
	}
	generation, g := complianceCurrentInt(m["generation"])
	attempt, a := complianceCurrentInt(m["attempt"])
	lease, l := complianceCurrentInt(m["lease_expires_at"])
	if !g || !a || !l || generation < 1 || attempt < 0 || attempt > 5 || lane == "execute" && attempt < 1 || lease <= nowMS || lease > nowMS+65000 || expires > lease || !complianceCurrentHash(m["lease_token"]) {
		return false
	}
	if kind == "execute_pre_capture_lease" {
		return true
	}
	if !complianceCurrentHash(m["package_digest"]) {
		return false
	}
	if kind == "execute_lease" {
		if !complianceCurrentHash(m["capture_digest"]) {
			return false
		}
	} else if !complianceCurrentHash(m["captured_proof_digest"]) {
		return false
	}
	coordinates, ok := complianceCurrentObject(m["provider_coordinates"], "reference", "version_id", "size", "sha256")
	if !ok || coordinates["reference"] != exportID || !complianceCurrentHash(coordinates["sha256"]) {
		return false
	}
	version, v := complianceCurrentString(coordinates["version_id"])
	size, s := complianceCurrentInt(coordinates["size"])
	return v && version != "" && len(version) <= 1024 && s && size >= 1 && size <= 8<<20
}
func signComplianceCurrentFrame(k *ComplianceCurrentKey, body []byte, now time.Time) ([]byte, error) {
	if !complianceCurrentFrameValid(k, body, now) {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, k.key[:])
	_, _ = mac.Write([]byte(complianceCurrentFrameDomain + "\x00"))
	_, _ = mac.Write(body)
	sum := mac.Sum(nil)
	defer clear(sum)
	raw, err := json.Marshal(struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{append([]byte(nil), body...), k.version, hex.EncodeToString(sum)})
	if err != nil || len(raw) > 65536 {
		return nil, ErrInvalid
	}
	return raw, nil
}
func verifyComplianceCurrentFrame(k *ComplianceCurrentKey, envelope, expected []byte, now time.Time) ([]byte, error) {
	if !complianceCurrentFrameValid(k, expected, now) {
		return nil, ErrInvalid
	}
	parsed, err := complianceCurrentJSON(envelope, 65536)
	if err != nil {
		return nil, ErrInvalid
	}
	m, ok := complianceCurrentObject(parsed, "body", "version", "mac")
	if !ok || m["version"] != k.version {
		return nil, ErrInvalid
	}
	encoded, b := complianceCurrentString(m["body"])
	textMAC, a := complianceCurrentString(m["mac"])
	if !a || !b || !complianceCurrentHex.MatchString(textMAC) {
		return nil, ErrInvalid
	}
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(body) == 0 || len(body) > complianceCurrentFrameLimit || base64.StdEncoding.EncodeToString(body) != encoded || !bytes.Equal(body, expected) || !complianceCurrentFrameValid(k, body, now) {
		return nil, ErrInvalid
	}
	supplied, err := hex.DecodeString(textMAC)
	if err != nil {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, k.key[:])
	_, _ = mac.Write([]byte(complianceCurrentFrameDomain + "\x00"))
	_, _ = mac.Write(body)
	computed := mac.Sum(nil)
	defer clear(computed)
	if !hmac.Equal(supplied, computed) {
		return nil, ErrInvalid
	}
	return append([]byte(nil), body...), nil
}
func validateComplianceCurrentModuleClaim(raw []byte) error {
	parsed, err := complianceCurrentJSON(raw, 4096)
	if err != nil {
		return ErrInvalid
	}
	m, ok := complianceCurrentObject(parsed, "domain", "profile", "module_checksum", "statement_sha256", "arguments_sha256", "operation", "subaction", "decision_sha256")
	if !ok || m["domain"] != "zasp-compliance-current-api-operation-v1" || m["profile"] != complianceCurrentModuleProfile {
		return ErrInvalid
	}
	for _, k := range []string{"module_checksum", "statement_sha256", "arguments_sha256", "decision_sha256"} {
		if !complianceCurrentHash(m[k]) {
			return ErrInvalid
		}
	}
	op, a := complianceCurrentString(m["operation"])
	sub, b := complianceCurrentString(m["subaction"])
	if !a || !b {
		return ErrInvalid
	}
	allowed := op == "create" && sub == "create" || op == "get" && sub == "get" || op == "read" && (sub == "listControls" || sub == "listEvidence" || sub == "getEvidence") || op == "grant" && (sub == "issue" || sub == "read" || sub == "consume" || sub == "integrity_failure")
	if !allowed {
		return ErrInvalid
	}
	return nil
}
func complianceCurrentArgumentsDigest(args []any, specs []complianceCurrentArgumentSpec) (string, error) {
	if len(args) != len(specs) || len(args) > 128 {
		return "", ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("zasp-compliance-current-arguments-v1\x00"))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(args)))
	_, _ = h.Write(count[:])
	total := 0
	for i, spec := range specs {
		if spec.Kind < 1 || spec.Kind > 5 {
			return "", ErrInvalid
		}
		tag := spec.Kind
		var value []byte
		if args[i] == nil {
			if !spec.Nullable {
				return "", ErrInvalid
			}
			tag = 6
		} else {
			switch spec.Kind {
			case 1:
				v, ok := args[i].(string)
				if !ok || len(v) > (16<<20)+4096 || !utf8.ValidString(v) {
					return "", ErrInvalid
				}
				value = []byte(v)
			case 2:
				v, ok := args[i].([]byte)
				if !ok || v == nil {
					return "", ErrInvalid
				}
				value = v
			case 3:
				v, ok := args[i].(int64)
				if !ok {
					return "", ErrInvalid
				}
				value = []byte(strconv.FormatInt(v, 10))
			case 4:
				v, ok := args[i].(bool)
				if !ok {
					return "", ErrInvalid
				}
				value = []byte("0")
				if v {
					value = []byte("1")
				}
			case 5:
				v, ok := args[i].(json.RawMessage)
				if !ok {
					return "", ErrInvalid
				}
				if _, err := complianceCurrentJSON(v, (16<<20)+4096); err != nil {
					return "", ErrInvalid
				}
				value = v
			}
		}
		if len(value) > (16<<20)+4096 || total > (32<<20)-len(value) {
			return "", ErrInvalid
		}
		total += len(value)
		_, _ = h.Write([]byte{tag})
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(value)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
