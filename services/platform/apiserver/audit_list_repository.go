package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAuditPublicPageReadySQL = `SELECT to_jsonb(zasp_audit_export_public_page_readiness($1,$2))`
const postgresAuditPublicPageSQL = `SELECT zasp_audit_export_public_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
const auditListHardBytes = 1 << 20
const auditListPrivateBytes = auditListHardBytes + 4096

// AuditPublicPageRepository binds list reads to the reviewed release and current
// registered API authority. It carries no storage or export-job capability.
type AuditPublicPageRepository struct {
	database              JSONDatabase
	checksum, fingerprint string
}
type auditPublicPageRequest struct {
	sessionDigest []byte
	filters       auditListFilters
	afterTime     time.Time
	// A parsed year-one instant is Go's zero time, but is not SQL NULL.
	afterTimeSet bool
	afterID      string
	limit        int
}
type auditPublicPage struct {
	items   []json.RawMessage
	hasMore bool
}

func NewAuditPublicPageRepository(parent context.Context, database JSONDatabase) (*AuditPublicPageRepository, error) {
	if parent == nil || nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	r := &AuditPublicPageRepository{database, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}
	if err := r.Ready(parent); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *AuditPublicPageRepository) configured() bool {
	return r != nil && !nilInterface(r.database) && r.checksum == migrations.ProductionAuditExports().Checksum() && r.fingerprint == migrations.ProductionAuditExportsSemanticFingerprint()
}
func (r *AuditPublicPageRepository) Ready(parent context.Context) error {
	if !r.configured() || parent == nil {
		return ErrRepositoryUnavailable
	}
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if current, err := currentAuthorizationSourceReady(ctx, r.database, 52, r.checksum, r.fingerprint); current {
		return err
	}
	raw, err := r.database.QueryJSON(ctx, postgresAuditPublicPageReadySQL, r.checksum, r.fingerprint)
	if e := ctx.Err(); e != nil {
		return e
	}
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) || len(raw) > 16 {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (r *AuditPublicPageRepository) read(parent context.Context, identity RequestIdentity, in auditPublicPageRequest) (auditPublicPage, error) {
	fail := auditPublicPage{}
	if !r.configured() || parent == nil {
		return fail, ErrRepositoryUnavailable
	}
	if err := parent.Err(); err != nil {
		return fail, err
	}
	if !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession {
		return fail, ErrRepositoryAuthentication
	}
	if !currentRequestHasPermission(parent, identity, "view_audit") {
		return fail, ErrAuditExportForbidden
	}
	if len(in.sessionDigest) != sha256.Size || bytes.Equal(in.sessionDigest, make([]byte, sha256.Size)) || in.limit < 1 || in.limit > 100 {
		return fail, ErrRepositoryOperation
	}
	filters, err := parseAuditListQuery(in.filters.values().Encode(), identity)
	if err != nil || filters.filters != in.filters || len(in.filters.bytes()) > 1024 {
		return fail, ErrRepositoryOperation
	}
	var afterTime, afterID any
	if in.afterTimeSet || !in.afterTime.IsZero() || in.afterID != "" {
		if !validProductID(in.afterID) || in.afterTime.IsZero() && !in.afterTimeSet || in.afterTime.Year() < 1 || in.afterTime.Year() > 9999 || in.afterTime.Nanosecond()%1000 != 0 {
			return fail, ErrRepositoryOperation
		}
		afterTime = in.afterTime.UTC()
		afterID = in.afterID
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := r.Ready(ctx); err != nil {
		return fail, err
	}
	raw, err := r.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresAuditPublicPageSQL, `SELECT zasp_authorization80.audit_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(in.sessionDigest), identity.CSRFToken, in.filters.bytes(), afterTime, afterID, in.limit, r.checksum, r.fingerprint)
	if e := ctx.Err(); e != nil {
		return fail, e
	}
	if err != nil {
		return fail, auditListRepositoryError(err)
	}
	page, err := decodeAuditPublicPage(raw, in)
	if e := ctx.Err(); e != nil {
		return fail, e
	}
	return page, err
}

func auditListRepositoryError(err error) error {
	classified := auditExportRepositoryError(err)
	for _, permitted := range []error{context.Canceled, context.DeadlineExceeded, ErrRepositoryOperation, ErrRepositoryAuthentication, ErrAuditExportForbidden} {
		if errors.Is(classified, permitted) {
			return permitted
		}
	}
	// A read-only page has no conflict or missing-record success alternative.
	// Cursor404 is produced before SQL, never from an unexpected source error.
	return ErrRepositoryUnavailable
}

// encoding/json replaces malformed Unicode scalars. Refuse them before decoding
// so RawMessage validation cannot silently disagree with the public wire.
func auditListScalarJSON(raw []byte) bool {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
func auditListUTF16(value string, maximum int) bool {
	units := 0
	for _, r := range value {
		units++
		if r > 0xffff {
			units++
		}
		if units > maximum {
			return false
		}
	}
	return true
}
func auditListMetadata(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || len(seen) >= 32 {
			return false
		}
		seen[name] = true
		var rawValue json.RawMessage
		if d.Decode(&rawValue) != nil || len(rawValue) == 0 || rawValue[0] != '"' {
			return false
		}
		var value string
		if json.Unmarshal(rawValue, &value) != nil || !auditListUTF16(value, 512) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && end == json.Delim('}') && d.Decode(&struct{}{}) == io.EOF
}
func decodeAuditPublicPage(raw []byte, in auditPublicPageRequest) (auditPublicPage, error) {
	fail := auditPublicPage{}
	if len(raw) > auditListPrivateBytes || !auditListScalarJSON(raw) {
		return fail, ErrRepositoryUnavailable
	}
	root, err := auditExportClosedObject(raw, auditListPrivateBytes, "items", "has_more")
	if err != nil {
		return fail, err
	}
	page := auditPublicPage{}
	if bytes.Equal(root["has_more"], []byte("true")) {
		page.hasMore = true
	} else if !bytes.Equal(root["has_more"], []byte("false")) {
		return fail, ErrRepositoryUnavailable
	}
	if len(root["items"]) == 0 || root["items"][0] != '[' || json.Unmarshal(root["items"], &page.items) != nil || len(page.items) > in.limit || page.hasMore && len(page.items) == 0 {
		return fail, ErrRepositoryUnavailable
	}
	previousTime, previousID := in.afterTime, in.afterID
	seen := map[string]bool{}
	for _, item := range page.items {
		fields, err := auditExportClosedObject(item, auditListPrivateBytes, "id", "workspace_id", "environment_id", "actor_id", "action", "target_id", "outcome", "metadata", "occurred_at")
		if err != nil {
			return fail, err
		}
		values := map[string]string{}
		for key, rawValue := range fields {
			if key == "metadata" {
				continue
			}
			var value string
			if len(rawValue) == 0 || rawValue[0] != '"' || json.Unmarshal(rawValue, &value) != nil {
				return fail, ErrRepositoryUnavailable
			}
			values[key] = value
		}
		for _, key := range []string{"id", "workspace_id", "environment_id", "actor_id"} {
			if !validProductID(values[key]) {
				return fail, ErrRepositoryUnavailable
			}
		}
		at, ok := auditListTime(values["occurred_at"])
		if !ok || at.Format(auditListTimeLayout) != values["occurred_at"] || !validAuditListAction(values["action"]) || values["target_id"] == "" || !auditListUTF16(values["target_id"], 128) || !stringIn(values["outcome"], "succeeded", "denied", "failed") || !auditListMetadata(fields["metadata"]) {
			return fail, ErrRepositoryUnavailable
		}
		id := values["id"]
		if seen[id] || previousID != "" && (at.After(previousTime) || at.Equal(previousTime) && id >= previousID) {
			return fail, ErrRepositoryUnavailable
		}
		seen[id] = true
		previousTime, previousID = at, id
		f := in.filters
		if f.actorID != "" && f.actorID != values["actor_id"] || f.action != "" && f.action != values["action"] || f.outcome != "" && f.outcome != values["outcome"] || f.from != "" && values["occurred_at"] < f.from || f.to != "" && values["occurred_at"] >= f.to {
			return fail, ErrRepositoryUnavailable
		}
	}
	return page, nil
}
