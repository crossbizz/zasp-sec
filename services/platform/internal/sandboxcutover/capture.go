package sandboxcutover

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
	"strconv"
)

const maxCaptureRecords = 10000
const maxCaptureBytes = 16 << 20
const maxCaptureRowBytes = 1 << 20

type captureQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Start with canonical receipts, not queue rows. Every missing LEFT JOIN target
// must survive the scan as an explicit refusal. Limit+1 detects overflow rather
// than silently authorizing a prefix. The server also bounds each wire row.
const captureSQL = `SELECT CASE WHEN octet_length(payload::text)<=$1 THEN payload ELSE NULL END
FROM (
 SELECT jsonb_build_object(
 'Organization',r.organization_id,'Workspace',r.workspace_id,'Environment',r.environment_id,
 'Batch',r.batch_id,'Generation',r.batch_generation,'Digest',encode(r.receipt_digest,'hex'),
 'Events',r.event_ids,'Documents',q.document_ids,'Reference',q.receipt_reference,'Version',q.receipt_version,
 'ProjectVersion',p.implementation_version,'CompleteVersion',c.implementation_version,
 'Valid',COALESCE(p.state='succeeded' AND c.state='succeeded' AND q.state='indexed'
 AND p.result_digest=r.receipt_digest AND q.receipt_digest=r.receipt_digest
 AND p.result_reference=q.receipt_reference AND p.result_version_id=q.receipt_version,false)) AS payload,
 r.organization_id,r.workspace_id,r.environment_id,r.batch_id,r.batch_generation
 FROM public.zasp_runtime_session_projection_receipts r
 LEFT JOIN public.zasp_runtime_stage_work p ON (p.organization_id,p.workspace_id,p.environment_id,p.batch_id,p.batch_generation,p.stage)=(r.organization_id,r.workspace_id,r.environment_id,r.batch_id,r.batch_generation,'project')
 LEFT JOIN public.zasp_runtime_stage_work c ON (c.organization_id,c.workspace_id,c.environment_id,c.batch_id,c.batch_generation,c.stage)=(r.organization_id,r.workspace_id,r.environment_id,r.batch_id,r.batch_generation,'complete')
 LEFT JOIN public.zasp_runtime_sandbox_search_outbox q ON (q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation)=(r.organization_id,r.workspace_id,r.environment_id,r.batch_id,r.batch_generation)
 ORDER BY r.organization_id COLLATE "C",r.workspace_id COLLATE "C",r.environment_id COLLATE "C",r.batch_id COLLATE "C",r.batch_generation
 LIMIT $2
) captured ORDER BY organization_id COLLATE "C",workspace_id COLLATE "C",environment_id COLLATE "C",batch_id COLLATE "C",batch_generation`

type captureWire struct {
	Organization, Workspace, Environment, Batch                 string
	Generation                                                  int64
	Digest, Reference, Version, ProjectVersion, CompleteVersion string
	Events, Documents                                           []string
	Valid                                                       bool
}

func captureReceipts(ctx context.Context, q captureQuery) (Capture, error) {
	rows, err := q.Query(ctx, captureSQL, maxCaptureRowBytes, maxCaptureRecords+1)
	if err != nil {
		return Capture{}, errRejected
	}
	defer rows.Close()
	result := Capture{Records: []ReceiptRecord{}}
	digest := sha256.New()
	digest.Write([]byte("zasp.sandbox-cutover.receipts.v1\x00"))
	total := 0
	for rows.Next() {
		var body []byte
		if rows.Scan(&body) != nil || len(result.Records) == maxCaptureRecords || len(body) == 0 || len(body) > maxCaptureRowBytes {
			return Capture{}, errRejected
		}
		total += len(body)
		if total > maxCaptureBytes {
			return Capture{}, errRejected
		}
		var wire captureWire
		if json.Unmarshal(body, &wire) != nil {
			return Capture{}, errRejected
		}
		record, err := decodeCaptureRecord(wire)
		if err != nil {
			return Capture{}, err
		}
		// Encode explicit scope fields, not domain.Scope's private Go fields.
		canonical, err := json.Marshal(wire)
		if err != nil {
			return Capture{}, errRejected
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(canonical)))
		digest.Write(size[:])
		digest.Write(canonical)
		result.Records = append(result.Records, record)
	}
	if rows.Err() != nil || ctx.Err() != nil {
		return Capture{}, errRejected
	}
	result.Digest = hex.EncodeToString(digest.Sum(nil))
	return result, nil
}

func decodeCaptureRecord(w captureWire) (ReceiptRecord, error) {
	if !w.Valid || w.Generation < 1 || !text(w.Reference) || len(w.Reference) > 2048 || !text(w.Version) || len(w.Version) > 1024 || len(w.Events) < 1 || len(w.Events) > 1000 || len(w.Documents) != len(w.Events) {
		return ReceiptRecord{}, errRejected
	}
	if !((w.ProjectVersion == "runtime-projection-v1" && w.CompleteVersion == "runtime-complete-v1") || (w.ProjectVersion == "runtime-projection-v2" && w.CompleteVersion == "runtime-complete-v2")) {
		return ReceiptRecord{}, errRejected
	}
	org, e1 := domain.ParseProductID(w.Organization)
	ws, e2 := domain.ParseProductID(w.Workspace)
	env, e3 := domain.ParseProductID(w.Environment)
	batch, e4 := domain.ParseProductID(w.Batch)
	scope, e5 := domain.NewScope(org, ws, env)
	rawDigest, e6 := hex.DecodeString(w.Digest)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || len(rawDigest) != 32 || !digest(w.Digest) {
		return ReceiptRecord{}, errRejected
	}
	binding := sessionsearch.ReceiptBinding{Scope: scope, BatchID: batch, Generation: w.Generation}
	copy(binding.ReceiptDigest[:], rawDigest)
	if binding.ReceiptDigest == ([32]byte{}) {
		return ReceiptRecord{}, errRejected
	}
	seen := map[string]bool{}
	for i, event := range w.Events {
		if _, err := domain.ParseProductID(event); err != nil || seen[event] {
			return ReceiptRecord{}, errRejected
		}
		seen[event] = true
		identity := "zasp.runtime-session-search.occurrence.v1\x00" + w.Organization + "\x00" + w.Workspace + "\x00" + w.Environment + "\x00" + w.Batch + "\x00" + strconv.FormatInt(w.Generation, 10) + "\x00" + event
		doc := sha256.Sum256([]byte(identity))
		if w.Documents[i] != hex.EncodeToString(doc[:]) {
			return ReceiptRecord{}, errRejected
		}
	}
	return ReceiptRecord{Binding: binding, ReceiptReference: w.Reference, ReceiptVersion: w.Version, ProjectVersion: w.ProjectVersion, CompleteVersion: w.CompleteVersion, EventIDs: w.Events, DocumentIDs: w.Documents}, nil
}
