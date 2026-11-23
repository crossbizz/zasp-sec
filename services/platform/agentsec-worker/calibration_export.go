package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Tier: 4 | Purpose: frozen calibration evidence export.
// Model: none. A lease exposes only preselected redacted fields.
// Authority: the compliance export identity writes a scoped, immutable object.
// Fallback: retry the same frozen bytes after lease expiry.
func (p *complianceExportProcessor) exportCalibration(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	raw, err := p.authority.query(bounded, `SELECT public.zasp_calibration_export_worker(NULL,NULL,NULL,NULL,$1,$2)`, 2<<20)
	if err != nil || string(raw) == "null" {
		return err
	}
	var j struct {
		O        string            `json:"organization_id"`
		W        string            `json:"workspace_id"`
		E        string            `json:"environment_id"`
		ID       string            `json:"id"`
		Lease    string            `json:"lease"`
		Snapshot []json.RawMessage `json:"snapshot"`
	}
	if json.Unmarshal(raw, &j) != nil || j.Snapshot == nil || len(j.Snapshot) > 2048 || len(j.Lease) != 36 {
		return errWorkerExecution
	}
	o, e1 := domain.ParseProductID(j.O)
	w, e2 := domain.ParseProductID(j.W)
	e, e3 := domain.ParseProductID(j.E)
	id, e4 := domain.ParseProductID(j.ID)
	scope, e5 := domain.NewScope(o, w, e)
	ref, e6 := domain.NewEvidenceRef(id)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil {
		return errWorkerExecution
	}
	var buf bytes.Buffer
	header, _ := json.Marshal(map[string]any{"schema_version": "zasp.calibration.v1", "samples": len(j.Snapshot), "days": 30, "maximum_samples": 2048})
	buf.Write(header)
	buf.WriteByte('\n')
	for _, row := range j.Snapshot {
		if json.Compact(&buf, row) != nil {
			return errWorkerExecution
		}
		buf.WriteByte('\n')
	}
	if buf.Len() > 1<<20 {
		return errWorkerExecution
	}
	item, err := p.store.Put(bounded, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/x-ndjson", Body: buf.Bytes()})
	if err != nil {
		return err
	}
	result, err := p.authority.query(bounded, `SELECT public.zasp_calibration_export_worker($1::uuid,$2,$3,$4,$5,$6)`, 32, j.Lease, item.VersionID, hex.EncodeToString(item.SHA256[:]), int(item.Size))
	if err != nil || string(result) != "true" {
		return errWorkerExecution
	}
	return nil
}
