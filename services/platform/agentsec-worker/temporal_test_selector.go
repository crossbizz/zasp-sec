package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/temporal"
)

type temporalTestSelectorSource struct {
	session   temporalDiscoveryScheduleSource
	automatic bool
}

func (s *temporalTestSelectorSource) protocol(ctx context.Context, c *pgx.Conn) (string, error) {
	present, err := automaticSourcesAvailable(ctx, automaticSelectorDatabase{c})
	if err != nil || !present || !s.automatic {
		return "", errWorkerExecution
	}
	return "zasp_temporal77", nil
}

func (s *temporalTestSelectorSource) WithCurrentSelector(ctx context.Context, ref orchestration.TestSelectorRef, fn func(orchestration.TestSelectorDesired) error) error {
	id, err := orchestration.TestSelectorID(ref)
	if err != nil || fn == nil {
		return errWorkerExecution
	}
	return s.session.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		schema, err := s.protocol(ctx, c)
		if err != nil {
			return err
		}
		if _, err := c.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, id); err != nil {
			return errWorkerExecution
		}
		encoded, _ := json.Marshal(ref)
		var raw []byte
		if c.QueryRow(ctx, `SELECT `+schema+`.desired($1::jsonb)`, string(encoded)).Scan(&raw) != nil {
			return errWorkerExecution
		}
		var d orchestration.TestSelectorDesired
		if decodeStrictWorkerJSON(raw, &d) != nil || !d.Valid() || d.Ref != ref {
			return errWorkerExecution
		}
		if err := fn(d); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return orchestration.ErrScheduleOutcomeUnknown
		}
		// There is no cross-store acknowledgement. The durable desired row stays
		// eligible for repair; an ambiguous write is returned and retried unchanged.
		return nil
	})
}
func (s *temporalTestSelectorSource) references(ctx context.Context, after string, limit int) (refs []orchestration.TestSelectorRef, err error) {
	err = s.session.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		schema, err := s.protocol(ctx, c)
		if err != nil {
			return err
		}
		var raw []byte
		if c.QueryRow(ctx, `SELECT `+schema+`.references($1,$2)`, after, limit).Scan(&raw) != nil || json.Unmarshal(raw, &refs) != nil {
			return errWorkerExecution
		}
		for _, r := range refs {
			if !r.Valid() {
				return errWorkerExecution
			}
		}
		return nil
	})
	return
}
func (s *temporalTestSelectorSource) Ready(ctx context.Context) error {
	_, err := s.references(ctx, "", 1)
	return err
}

type temporalTestSelectorProcessor struct {
	mu         sync.Mutex
	source     *temporalTestSelectorSource
	reconciler *orchestration.TestSelectorReconciler
	after      string
}

func (p *temporalTestSelectorProcessor) RunOnce(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	refs, err := p.source.references(ctx, p.after, 25)
	if err != nil {
		return err
	}
	var result error
	for _, ref := range refs {
		result = errors.Join(result, p.reconciler.Reconcile(ctx, ref))
		p.after = strings.Join([]string{ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.DefinitionID}, "/")
	}
	if len(refs) < 25 {
		p.after = ""
	}
	return result
}

func testSelectorAvailable(ctx context.Context, db apiserver.JSONDatabase) (bool, error) {
	raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal75') IS NOT NULL)`)
	if err != nil {
		return false, errWorkerExecution
	}
	var present bool
	if json.Unmarshal(raw, &present) != nil {
		return false, errWorkerExecution
	}
	if !present {
		return false, nil
	}
	raw, err = db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal75.ready($1,$2))`, migrations.ProductionTemporalTestSelector().Checksum(), migrations.TemporalTestSelectorFingerprint())
	var ready bool
	if err != nil || json.Unmarshal(raw, &ready) != nil || !ready {
		return false, errWorkerExecution
	}
	return true, nil
}
func (p *temporalSecurityAgentProduct) AdmitTestSelector(ctx context.Context, q orchestration.TestSelectorStart) error {
	if !q.Ref.Valid() || q.Revision < 1 || q.Revision > 1000000 {
		return temporal.NewNonRetryableApplicationError("selector request rejected", "invalid", nil)
	}
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	// A retained Schedule may still invoke the legacy Activity.77's SQL guard
	// prevents configured-row admission while keeping omitted-rule75 semantics.
	if p == nil || p.executor == nil {
		return orchestration.ErrUnavailable
	}
	if ready, err := automaticSourcesAvailable(bounded, p.executor); err != nil || !ready {
		return orchestration.ErrUnavailable
	}
	body, _ := json.Marshal(q)
	raw, err := p.executor.QueryJSON(bounded, `SELECT zasp_temporal75.admit($1::jsonb)`, string(body))
	if err != nil {
		return orchestration.ErrUnavailable
	}
	var result struct {
		Created int `json:"created"`
	}
	if decodeStrictWorkerJSON(raw, &result) != nil || result.Created < 0 || result.Created > 25 {
		return orchestration.ErrUnavailable
	}
	return nil
}
