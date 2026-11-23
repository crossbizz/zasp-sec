package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type queueProfile struct {
	ids              []string
	attestation      aigateway.DeploymentAttestation
	manifest, corpus []byte
	digest, region   string
	cost             int64
	driver           aigateway.ProviderDriver
}

func serveJobs(ctx context.Context, ids []string, manifest []byte, a aigateway.DeploymentAttestation, driver aigateway.ProviderDriver, digest string, corpus []byte) error {
	conn, err := pgx.Connect(ctx, os.Getenv("ZASP_QUALIFICATION_DATABASE_URL"))
	if err != nil {
		return errors.New("qualification database unavailable")
	}
	defer conn.Close(ctx)
	region, cost := a.Deployment.Region, a.Deployment.MaximumNanoCredits
	if a.Bedrock != nil {
		region = "us"
		if strings.Contains(a.Bedrock.VPCEHost, ".eu-") {
			region = "eu"
		}
		cost = a.Bedrock.MaximumNanoCredits
	}
	if a.Vertex != nil {
		region = "us"
		if strings.HasPrefix(a.Vertex.Location, "europe-") {
			region = "eu"
		}
		cost = a.Vertex.MaximumNanoCredits
	}
	q := queueProfile{ids, a, manifest, corpus, digest, region, cost, driver}
	for time.Now().Before(a.ExpiresAt) {
		if err := q.poll(ctx, conn); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return errors.New("qualification profile expired")
}

func (q queueProfile) poll(ctx context.Context, db *pgx.Conn) error {
	a := q.attestation
	args := []any{q.ids[0], q.ids[1], q.ids[2], a.ProviderMode(), a.ModelName(), a.Purpose, q.digest}
	_, err := db.Exec(ctx, `INSERT INTO public.model_qualification_workers VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,least($10,now()+interval '30 seconds'))
 ON CONFLICT (organization_id,workspace_id,environment_id,provider,model,purpose) DO UPDATE SET deployment_digest=excluded.deployment_digest,region=excluded.region,cost_per_call=excluded.cost_per_call,available_until=excluded.available_until`, append(args, q.region, q.cost, a.ExpiresAt)...)
	if err != nil {
		return errors.New("qualification registration failed")
	}
	var id, lease string
	err = db.QueryRow(ctx, `WITH job AS (SELECT id FROM public.model_qualification_runs WHERE (organization_id,workspace_id,environment_id,provider,model,purpose,deployment_digest)=($1,$2,$3,$4,$5,$6,$7)
 AND status='queued' AND requested_at>now()-interval '1 hour' ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
 UPDATE public.model_qualification_runs r SET status='running',lease=gen_random_uuid() FROM job WHERE (r.organization_id,r.workspace_id,r.environment_id,r.id)=($1,$2,$3,job.id) RETURNING r.id,lease::text`, args...).Scan(&id, &lease)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errors.New("qualification admission failed")
	}
	return q.execute(ctx, db, id, lease)
}

type jobDriver struct {
	db      *pgx.Conn
	ids     []any
	driver  aigateway.ProviderDriver
	stopped bool
}

func (j *jobDriver) Evaluate(ctx context.Context, p aigateway.Purpose, input json.RawMessage) (json.RawMessage, error) {
	if j.stopped {
		return nil, errors.New("qualification authorization expired")
	}
	var ok bool
	if err := j.db.QueryRow(ctx, `SELECT zasp_authorization80.qualify_observation($1,$2,$3,$4,$5::uuid)`, j.ids...).Scan(&ok); err != nil || !ok {
		j.stopped = true
		return nil, errors.New("qualification authorization expired")
	}
	return j.driver.Evaluate(ctx, p, input)
}

func (q queueProfile) execute(ctx context.Context, db *pgx.Conn, id, lease string) error {
	args := []any{q.ids[0], q.ids[1], q.ids[2], id, lease}
	bounded, cancel := context.WithDeadline(ctx, minTime(q.attestation.ExpiresAt, time.Now().Add(time.Hour)))
	defer cancel()
	checked := &jobDriver{db: db, ids: args, driver: q.driver}
	result, err := measure(bounded, checked, q.attestation, q.digest, q.corpus)
	approved := err == nil && result.Qualified && !checked.stopped && bounded.Err() == nil
	status := "failed"
	if approved {
		status = "passed"
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current bool
	if err := tx.QueryRow(ctx, `SELECT expires_at>now() FROM (SELECT requested_at+interval '1 hour' AS expires_at FROM public.model_qualification_runs WHERE (organization_id,workspace_id,environment_id,id,lease)=($1,$2,$3,$4,$5::uuid) AND status='running' FOR UPDATE) s`, args...).Scan(&current); err != nil {
		return err
	}
	if !current {
		status = "failed"
	}
	if !checked.stopped && result.Total > 0 {
		result.Qualified = status == "passed"
		if err := record(ctx, tx, q.ids, q.manifest, q.attestation, result); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE public.model_qualification_runs SET status=$6,finished_at=now(),lease=NULL WHERE (organization_id,workspace_id,environment_id,id,lease)=($1,$2,$3,$4,$5::uuid)`, append(args, status)...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func minTime(x, y time.Time) time.Time {
	if x.Before(y) {
		return x
	}
	return y
}
