package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// This installer-only artifact records static executable definitions and pins,
// never worker verifier material, product rows or an authorization result.
func TestP7OrderedReadinessClosure(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_READINESS_CAPTURE") == "" {
		t.Skip("explicit static catalog destination required")
	}
	runOrdered68PolicyBoundary(t, true, false, false)
}

func captureOrderedReadinessClosure(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
	t.Helper()
	if runReadinessAttribution(t, ctx, owner) {
		return true
	}
	destination := os.Getenv("ZASP_ORDERED_READINESS_CAPTURE")
	if destination == "" {
		return false
	}
	var raw json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'functions',(SELECT jsonb_agg(jsonb_build_object('signature',p.oid::regprocedure::text,'schema',n.nspname,'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid),'source',p.prosrc,'owner',p.proowner::regrole::text,'acl',p.proacl::text,'language',l.lanname,'volatility',p.provolatile,'security_definer',p.prosecdef,'strict',p.proisstrict,'parallel',p.proparallel,'config',p.proconfig) ORDER BY n.nspname,p.proname,p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE p.prokind='f' AND(left(n.nspname,5)='zasp_' OR n.nspname='public' AND left(p.proname,5)='zasp_')),
 'schemas',(SELECT jsonb_agg(jsonb_build_object('name',nspname,'owner',nspowner::regrole::text,'acl',nspacl::text) ORDER BY nspname) FROM pg_namespace WHERE left(nspname,5)='zasp_'),
 'registrations',jsonb_build_object('worker',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_authorization80_worker.registration r),'temporal',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_authorization80_temporal.registration r),'authorization79',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_authorization79.registration r),'executor68',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_temporal68.registration r),'lifecycle69',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_temporal69.registration r),'finding78',(SELECT jsonb_agg(to_jsonb(r)) FROM zasp_temporal78.registration r)))`).Scan(&raw); err != nil {
		t.Fatal("capture static readiness catalog", err)
	}
	var artifact struct {
		Functions []json.RawMessage `json:"functions"`
	}
	if len(raw) > 64*1024*1024 || json.Unmarshal(raw, &artifact) != nil || len(artifact.Functions) == 0 || len(artifact.Functions) > 10000 {
		t.Fatal("static readiness catalog bounds")
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create static readiness artifact", err)
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("write static readiness artifact", writeErr, closeErr)
	}
	digest := sha256.Sum256(raw)
	t.Log("static readiness catalog functions", len(artifact.Functions), "bytes", len(raw), "sha256", hex.EncodeToString(digest[:]))
	return true
}
