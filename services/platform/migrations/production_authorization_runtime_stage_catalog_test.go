package migrations

import (
	"strings"
	"testing"
)

func TestWorkerRuntimeStageStatementCatalogProjection(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, required := range []string{
		"MESSAGE='runtime precision statement trigger branch changed'",
		"AND NOT(t.tgrelid=''public.zasp_runtime_stage_work''::regclass AND t.tgname=''zasp_authorization80_runtime_stage_insert'')",
		"concat_ws('|','runtime-stage-insert-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text)",
		"WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("assembled runtime stage catalog lacks exact contract %q", required)
		}
	}
}
