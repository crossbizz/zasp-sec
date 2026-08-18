DROP POLICY "zasp_organization_scope" ON "public"."export_jobs";
ALTER TABLE "public"."export_jobs" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."export_jobs" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."audit_metadata";
ALTER TABLE "public"."audit_metadata" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."audit_metadata" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."tests";
ALTER TABLE "public"."tests" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."tests" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."findings";
ALTER TABLE "public"."findings" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."findings" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."policies";
ALTER TABLE "public"."policies" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."policies" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."integrations";
ALTER TABLE "public"."integrations" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."integrations" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."workspace_grants";
ALTER TABLE "public"."workspace_grants" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."workspace_grants" DISABLE ROW LEVEL SECURITY;

DROP POLICY "zasp_organization_scope" ON "public"."organizations";
ALTER TABLE "public"."organizations" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."organizations" DISABLE ROW LEVEL SECURITY;
