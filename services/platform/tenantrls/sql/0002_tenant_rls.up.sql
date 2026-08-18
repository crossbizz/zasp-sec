ALTER TABLE "public"."organizations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."organizations" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."organizations" AS PERMISSIVE FOR ALL
USING ("id" = current_setting('app.current_organization_id', true))
WITH CHECK ("id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."workspace_grants" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."workspace_grants" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."workspace_grants" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."integrations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."integrations" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."integrations" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."policies" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."policies" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."policies" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."findings" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."findings" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."findings" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."tests" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."tests" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."tests" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."audit_metadata" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."audit_metadata" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."audit_metadata" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));

ALTER TABLE "public"."export_jobs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."export_jobs" FORCE ROW LEVEL SECURITY;
CREATE POLICY "zasp_organization_scope" ON "public"."export_jobs" AS PERMISSIVE FOR ALL
USING ("organization_id" = current_setting('app.current_organization_id', true))
WITH CHECK ("organization_id" = current_setting('app.current_organization_id', true));
