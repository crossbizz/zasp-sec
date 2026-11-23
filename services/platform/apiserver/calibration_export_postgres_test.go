package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestCalibrationExportOnInstalledPostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	user := b.member("security_admin", "manage_api_tokens", "view_compliance")
	reader := &compliancePGReader{}
	h := calibrationExportHTTP{b.product, reader}
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,false) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
	})
	create := func() *httptest.ResponseRecorder {
		return b.serve(h, user, "createCalibrationExport", "POST", "/api/v1/calibration/exports", nil, "{}", map[string]string{"Idempotency-Key": "export-calibration-test-key"})
	}
	created := create()
	var job struct{ ID, Status string }
	if created.Code != 202 || json.Unmarshal(created.Body.Bytes(), &job) != nil || job.Status != "queued" {
		t.Fatal(created.Code, created.Body)
	}
	if replay := create(); replay.Code != 202 || replay.Body.String() != created.Body.String() {
		t.Fatal("idempotency", replay.Code, replay.Body)
	}
	path := "/api/v1/calibration/exports/" + job.ID
	op := func(name, method, suffix, payload string) *httptest.ResponseRecorder {
		return b.serve(h, user, name, method, path+suffix, map[string]string{"id": job.ID}, payload, nil)
	}
	issue := func() *httptest.ResponseRecorder {
		return op("createCalibrationDownloadGrant", "POST", "/download-grants", "{}")
	}
	if res := issue(); res.Code != 409 {
		t.Fatal("premature grant", res.Code, res.Body)
	}
	var claim struct {
		ID, Lease string
		Snapshot  []json.RawMessage
	}
	worker := b.login("zasp_svc_compliance_worker")
	workerRPC := func(statement string, args ...any) string {
		args = append(args, migrations.ComplianceChecksum(), migrations.ComplianceFingerprint())
		var result string
		if err := worker.QueryRow(b.ctx, statement, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	raw := workerRPC(`SELECT public.zasp_calibration_export_worker(NULL,NULL,NULL,NULL,$1,$2)::text`)
	if json.Unmarshal([]byte(raw), &claim) != nil || claim.ID != job.ID || len(claim.Snapshot) != 0 {
		t.Fatal(raw)
	}
	data := []byte("{\"schema_version\":\"zasp.calibration.v1\",\"samples\":0}\n")
	sum := sha256.Sum256(data)
	ref, _ := domain.ParseEvidenceRef(job.ID)
	reader.artifact = artifactstore.Artifact{Locator: artifactstore.Locator{Scope: b.scope, Reference: ref, VersionID: "s3-version-123"}, MediaType: "application/x-ndjson", Body: data, Size: int64(len(data)), SHA256: sum}
	if !strings.Contains(workerRPC(`SELECT public.zasp_calibration_export_worker($1::uuid,$2,$3,$4,$5,$6)::text`, claim.Lease, reader.artifact.VersionID, hex.EncodeToString(sum[:]), len(data)), "true") {
		t.Fatal("failed to finish job")
	}
	if res := op("getCalibrationExport", "GET", "", ""); res.Code != 200 || !strings.Contains(res.Body.String(), `"ready"`) {
		t.Fatal(res.Code, res.Body)
	}
	issued := issue()
	var grant struct{ Grant string }
	if issued.Code != 200 || json.Unmarshal(issued.Body.Bytes(), &grant) != nil || len(grant.Grant) != 64 {
		t.Fatal("grant", issued.Code)
	}
	req, _ := json.Marshal(map[string]string{"grant": grant.Grant})
	download := func() *httptest.ResponseRecorder {
		return op("downloadCalibrationExport", "POST", "/download", string(req))
	}
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issueToken, _ := installedWorkloadTokenIssuer(t, b, repo, user)
	token := issueToken("Calibration export", `["view_compliance"]`)
	downloadPAT := func() *httptest.ResponseRecorder {
		return b.serve(h, token, "downloadCalibrationExport", "POST", path+"/download", map[string]string{"id": job.ID}, string(req), nil)
	}
	reader.artifact.MediaType = "text/plain"
	if bad := download(); bad.Code != 503 {
		t.Fatal("storage integrity", bad.Code, bad.Body)
	}
	reader.artifact.MediaType = "application/x-ndjson"
	if res := downloadPAT(); res.Code != 200 || res.Header().Get("Cache-Control") != "no-store" || !strings.Contains(res.Body.String(), hex.EncodeToString(sum[:])) {
		t.Fatal("download", res.Code, res.Body)
	}
	if replay := download(); replay.Code != 409 {
		t.Fatal("reused grant", replay.Code, replay.Body)
	}
}

func TestQualificationRequestOnInstalledPostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	user := b.member("security_admin", "manage_data_controls", "view_compliance")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		serveQualificationRun(b.product, w, r, op)
	})
	const model = "mistralai/Shieldstral-1.0-3B"
	body := `{"provider":"zasp_vpc_slm","model":"` + model + `","purpose":"purpose_alignment_check"}`
	request := func() *httptest.ResponseRecorder {
		return b.serve(h, user, "runModelQualification", "POST", "/api/v1/ai/qualifications/run", nil, body, map[string]string{"Idempotency-Key": "qualification-test-request"})
	}
	if res := request(); res.Code != 409 {
		t.Fatal(res.Code, res.Body)
	}
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'staging','metadata_only',30,false) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO public.zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency) VALUES($1,true,ARRAY['zasp_vpc_slm','deterministic_only'],'eu_only')`, b.o)
		b.exec(`INSERT INTO public.zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier2_profile,monthly_budget_nano_credits) VALUES($1,$2,$3,'staging','zasp_vpc_slm',$4,2)`, b.o, b.w, b.e, model)
		b.exec(`INSERT INTO public.model_qualification_workers VALUES($1,$2,$3,'zasp_vpc_slm',$4,'purpose_alignment_check','sha256:'||repeat('a',64),'eu',2,now()+interval '30 seconds')`, b.o, b.w, b.e, model)
	})
	res := request()
	var job struct{ ID, Status string }
	if res.Code != 202 || json.Unmarshal(res.Body.Bytes(), &job) != nil || job.Status != "queued" {
		t.Fatal(res.Code, res.Body)
	}
	if replay := request(); replay.Code != 202 || replay.Body.String() != res.Body.String() {
		t.Fatal("replay", replay.Code, replay.Body)
	}
	lease := b.text(`UPDATE public.model_qualification_runs SET status='running',lease=gen_random_uuid() WHERE id=$1 RETURNING lease::text`, job.ID)
	observe := func() string {
		return b.text(`SELECT zasp_authorization80.qualify_observation($1,$2,$3,$4,$5::uuid)::text`, b.o, b.w, b.e, job.ID, lease)
	}
	if observe() != "true" || observe() != "false" {
		t.Fatal("reservation must exhaust scope budget")
	}
	get := b.serve(h, user, "getModelQualificationRun", "GET", "/api/v1/ai/qualifications/runs/"+job.ID, map[string]string{"id": job.ID}, "", nil)
	if get.Code != 200 || !strings.Contains(get.Body.String(), "running") {
		t.Fatal(get.Code, get.Body)
	}
}
