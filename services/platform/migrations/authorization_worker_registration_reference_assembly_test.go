package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

type workerRegistrationReferenceToken struct {
	Checksum     string `json:"checksum"`
	Fingerprint  string `json:"fingerprint"`
	SourceSHA256 string `json:"source_sha256"`
}

// This emitter compiles the ORIGINAL package's unexported functions. It neither
// installs SQL nor reads a database, an archived assembly, or an evaluator.
type workerRegistrationReferenceAssemblyPacket struct {
	Version                 string                                      `json:"version"`
	GoVersion               string                                      `json:"go_version"`
	InputSHA256             string                                      `json:"input_sha256"`
	ExecutableSHA256        string                                      `json:"executable_sha256"`
	BuildInfo               string                                      `json:"build_info"`
	WorkerSource            string                                      `json:"worker_source"`
	WorkerChecksum          string                                      `json:"worker_checksum"`
	WorkerChecksumPreimage  string                                      `json:"worker_checksum_preimage"`
	WorkerSourceSHA256      string                                      `json:"worker_source_sha256"`
	WorkerFingerprint       string                                      `json:"worker_fingerprint"`
	WorkerCatalog           string                                      `json:"worker_catalog"`
	WorkerCatalogSHA256     string                                      `json:"worker_catalog_sha256"`
	RuntimeSource           string                                      `json:"runtime_source"`
	RuntimeChecksum         string                                      `json:"runtime_checksum"`
	RuntimeChecksumPreimage string                                      `json:"runtime_checksum_preimage"`
	RuntimeSourceSHA256     string                                      `json:"runtime_source_sha256"`
	RuntimeFingerprint      string                                      `json:"runtime_fingerprint"`
	StopSuccessor           string                                      `json:"stop_successor"`
	Tokens                  map[string]workerRegistrationReferenceToken `json:"tokens"`
}

func workerRegistrationReferenceHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func workerRegistrationReferenceAssembly() workerRegistrationReferenceAssemblyPacket {
	w, wc := authorizationWorkerProfileSource()
	r, rc := authorizationRuntimeProfileSource()
	p := workerRegistrationReferenceAssemblyPacket{Version: "original-worker-registration-assembly-v1", GoVersion: runtime.Version(), WorkerSource: w, WorkerChecksum: wc, WorkerSourceSHA256: workerRegistrationReferenceHash(w), WorkerFingerprint: strings.Split(w, "$fingerprint$")[1], WorkerCatalog: strings.Split(w, "$catalog$")[1], RuntimeSource: r, RuntimeChecksum: rc, RuntimeSourceSHA256: workerRegistrationReferenceHash(r), RuntimeFingerprint: strings.Split(r, "$runtime_fingerprint$")[1], StopSuccessor: authorizationWorkerStopSuccessor(ProductionTemporalTestExecutor().UpSQL()), Tokens: map[string]workerRegistrationReferenceToken{}}
	p.WorkerCatalogSHA256 = workerRegistrationReferenceHash(p.WorkerCatalog)
	p.WorkerChecksumPreimage = strings.ReplaceAll(w, wc, "-- worker profile checksum")
	p.RuntimeChecksumPreimage = strings.ReplaceAll(r, rc, "-- runtime profile checksum")
	for _, v := range []struct {
		name string
		m    Metadata
		fp   string
	}{
		{"finding78", ProductionTemporalFindingResponse(), TemporalFindingResponseFingerprint()},
		{"test74", ProductionTemporalTestExecutor(), TemporalTestExecutorFingerprint()},
		{"runtime48", ProductionRuntimeAcceptance(), ProductionRuntimeAcceptanceSemanticFingerprint()},
		{"runtime50", ProductionRuntimeSandboxBinding(), ProductionRuntimeSandboxBindingSemanticFingerprint()},
		{"runtime51", ProductionRuntimePrecision(), ProductionRuntimePrecisionSemanticFingerprint()},
		{"authorization80", ProductionAuthorizationEnforcement(), ""},
	} {
		p.Tokens[v.name] = workerRegistrationReferenceToken{Checksum: v.m.Checksum(), Fingerprint: v.fp, SourceSHA256: workerRegistrationReferenceHash(v.m.UpSQL())}
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		p.BuildInfo = info.String()
	}
	return p
}

func TestWorkerRegistrationReferenceAssemblyEmitter(t *testing.T) {
	destination := os.Getenv("ZASP_WORKER_REGISTRATION_ASSEMBLY_OUTPUT")
	if destination == "" {
		t.Skip("assembly emission requires an explicit owner-only destination; no database execution")
	}
	inputSHA := os.Getenv("ZASP_WORKER_REGISTRATION_INPUT_SHA256")
	if len(inputSHA) != 64 {
		t.Fatal("root-authorized frozen input digest required")
	}
	p := workerRegistrationReferenceAssembly()
	if workerRegistrationReferenceHash(p.WorkerChecksumPreimage) != p.WorkerChecksum || workerRegistrationReferenceHash(p.RuntimeChecksumPreimage) != p.RuntimeChecksum {
		t.Fatal("fresh original checksum preimage does not close")
	}
	p.InputSHA256 = inputSHA
	path, err := os.Executable()
	if err != nil {
		t.Fatal("assembly executable identity unavailable")
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 512*1024*1024 {
		t.Fatal("assembly executable identity refused")
	}
	p.ExecutableSHA256 = workerRegistrationReferenceHash(string(b))
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 16*1024*1024 {
		t.Fatal("assembly packet bound refused")
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("exclusive assembly destination refused")
	}
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || n != len(raw) {
		t.Fatal("complete assembly publication failed")
	}
	t.Log("fresh original assembly emitted; database not executed", len(raw), workerRegistrationReferenceHash(string(raw)))
}

func TestWorkerRegistrationReferenceFreshAssembly(t *testing.T) {
	p := workerRegistrationReferenceAssembly()
	if p.WorkerSource == "" || p.RuntimeSource == "" || len(p.WorkerChecksum) != 64 || len(p.RuntimeChecksum) != 64 || p.WorkerChecksum == p.RuntimeChecksum {
		t.Fatal("independent fresh compiler outputs absent")
	}
	if !strings.Contains(p.WorkerSource, p.RuntimeSource[:strings.Index(p.RuntimeSource, "CREATE FUNCTION zasp_authorization80_runtime.fingerprint()")]) {
		t.Fatal("runtime bootstrap insertion changed")
	}
	if !strings.Contains(p.WorkerSource, "INSERT INTO zasp_authorization80_runtime.registration") || strings.Contains(p.WorkerSource, "INSERT INTO zasp_authorization80_worker.registration VALUES") {
		t.Fatal("distinct registration insertion provenance")
	}
	if !strings.Contains(p.StopSuccessor, "FUNCTION zasp_authorization80_worker.test74_stop_evidence(") || !strings.Contains(p.StopSuccessor, workerSettledStopArm+workerStopParentAnchor) {
		t.Fatal("original74 successor not admitted")
	}
	if p.WorkerCatalogSHA256 != "28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016" {
		t.Fatal("original33-selector authority changed")
	}
	if workerRegistrationReferenceHash(p.WorkerChecksumPreimage) != p.WorkerChecksum || workerRegistrationReferenceHash(p.RuntimeChecksumPreimage) != p.RuntimeChecksum || strings.ReplaceAll(p.WorkerChecksumPreimage, "-- worker profile checksum", p.WorkerChecksum) != p.WorkerSource || strings.ReplaceAll(p.RuntimeChecksumPreimage, "-- runtime profile checksum", p.RuntimeChecksum) != p.RuntimeSource {
		t.Fatal("original full checksum preimage closure")
	}
	for _, n := range []string{"finding78", "test74", "runtime48", "runtime50", "runtime51", "authorization80"} {
		if p.Tokens[n].Checksum == "" || p.Tokens[n].SourceSHA256 == "" {
			t.Fatal("upstream token closure absent", n)
		}
	}
	t.Log("fresh current original source-only worker", len(p.WorkerSource), p.WorkerSourceSHA256, "checksum", p.WorkerChecksum, "runtime", len(p.RuntimeSource), p.RuntimeSourceSHA256, "checksum", p.RuntimeChecksum)
}
