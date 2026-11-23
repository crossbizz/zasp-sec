package apiserver

import (
	"io"
	"os"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

// This path is configured by the deployment. Untrusted API requests never
// supply public keys or a path. Read on evaluation to support immediate
// rotation and removal across long-running API and reporting workers.
func ticketProofQualification(bundle redteam.TicketProofBundle, submittedAt time.Time) string {
	var trust redteam.TicketTrust
	if bundle.Attestations != nil {
		path := os.Getenv("ZASP_TICKET_ATTESTATION_TRUST_FILE")
		if path == "" {
			return "unknown"
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() >= 64*1024 {
			return "unknown"
		}
		f, err := os.Open(path)
		if err != nil {
			return "unknown"
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0022 != 0 {
			return "unknown"
		}
		b, err := io.ReadAll(io.LimitReader(f, 64*1024))
		if err != nil || redteam.DecodeTicketExport(b, &trust) != nil {
			return "unknown"
		}
	}
	return redteam.QualifyTicketProof(bundle, submittedAt, trust)
}
