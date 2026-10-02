package apiserver

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSingleRecoveryBrowserSessionMatchesAdministrationContract(t *testing.T) {
	const constraint = `ADD CONSTRAINT "zasp_product_sessions_session_id_check" CHECK ("session_id" ~ '^session-[a-z0-9][a-z0-9-]*$');`
	if !strings.Contains(migrations.ProductionAdministration().UpSQL(), constraint) {
		t.Fatal("production administration session contract changed")
	}
	if !regexp.MustCompile(`^session-[a-z0-9][a-z0-9-]*$`).MatchString(singleRecoveryBrowserSessionID) {
		t.Fatalf("single recovery browser session ID violates migration 0007: %q", singleRecoveryBrowserSessionID)
	}
	if singleRecoveryBrowserSessionID == singleRecoveryBrowser {
		t.Fatal("stored session ID must remain distinct from the browser credential")
	}
}
