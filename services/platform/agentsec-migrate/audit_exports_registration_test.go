package main

import (
	"errors"
	"strings"
	"testing"
)

func TestAuditExportWorkerRegistrationConfiguration(t *testing.T) {
	for _, values := range [][2]string{{"zasp_export_executor", "zasp_export_outbox"}, {"abc", strings.Repeat("b", 63)}} {
		getenv := func(key string) string {
			if key == "ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL" {
				return values[0]
			}
			if key == "ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL" {
				return values[1]
			}
			t.Fatalf("read unrelated configuration %s", key)
			return ""
		}
		executor, outbox, err := loadAuditExportWorkerRegistration(getenv)
		if err != nil || executor != values[0] || outbox != values[1] {
			t.Fatal("valid distinct worker identities rejected", err)
		}
	}
	for _, values := range [][2]string{{"", "valid_name"}, {"valid_name", ""}, {"same_name", "same_name"}, {" invalid", "valid_name"}, {"valid_name", "UPPERCASE"}, {"ab", "valid_name"}, {strings.Repeat("a", 64), "valid_name"}, {"x;DROP ROLE y", "valid_name"}} {
		getenv := func(key string) string {
			if key == "ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL" {
				return values[0]
			}
			return values[1]
		}
		if _, _, err := loadAuditExportWorkerRegistration(getenv); !errors.Is(err, errInvalidMigrationCommand) {
			t.Fatal("invalid worker identities accepted")
		}
	}
	if _, _, err := loadAuditExportWorkerRegistration(nil); !errors.Is(err, errInvalidMigrationCommand) {
		t.Fatal("nil configuration reader accepted")
	}
}
