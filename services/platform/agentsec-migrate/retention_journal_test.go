package main

import (
	"bytes"
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestRetentionJournalOperatorBoundary(t *testing.T) {
	env := map[string]string{migrationPrincipalEnvironment: "zasp_e2e", retentionJournalChecksumEnvironment: migrations.RetentionJournalProfileChecksum()}
	for _, command := range []string{"up-retention-writer-journal", "enroll-retention-journal-scope"} {
		if !retentionJournalCommand(command) {
			t.Fatal("journal command not mounted")
		}
		_, err := loadRetentionJournalCommand([]string{command, "arbitrary-target"}, func(k string) string { return env[k] })
		if err == nil {
			t.Fatal("unbounded operator targets accepted")
		}
	}
	input, err := loadRetentionJournalCommand([]string{"up-retention-writer-journal"}, func(k string) string { return env[k] })
	if err != nil || input.principal != "zasp_e2e" {
		t.Fatal("exact original owner configuration refused")
	}
	var out bytes.Buffer
	if err := writeRetentionJournalChecksum(&out); err != nil || !bytes.Contains(out.Bytes(), []byte(migrations.RetentionJournalProfileChecksum())) {
		t.Fatal("offline compiled checksum missing")
	}
	var r *migrations.Runner
	if r.UpProductionRetentionJournalProfile(context.Background()) != migrations.ErrInvalidRunner {
		t.Fatal("nil journal installer accepted")
	}
}
