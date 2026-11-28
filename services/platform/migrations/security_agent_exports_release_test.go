package migrations

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestSecurityAgentExportMetadataPreservesBoundMigration(t *testing.T) {
	const readers = 8
	results := make(chan Metadata, readers)
	for range readers {
		go func() { results <- ProductionSecurityAgentExports() }()
	}
	got := <-results
	for range readers - 1 {
		if <-results != got {
			t.Fatal("concurrent readers received different export migration metadata")
		}
	}
	if got.Version() != 58 || got.Name() != "production_security_agent_exports" ||
		got.Checksum() != "5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(got.UpSQL()))) != "58b6c38119f841219cdae2cb1efe3dbfe9c2cc77d286af3bb99d6022c1edf6fe" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(got.DownSQL()))) != "2e68048c8b0ac75cf987871692a8b1789d1a2a2c89d5550859b9fa1791bc57d0" {
		t.Fatal("release 58 identity, bound migration SQL or rollback SQL changed")
	}
	var again Metadata
	if allocations := testing.AllocsPerRun(5, func() { again = ProductionSecurityAgentExports() }); allocations > 1 || again != got {
		t.Fatalf("repeated export metadata read changed or rebuilt the release: %.0f allocations", allocations)
	}
}
