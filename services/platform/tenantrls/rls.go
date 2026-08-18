package tenantrls

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const (
	migrationVersion = int64(2)
	migrationName    = "tenant_rls"
)

//go:embed sql/0002_tenant_rls.up.sql
var upAsset string

//go:embed sql/0002_tenant_rls.down.sql
var downAsset string

type Table struct {
	Name               string
	OrganizationColumn string
}

var coreTables = [...]Table{
	{Name: "organizations", OrganizationColumn: "id"},
	{Name: "workspace_grants", OrganizationColumn: "organization_id"},
	{Name: "integrations", OrganizationColumn: "organization_id"},
	{Name: "policies", OrganizationColumn: "organization_id"},
}

var workflowTables = [...]Table{
	{Name: "findings", OrganizationColumn: "organization_id"},
	{Name: "tests", OrganizationColumn: "organization_id"},
	{Name: "audit_metadata", OrganizationColumn: "organization_id"},
	{Name: "export_jobs", OrganizationColumn: "organization_id"},
}

type Metadata struct {
	version  int64
	name     string
	checksum string
	up       string
	down     string
}

func Migration() Metadata {
	up := strings.TrimSpace(upAsset)
	down := strings.TrimSpace(downAsset)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{
		version:  migrationVersion,
		name:     migrationName,
		checksum: hex.EncodeToString(digest[:]),
		up:       up,
		down:     down,
	}
}

func (metadata Metadata) Version() int64   { return metadata.version }
func (metadata Metadata) Name() string     { return metadata.name }
func (metadata Metadata) Checksum() string { return metadata.checksum }
func (metadata Metadata) UpSQL() string    { return metadata.up }
func (metadata Metadata) DownSQL() string  { return metadata.down }

func (metadata Metadata) CoreTables() []Table {
	return append([]Table(nil), coreTables[:]...)
}

func (metadata Metadata) WorkflowTables() []Table {
	return append([]Table(nil), workflowTables[:]...)
}
