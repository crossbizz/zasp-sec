package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// This deliberately has no Runner/registry entry. It is a source component,
// with no public grants and Ready false until a separate native admission.
//
//go:embed sql/0081_security_agent_temporary_policy_modes.up.sql
var temporaryPolicyModesUp string

//go:embed sql/0081_security_agent_temporary_policy_modes.planning.sql
var temporaryPolicyModesPlanning string

//go:embed sql/0081_security_agent_temporary_policy_modes.effects.sql
var temporaryPolicyModesEffects string

func TemporaryPolicyModesSourceSQL() string {
	return temporaryPolicyModesUp + "\n" + temporaryPolicyModesPlanning + "\n" + temporaryPolicyModesEffects + "\n" + `DO $ownership$ DECLARE p oid; BEGIN FOR p IN SELECT proc.oid FROM pg_proc proc JOIN pg_namespace n ON n.oid=proc.pronamespace WHERE n.nspname='zasp_sa_temporary81' LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p::regprocedure); EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p::regprocedure); END LOOP; END $ownership$;`
}
func TemporaryPolicyModesSourceChecksum() string {
	sum := sha256.Sum256([]byte(TemporaryPolicyModesSourceSQL()))
	return hex.EncodeToString(sum[:])
}
