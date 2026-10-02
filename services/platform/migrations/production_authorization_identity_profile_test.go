package migrations

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// These independently captured pre-refactor hashes pin retained SQL bytes.
// Actual administration/read/reveal tests remain the behavioral acceptance.
func TestIdentityRetainedSQLAssembly(t *testing.T) {
	source, _ := authorizationIdentityProfileSource()
	want := map[string]string{
		"_member_role":         "50aee40dc70ea9b6d113e47171a2923cde2788a634caf8e83f217c41cf1b199f",
		"_group_mapping":       "2c01933f3cca83fd8d88c5a23ed46b3eeb2568e2c3ba814006ce82d168a96add",
		"_create_pat":          "62719c334f1d7530a0410774b4b91d36b4de361e9292e421e7f537075997bb95",
		"_rotate_pat":          "4b0a64dc121f8839ad2ab529d5d50752e4e68435cc052d6ceeb49b5ed9cdb522",
		"_revoke_pat":          "e77f31ec621a91a3db41334e678b496a9355e76bac87c425fa845a5f3095018f",
		"_ack_reveal":          "e575c99aa013df72e574289c42bb192566fdbac159c6b22af5305e514008b1a4",
		"_revoke_investigated": "010222d44898f4bb24ca6e5692b9163708a408edfeb783bfd4d8a1dad716c9a5",
		"_pat_page":            "b745be564a89264c2e554b885edacca1299f736ee32dd00d6bffad9afe061f9f",
		"_reveal_page":         "7a971cb8b21b7fb80e15f37478184c3dee11b750881fbf30042939373c967ece",
		"_reveal_pat":          "735fe8ce6ca422e764c771687777276f75992333aed426ff33b5a8a3d79e3652",
	}
	for name, digest := range want {
		re := regexp.MustCompile(`(?s)CREATE FUNCTION zasp_authorization80_identity\.` + name + `\([^;]*?AS \$retained\$\n(.*?)\n\$retained\$;`)
		matches := re.FindAllStringSubmatch(source, -1)
		if len(matches) != 1 {
			t.Fatalf("retained function %s count=%d", name, len(matches))
		}
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(matches[0][1])))); got != digest {
			t.Errorf("retained SQL changed for %s: %s", name, got)
		}
	}
	if strings.Contains(source, "-- retained identity ") {
		t.Fatal("unexpanded retained identity body")
	}
}

func TestIdentityProfileDependencyCheckpoint(t *testing.T) {
	source, identity := authorizationIdentityProfileSource()
	_, composed := authorizationTemporalProfileSource()
	for _, marker := range []string{"-- identity checksum", "-- identity80 checksum", "-- identity audit checksum", "-- identity composed checksum", "-- identity catalog body", "-- identity retained deprovision", "-- identity projected19 query"} {
		if strings.Contains(source, marker) {
			t.Fatalf("unexpanded installer marker %q", marker)
		}
	}
	for name, checksum := range map[string]string{
		"identity":                    identity,
		"main80":                      ProductionAuthorizationEnforcement().Checksum(),
		"audit":                       AuthorizationAuditProfileChecksum(),
		"composed":                    composed,
		"source19":                    ProductionIdentityAdministration().Checksum(),
		"source19_semantic":           ProductionIdentityAdministrationSemanticFingerprint(),
		"source79":                    ProductionAuthorizationProjection().Checksum(),
		"fixed_catalog_body":          fmt.Sprintf("%x", sha256.Sum256([]byte(identityCatalogBody()))),
		"compiled_source19_query":     fmt.Sprintf("%x", sha256.Sum256([]byte(identity19CatalogQuery()))),
		"wrapper_retained_projection": fmt.Sprintf("%x", sha256.Sum256([]byte(identityDeprovisionSource()))),
		"assembled_installer":         fmt.Sprintf("%x", sha256.Sum256([]byte(source))),
	} {
		if len(checksum) != 64 {
			t.Fatalf("invalid %s checksum", name)
		}
		t.Logf("%s=%s", name, checksum)
	}
	if strings.Contains(identityCatalogBody(), identity) {
		t.Fatal("fixed catalog gate embeds identity checksum")
	}
}
