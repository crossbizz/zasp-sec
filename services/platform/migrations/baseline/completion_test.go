package baseline

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

// The schema pins the digest of the inventory rule catalog (a CHECK
// constraint, the cutover rows, schema metadata and two function bodies).
// completion.sql must pin the digest of the catalog the workers compile, or
// the schema and the workers disagree about which rules are current.
func TestCompletionPinsTheCompiledRuleCatalogDigest(t *testing.T) {
	completion, err := os.ReadFile("completion.sql")
	if err != nil {
		t.Fatal(err)
	}
	digest := inventoryprojection.RuleCatalogDigest()
	want := "current_value CONSTANT text:='" + hex.EncodeToString(digest[:]) + "';"
	if strings.Count(string(completion), want) != 1 {
		t.Fatalf("completion.sql does not pin the compiled rule catalog digest exactly once: %s", want)
	}
	rule, found := inventoryprojection.LookupRule("aws", "aws_role")
	if !found || rule.ProductKind != inventoryprojection.KindIdentity || rule.Version != 2 {
		t.Fatalf("compiled aws_role rule = %+v, completion.sql classifies it as identity at rule version 2", rule)
	}
}
