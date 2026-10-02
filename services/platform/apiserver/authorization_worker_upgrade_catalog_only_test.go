package apiserver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type orderedPredecessorCatalogCapture struct {
	enabled, reached, completed bool
	destination                 string
}

func orderedPredecessorCatalogPreflight(catalogOnly, approvalOnly, writerCatalog, acceptance bool, lifecycle int) (*orderedPredecessorCatalogCapture, error) {
	c := &orderedPredecessorCatalogCapture{}
	mode := os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE")
	if mode == "" {
		return c, nil
	}
	if mode != "1" && mode != "catalog" {
		return nil, errors.New("invalid predecessor capture mode")
	}
	if mode == "catalog" {
		if !catalogOnly || approvalOnly || writerCatalog || acceptance || lifecycle != 0 {
			return nil, errors.New("invalid predecessor catalog options")
		}
		for _, name := range []string{"ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE"} {
			if os.Getenv(name) != "" {
				return nil, errors.New("overlapping predecessor catalog mode")
			}
		}
	}
	artifact := os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE")
	c.destination = os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT")
	if !filepath.IsAbs(artifact) || !filepath.IsAbs(c.destination) || filepath.Clean(c.destination) != c.destination {
		return nil, errors.New("explicit predecessor artifact/output required")
	}
	if readWorkerPredecessorArtifact(artifact) != nil {
		return nil, errors.New("frozen predecessor artifact refused")
	}
	if _, err := os.Lstat(c.destination); !os.IsNotExist(err) {
		return nil, errors.New("new predecessor output required")
	}
	c.enabled = mode == "catalog"
	return c, nil
}

func (c *orderedPredecessorCatalogCapture) run(capture func(string)) (bool, error) {
	if !c.enabled {
		return false, nil
	}
	if capture == nil || c.reached {
		return false, errors.New("missing or repeated predecessor capture callback")
	}
	c.reached = true
	capture(c.destination)
	info, err := os.Lstat(c.destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 64*1024*1024+1 {
		return true, errors.New("predecessor capture output witness invalid")
	}
	c.completed = true
	return true, nil
}

func TestP7Ordered69PredecessorCatalogOnly(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") == "" {
		t.Skip("explicit predecessor catalog-only capture required")
	}
	if os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" {
		t.Fatal("invalid predecessor catalog-only mode")
	}
	runOrdered68PolicyBoundary(t, true, false, false)
}

func TestWorkerUpgradeCatalogOnlyPreflightAndBranch(t *testing.T) {
	reference := os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE")
	if reference == "" {
		t.Skip("explicit frozen compiler artifact required for preflight controls")
	}
	if readWorkerPredecessorArtifact(reference) != nil {
		t.Fatal("actual frozen compiler artifact required")
	}
	for _, tc := range []struct {
		name, mode string
		invalid    bool
		change     func(*testing.T)
	}{
		{name: "default"}, {name: "catalog", mode: "catalog"}, {name: "full-producer", mode: "1"},
		{name: "unknown-mode", mode: "other", invalid: true},
		{name: "artifact", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", filepath.Join(t.TempDir(), "absent")) }},
		{name: "relative-output", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "relative") }},
		{name: "existing-output", mode: "catalog", invalid: true, change: func(t *testing.T) {
			if os.WriteFile(os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT"), []byte("untouched"), 0600) != nil {
				t.Fatal("fixture")
			}
		}},
		{name: "attribution-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_READINESS_ATTRIBUTION", "1") }},
		{name: "policy-function-timing-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_POLICY_FUNCTION_TIMING", "1") }},
		{name: "policy-function-capture-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) {
			t.Setenv("ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", filepath.Join(t.TempDir(), "timing.json"))
		}},
		{name: "policy-trace-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_POLICY_TRACE", "1") }},
		{name: "capacity-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_ORDERED_POLICY_CAPACITY", "100") }},
		{name: "retirement-overlap", mode: "catalog", invalid: true, change: func(t *testing.T) { t.Setenv("ZASP_P7_ORDERED69_RETIREMENT_ACL", "1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", tc.mode)
			t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", reference)
			destination := filepath.Join(t.TempDir(), "catalog.json")
			t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", destination)
			if tc.change != nil {
				tc.change(t)
			}
			c, err := orderedPredecessorCatalogPreflight(true, false, false, false, 0)
			if (err != nil) != tc.invalid {
				t.Fatal("preflight admission boundary changed")
			}
			if tc.invalid {
				return
			}
			calls := 0
			ran, err := c.run(func(output string) {
				calls++
				if output != destination {
					t.Fatal("output forwarding changed")
				}
				if err := writeWorkerUpgradeCatalog(output, workerUpgradeCompleteFixture(t)); err != nil {
					t.Fatal(err)
				}
			})
			want := tc.mode == "catalog"
			if err != nil || ran != want || c.completed != want || c.reached != want || calls != map[bool]int{false: 0, true: 1}[want] {
				t.Fatal("catalog-only branch did not select exact one real exporter callback")
			}
			if !want {
				if _, err := os.Stat(destination); !os.IsNotExist(err) {
					t.Fatal("disabled branch touched output")
				}
				return
			}
			if _, err := c.run(func(string) { t.Fatal("duplicate capture invoked") }); err == nil {
				t.Fatal("capture repeated")
			}
		})
	}
	for _, options := range [][5]int{{0, 0, 0, 0, 0}, {1, 1, 0, 0, 0}, {1, 0, 1, 0, 0}, {1, 0, 0, 1, 0}, {1, 0, 0, 0, 1}} {
		t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
		t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", filepath.Join(t.TempDir(), "catalog.json"))
		if _, err := orderedPredecessorCatalogPreflight(options[0] != 0, options[1] != 0, options[2] != 0, options[3] != 0, options[4]); err == nil {
			t.Fatal("catalog-only options widened")
		}
	}
}

func TestWorkerUpgradeCatalogOnlyCompletionWitness(t *testing.T) {
	for _, mode := range []string{"skipped", "bad-mode", "empty", "symlink", "valid"} {
		t.Run(mode, func(t *testing.T) {
			c := &orderedPredecessorCatalogCapture{enabled: true, destination: filepath.Join(t.TempDir(), "catalog.json")}
			ran, err := c.run(func(output string) {
				switch mode {
				case "skipped":
					return
				case "bad-mode":
					if os.WriteFile(output, []byte("data"), 0644) != nil {
						t.Fatal("fixture")
					}
				case "empty":
					if os.WriteFile(output, nil, 0600) != nil {
						t.Fatal("fixture")
					}
				case "symlink":
					if os.Symlink("absent", output) != nil {
						t.Fatal("fixture")
					}
				case "valid":
					if err := writeWorkerUpgradeCatalog(output, workerUpgradeCompleteFixture(t)); err != nil {
						t.Fatal(err)
					}
				}
			})
			if !ran || !c.reached || (err == nil) != (mode == "valid") || c.completed != (mode == "valid") {
				t.Fatal("missing/invalid output counted as completed capture")
			}
		})
	}
	if _, err := (&orderedPredecessorCatalogCapture{enabled: true}).run(nil); err == nil {
		t.Fatal("missing callback accepted")
	}
}
