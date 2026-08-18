package bucketlayout

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	wantBucket  = "zasp-product-data-0123456789abcdef0123456789abcdef"
	wantRegion  = "us-west-2"
	wantAccount = "123456789012"
	wantKMSARN  = "arn:aws:kms:us-west-2:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
)

func TestLayoutBuildsExactScopedPrefixesAndKeys(t *testing.T) {
	t.Parallel()

	layout := mustLayout(t)
	scope := fixtureScope(t)
	reference := fixtureProductID(t, 4)
	wantWorkspace := "organizations/pid_00000000-0000-4000-8000-000000000001/" +
		"workspaces/pid_00000000-0000-4000-8000-000000000002/"

	if got, err := layout.WorkspacePrefix(scope); err != nil || got != wantWorkspace {
		t.Fatalf("WorkspacePrefix() = %q, %v", got, err)
	}

	for _, test := range []struct {
		class   Class
		segment string
	}{
		{class: ClassEvidence, segment: "evidence"},
		{class: ClassExport, segment: "exports"},
		{class: ClassPolicy, segment: "policies"},
	} {
		t.Run(string(test.class), func(t *testing.T) {
			t.Parallel()
			wantPrefix := wantWorkspace + "environments/pid_00000000-0000-4000-8000-000000000003/" + test.segment + "/"
			prefix, err := layout.Prefix(scope, test.class)
			if err != nil || prefix != wantPrefix {
				t.Fatalf("Prefix() = %q, %v", prefix, err)
			}
			key, err := layout.Key(scope, test.class, reference)
			if err != nil || key != wantPrefix+"pid_00000000-0000-4000-8000-000000000004" {
				t.Fatalf("Key() = %q, %v", key, err)
			}
			assertSafeKey(t, key, wantWorkspace, false)
			assertSafeKey(t, prefix, wantWorkspace, true)
		})
	}
}

func TestLayoutReturnsExactConfigurationAndEncryptionCopies(t *testing.T) {
	t.Parallel()

	layout := mustLayout(t)
	wantConfiguration := validConfiguration()
	if err := layout.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if got := layout.Configuration(); got != wantConfiguration {
		t.Fatalf("Configuration() = %#v", got)
	}
	wantEncryption := Encryption{Algorithm: "aws:kms", KMSKeyARN: wantKMSARN, BucketKeyEnabled: true}
	if got := layout.Encryption(); got != wantEncryption {
		t.Fatalf("Encryption() = %#v", got)
	}

	configuration := layout.Configuration()
	configuration.BucketName = "changed"
	encryption := layout.Encryption()
	encryption.KMSKeyARN = "changed"
	if layout.Configuration() != wantConfiguration || layout.Encryption() != wantEncryption {
		t.Fatal("returned value mutation changed layout")
	}
}

func TestNewRejectsInvalidBucketConfiguration(t *testing.T) {
	t.Parallel()

	valid := validConfiguration()
	tests := map[string]string{
		"empty":          "",
		"short token":    "zasp-product-data-0123",
		"long token":     "zasp-product-data-0123456789abcdef0123456789abcdef0",
		"uppercase":      "zasp-product-data-0123456789abcdef0123456789abcdeF",
		"non hex":        "zasp-product-data-0123456789abcdef0123456789abcdeg",
		"extra suffix":   wantBucket + "-extra",
		"leading space":  " " + wantBucket,
		"trailing space": wantBucket + " ",
		"unicode":        "zasp-product-data-0123456789abcdef0123456789abcdeé",
		"dot":            "zasp.product-data-0123456789abcdef0123456789abcdef",
		"underscore":     "zasp_product-data-0123456789abcdef0123456789abcdef",
		"customer prose": "zasp-product-data-customer-one-production-bucket",
		"arn":            "arn:aws:s3:::zasp-product-data-0123456789abcdef0123456789abcdef",
		"ip":             "192.168.0.1",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			configuration := valid
			configuration.BucketName = value
			assertNewRejected(t, configuration, value)
		})
	}
}

func TestNewRejectsInvalidAccountRegionAndKMSIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{name: "empty account", mutate: func(value *Configuration) { value.AccountID = "" }},
		{name: "short account", mutate: func(value *Configuration) { value.AccountID = "12345678901" }},
		{name: "nondigit account", mutate: func(value *Configuration) { value.AccountID = "12345678901a" }},
		{name: "empty region", mutate: func(value *Configuration) { value.Region = "" }},
		{name: "uppercase region", mutate: func(value *Configuration) { value.Region = "US-WEST-2" }},
		{name: "region whitespace", mutate: func(value *Configuration) { value.Region = "us-west-2 " }},
		{name: "region slash", mutate: func(value *Configuration) { value.Region = "us/west/2" }},
		{name: "region colon", mutate: func(value *Configuration) { value.Region = "us:west:2" }},
		{name: "region empty segment", mutate: func(value *Configuration) { value.Region = "us--west-2" }},
		{name: "empty arn", mutate: func(value *Configuration) { value.KMSKeyARN = "" }},
		{name: "unsupported partition", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Replace(wantKMSARN, "arn:aws:", "arn:aws-iso:", 1)
		}},
		{name: "wrong service", mutate: func(value *Configuration) { value.KMSKeyARN = strings.Replace(wantKMSARN, ":kms:", ":s3:", 1) }},
		{name: "region mismatch", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Replace(wantKMSARN, ":us-west-2:", ":us-east-1:", 1)
		}},
		{name: "account mismatch", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Replace(wantKMSARN, ":123456789012:", ":210987654321:", 1)
		}},
		{name: "alias arn", mutate: func(value *Configuration) { value.KMSKeyARN = "arn:aws:kms:us-west-2:123456789012:alias/product" }},
		{name: "bare alias", mutate: func(value *Configuration) { value.KMSKeyARN = "alias/product" }},
		{name: "bare key id", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Join([]string{"01234567", "89ab", "cdef", "0123", "456789abcdef"}, "-")
		}},
		{name: "uppercase uuid", mutate: func(value *Configuration) { value.KMSKeyARN = strings.Replace(wantKMSARN, "abcdef", "abcdeF", 1) }},
		{name: "short uuid", mutate: func(value *Configuration) { value.KMSKeyARN = strings.TrimSuffix(wantKMSARN, "f") }},
		{name: "query", mutate: func(value *Configuration) { value.KMSKeyARN = wantKMSARN + "?version=1" }},
		{name: "fragment", mutate: func(value *Configuration) { value.KMSKeyARN = wantKMSARN + "#key" }},
		{name: "commercial partition with gov region", mutate: func(value *Configuration) {
			value.Region = "us-gov-west-1"
			value.KMSKeyARN = "arn:aws:kms:us-gov-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
		}},
		{name: "commercial partition with iso region", mutate: func(value *Configuration) {
			value.Region = "us-iso-east-1"
			value.KMSKeyARN = strings.Replace(wantKMSARN, "us-west-2", value.Region, 1)
		}},
		{name: "commercial partition with iso b region", mutate: func(value *Configuration) {
			value.Region = "us-isob-east-1"
			value.KMSKeyARN = strings.Replace(wantKMSARN, "us-west-2", value.Region, 1)
		}},
		{name: "commercial partition with iso e region", mutate: func(value *Configuration) {
			value.Region = "eu-isoe-west-1"
			value.KMSKeyARN = strings.Replace(wantKMSARN, "us-west-2", value.Region, 1)
		}},
		{name: "commercial partition with iso f region", mutate: func(value *Configuration) {
			value.Region = "us-isof-south-1"
			value.KMSKeyARN = strings.Replace(wantKMSARN, "us-west-2", value.Region, 1)
		}},
		{name: "gov partition with commercial region", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Replace(wantKMSARN, "arn:aws:", "arn:aws-us-gov:", 1)
		}},
		{name: "china partition with commercial region", mutate: func(value *Configuration) {
			value.KMSKeyARN = strings.Replace(wantKMSARN, "arn:aws:", "arn:aws-cn:", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := validConfiguration()
			test.mutate(&configuration)
			assertNewRejected(t, configuration, "provider-secret-must-not-escape")
		})
	}

	for _, configuration := range []Configuration{
		{BucketName: wantBucket, Region: "cn-north-1", AccountID: wantAccount, KMSKeyARN: "arn:aws-cn:kms:cn-north-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"},
		{BucketName: wantBucket, Region: "us-gov-west-1", AccountID: wantAccount, KMSKeyARN: "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"},
	} {
		if _, err := New(configuration); err != nil {
			t.Fatalf("valid partition configuration rejected: %v", err)
		}
	}
}

func TestLayoutRejectsInvalidScopeClassReferenceAndCollisions(t *testing.T) {
	t.Parallel()

	layout := mustLayout(t)
	scope := fixtureScope(t)
	reference := fixtureProductID(t, 4)
	for _, class := range []Class{"", "Evidence", "export", "policy", "artifact", "../evidence", "evidence/../exports", "evidence%2f..%2fexports", "evidence\\exports", ".", "..", "évidence"} {
		if prefix, err := layout.Prefix(scope, class); !errors.Is(err, ErrLayout) || prefix != "" {
			t.Fatalf("Prefix(%q) = %q, %v", class, prefix, err)
		}
		if key, err := layout.Key(scope, class, reference); !errors.Is(err, ErrLayout) || key != "" {
			t.Fatalf("Key(%q) = %q, %v", class, key, err)
		}
	}

	if value, err := layout.WorkspacePrefix(domain.Scope{}); !errors.Is(err, ErrLayout) || value != "" {
		t.Fatalf("WorkspacePrefix(zero) = %q, %v", value, err)
	}
	if value, err := layout.Key(scope, ClassEvidence, domain.ProductID{}); !errors.Is(err, ErrLayout) || value != "" {
		t.Fatalf("Key(zero reference) = %q, %v", value, err)
	}
	for _, collision := range []domain.ProductID{scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID()} {
		if value, err := layout.Key(scope, ClassEvidence, collision); !errors.Is(err, ErrLayout) || value != "" {
			t.Fatalf("Key(colliding reference) = %q, %v", value, err)
		}
	}
}

func TestZeroAndForgedLayoutsFailClosedWithoutLeakingState(t *testing.T) {
	t.Parallel()

	zero := Layout{}
	if !errors.Is(zero.Validate(), ErrLayout) || zero.Configuration() != (Configuration{}) || zero.Encryption() != (Encryption{}) {
		t.Fatalf("zero layout did not fail closed: %#v %#v", zero.Configuration(), zero.Encryption())
	}
	if value, err := zero.WorkspacePrefix(fixtureScope(t)); !errors.Is(err, ErrLayout) || value != "" {
		t.Fatalf("zero WorkspacePrefix = %q, %v", value, err)
	}

	canonical := mustLayout(t)
	for name, mutate := range map[string]func(*Layout){
		"valid bit": func(value *Layout) { value.valid = false },
		"bucket":    func(value *Layout) { value.bucketName = "forged" },
		"region":    func(value *Layout) { value.region = "forged" },
		"account":   func(value *Layout) { value.accountID = "forged" },
		"kms arn":   func(value *Layout) { value.kmsKeyARN = "forged" },
	} {
		t.Run(name, func(t *testing.T) {
			forged := canonical
			mutate(&forged)
			if err := forged.Validate(); !errors.Is(err, ErrLayout) || err.Error() != ErrLayout.Error() {
				t.Fatalf("Validate() = %v", err)
			}
			if forged.Configuration() != (Configuration{}) || forged.Encryption() != (Encryption{}) {
				t.Fatal("forged layout exposed state")
			}
		})
	}
}

func TestLayoutIsDeterministicUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	layout := mustLayout(t)
	scope := fixtureScope(t)
	reference := fixtureProductID(t, 4)
	want, err := layout.Key(scope, ClassEvidence, reference)
	if err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				got, buildErr := layout.Key(scope, ClassEvidence, reference)
				if buildErr != nil || got != want || layout.Configuration() != validConfiguration() {
					t.Errorf("concurrent result = %q, %v", got, buildErr)
					return
				}
			}
		}()
	}
	group.Wait()
}

func validConfiguration() Configuration {
	return Configuration{BucketName: wantBucket, Region: wantRegion, AccountID: wantAccount, KMSKeyARN: wantKMSARN}
}

func mustLayout(t *testing.T) Layout {
	t.Helper()
	layout, err := New(validConfiguration())
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	return layout
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureProductID(t, 1), fixtureProductID(t, 2), fixtureProductID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func fixtureProductID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + string(rune('0'+value)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertNewRejected(t *testing.T, configuration Configuration, sensitive string) {
	t.Helper()
	layout, err := New(configuration)
	if !errors.Is(err, ErrLayout) || err.Error() != ErrLayout.Error() || layout != (Layout{}) {
		t.Fatalf("New() = %#v, %v", layout, err)
	}
	if sensitive != "" && strings.Contains(err.Error(), sensitive) {
		t.Fatal("error leaked rejected input")
	}
}

func assertSafeKey(t *testing.T, value, workspacePrefix string, trailing bool) {
	t.Helper()
	if !utf8.ValidString(value) || len(value) > 1024 || !strings.HasPrefix(value, workspacePrefix) || strings.Contains(value, "//") {
		t.Fatalf("unsafe key %q", value)
	}
	if strings.HasSuffix(value, "/") != trailing {
		t.Fatalf("trailing slash = %t, want %t", strings.HasSuffix(value, "/"), trailing)
	}
	parts := strings.Split(strings.TrimSuffix(value, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			t.Fatalf("unsafe segment %q in %q", part, value)
		}
	}
}
