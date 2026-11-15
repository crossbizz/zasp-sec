package demodata

import (
	"context"
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// Every fixture loads, and the real collector of its provider completes on
// it with a typed snapshot. The whole dataset is a mid-size company: forty
// to eighty agents across all eight providers.
func TestDatasetCollectsWithTheRealCollectors(t *testing.T) {
	integrations, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	providers := map[string]bool{}
	agents := 0
	for _, integration := range integrations {
		providers[integration.Provider] = true
		snapshot, err := Collect(context.Background(), integration, testTarget(t, integration.Key))
		if err != nil {
			t.Fatalf("%s: %v", integration.Key, err)
		}
		count, entities, err := Count(snapshot)
		if err != nil || entities == 0 {
			t.Fatalf("%s: %d entities, %v", integration.Key, entities, err)
		}
		agents += count
		// A request the fixture does not answer is an API the collector
		// reads as absent. Only the two optional reads below may be.
		for _, request := range snapshot.Unanswered {
			if !strings.Contains(request, "discoveryengine.") && !strings.Contains(request, ":getIamPolicy") && !strings.Contains(request, "/tooling/query") && !strings.Contains(request, "/services/Soap/") {
				t.Errorf("%s: the fixture does not answer %s", integration.Key, request)
			}
		}
		if integration.HasEarlier() {
			target := testTarget(t, integration.Key)
			target.Earlier = true
			if _, err := Collect(context.Background(), integration, target); err != nil {
				t.Fatalf("%s (earlier state): %v", integration.Key, err)
			}
		}
	}
	for _, provider := range Providers {
		if !providers[provider] {
			t.Errorf("the dataset has no %s integration", provider)
		}
	}
	if agents < 40 || agents > 80 {
		t.Fatalf("the dataset has %d agents", agents)
	}
	if _, err := RegistryDecisions(); err != nil {
		t.Fatal(err)
	}
}

// The dataset is fictional and holds nothing shaped like a credential.
func TestDatasetIsFictionalAndHoldsNoCredential(t *testing.T) {
	credential := regexp.MustCompile(`sk-[A-Za-z0-9]{16}|ghp_[A-Za-z0-9]{20}|gh[osu]_[A-Za-z0-9]{20}|AKIA[A-Z0-9]{12}|ASIA[A-Z0-9]{12}|xox[abpr]-|dapi[0-9a-f]{32}|-----BEGIN|eyJ[A-Za-z0-9_-]{20}`)
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}`)
	account := regexp.MustCompile(`arn:aws:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}`)
	allowedAccounts := map[string]bool{"111122223333": true, "424242424242": true, "515151515151": true}
	for _, directory := range []string{"fixtures", "extras"} {
		entries, err := fs.ReadDir(fixtures, directory)
		if directory == "extras" {
			entries, err = nil, nil
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			raw, err := fs.ReadFile(fixtures, directory+"/"+entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if found := credential.FindString(text); found != "" {
				t.Errorf("%s holds something shaped like a credential: %q", entry.Name(), found)
			}
			for _, address := range email.FindAllString(text, -1) {
				if !strings.HasSuffix(address, "@example.com") && !strings.HasSuffix(address, ".gserviceaccount.com") && !strings.HasPrefix(address, "@") {
					t.Errorf("%s holds an address outside example.com: %s", entry.Name(), address)
				}
			}
			for _, number := range account.FindAllString(text, -1) {
				if !allowedAccounts[number[len(number)-12:]] {
					t.Errorf("%s holds an account number that is not a documentation value: %s", entry.Name(), number)
				}
			}
			var integration Integration
			if err := json.Unmarshal(raw, &integration); err != nil || !strings.HasPrefix(integration.Name, NamePrefix) {
				t.Errorf("%s: name %q", entry.Name(), integration.Name)
			}
		}
	}
	if found := credential.FindString(string(registryDecisions)); found != "" {
		t.Errorf("the registry decisions hold something shaped like a credential: %q", found)
	}
}

// The loader refuses a fixture that is not one the seeder can use.
func TestLoadRefusesMalformedFixtures(t *testing.T) {
	valid := `{"key":"aws-x","provider":"aws","name":"Demo: X","subject":"111122223333","description":"d","configuration":{"region":"us-east-1"},"aws":{"roles":[],"agents":{"account_id":"111122223333","bedrock_agents":[],"gateways":[],"lambda_functions":[],"runtimes":[],"services":[]}}}`
	if _, err := load(fstest.MapFS{"f/aws-x.json": {Data: []byte(valid)}}, "f"); err != nil {
		t.Fatalf("a valid fixture was refused: %v", err)
	}
	for name, document := range map[string]string{
		"name without the prefix": strings.Replace(valid, "Demo: X", "X", 1),
		"unknown provider":        strings.Replace(valid, `"provider":"aws"`, `"provider":"other"`, 1),
		"unknown member":          strings.Replace(valid, `"key":"aws-x"`, `"key":"aws-x","extra":1`, 1),
		"marker in configuration": strings.Replace(valid, `"region":"us-east-1"`, `"demo_dataset":"x"`, 1),
		"http source for aws":     strings.Replace(valid, `"aws":{`, `"http":{"routes":[{"path":"/x","body":{}}]},"aws":{`, 1),
		"key is not the file":     strings.Replace(valid, `"key":"aws-x"`, `"key":"aws-y"`, 1),
	} {
		if _, err := load(fstest.MapFS{"f/aws-x.json": {Data: []byte(document)}}, "f"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
