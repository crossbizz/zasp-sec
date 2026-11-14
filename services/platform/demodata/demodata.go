// Package demodata holds the synthetic company the demo seeder shows
// ("Northwind Robotics") and turns it into typed discovery snapshots.
//
// The dataset is a set of JSON files under fixtures/, one per demo
// integration. A file holds what a provider would answer: for the HTTP
// providers the responses of the provider's API (served in process by a
// replay transport, never over a socket), for AWS the typed account source
// the worker's AWS reader hands to the collector. Collect runs the product's
// real collector over those answers, driven by the shared collection client
// exactly as the discovery worker drives it, and returns the typed snapshot
// the pipeline applies. Nothing here writes to a database.
//
// Everything in the dataset is fictional: the company, the account numbers
// (111122223333 and similar documentation values), the example.com hosts.
// It holds no credential and nothing shaped like one.
package demodata

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// NamePrefix starts the display name of every demo integration. It is the
// marker the seeder, the status command and the web application recognise.
const NamePrefix = "Demo: "

// Marker is the member the configuration of every demo integration carries.
const Marker = "demo_dataset"

// Company is the fictional company of the dataset.
const Company = "Northwind Robotics"

var (
	// ErrDataset means a fixture file is not one the seeder accepts.
	ErrDataset = errors.New("demo dataset rejected")

	keyPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
)

// Providers are the discovery providers the dataset covers, in seeding order.
var Providers = []string{"aws", "gcp", "kubernetes", "github", "okta", "microsoft", "salesforce", "saas"}

// Integration is one demo integration: a provider account, project, cluster,
// installation or tenant, and what its provider answers.
type Integration struct {
	// Key names the integration inside the dataset. The integration's ID in
	// a scope is derived from it, so a second seeding finds the same row.
	Key      string `json:"key"`
	Provider string `json:"provider"`
	// Name is the display name; it starts with NamePrefix.
	Name string `json:"name"`
	// Subject is the provider subject the collection is bound to: the AWS
	// account, the cluster, the installation, the tenant.
	Subject string `json:"subject"`
	// Configuration is the integration's reference-only configuration, as a
	// person would have entered it. The seeder adds the Marker member.
	Configuration map[string]any `json:"configuration"`
	// Description says what the integration shows, for the status output.
	Description string `json:"description"`

	AWS  *AWSSource  `json:"aws,omitempty"`
	HTTP *HTTPSource `json:"http,omitempty"`
}

// HasEarlier reports whether the integration has an earlier state: what the
// provider answered at the previous collection. Seeding applies it first, so
// that what disappeared since is retired the way a real inventory retires it.
func (integration Integration) HasEarlier() bool {
	if integration.HTTP == nil {
		return false
	}
	for _, route := range integration.HTTP.Routes {
		if route.Earlier != nil || route.EarlierItems != nil {
			return true
		}
	}
	return false
}

// Load returns the dataset, ordered by provider (in Providers order) and key.
func Load() ([]Integration, error) {
	return load(fixtures, "fixtures")
}

func load(files fs.FS, directory string) ([]Integration, error) {
	entries, err := fs.ReadDir(files, directory)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDataset, err)
	}
	order := map[string]int{}
	for index, provider := range Providers {
		order[provider] = index
	}
	seen := map[string]bool{}
	var integrations []Integration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := fs.ReadFile(files, directory+"/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrDataset, entry.Name(), err)
		}
		var integration Integration
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&integration); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrDataset, entry.Name(), err)
		}
		if err := integration.validate(); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrDataset, entry.Name(), err)
		}
		if integration.Key+".json" != entry.Name() || seen[integration.Key] {
			return nil, fmt.Errorf("%w: %s: the file name is not the integration's key", ErrDataset, entry.Name())
		}
		seen[integration.Key] = true
		integrations = append(integrations, integration)
	}
	if len(integrations) == 0 {
		return nil, fmt.Errorf("%w: no fixture", ErrDataset)
	}
	sort.SliceStable(integrations, func(left, right int) bool {
		if order[integrations[left].Provider] != order[integrations[right].Provider] {
			return order[integrations[left].Provider] < order[integrations[right].Provider]
		}
		return integrations[left].Key < integrations[right].Key
	})
	return integrations, nil
}

func (integration Integration) validate() error {
	known := false
	for _, provider := range Providers {
		known = known || provider == integration.Provider
	}
	switch {
	case !keyPattern.MatchString(integration.Key):
		return errors.New("key")
	case !known:
		return errors.New("provider")
	case !strings.HasPrefix(integration.Name, NamePrefix) || len(integration.Name) > 128 || strings.TrimSpace(integration.Name) != integration.Name:
		return errors.New("name must start with \"" + NamePrefix + "\"")
	case integration.Subject == "" || integration.Description == "" || integration.Configuration == nil:
		return errors.New("subject, description and configuration are required")
	case (integration.Provider == "aws") != (integration.AWS != nil), (integration.Provider != "aws") != (integration.HTTP != nil):
		return errors.New("an aws integration has an aws source, every other one an http source")
	}
	if _, reserved := integration.Configuration[Marker]; reserved {
		return errors.New("configuration must not set " + Marker)
	}
	if integration.HTTP != nil {
		return integration.HTTP.validate()
	}
	return nil
}
