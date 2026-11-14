// Package platforms holds the SaaS platform definitions of the generic saas
// discovery provider, one file per platform, and the registry that lists
// them. Adding a platform is adding a file here, one line to All and a test;
// see docs/operations/saas-connectors.md.
package platforms

import (
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// All returns the definition of every platform the product knows.
func All() []saasdiscovery.Platform {
	return []saasdiscovery.Platform{
		Anthropic(),
		Atlassian(),
		Databricks(),
		GitLab(),
		GoogleWorkspace(),
		OpenAI(),
		ServiceNow(),
		Slack(),
	}
}

var registry = sync.OnceValues(func() (*saasdiscovery.Registry, error) {
	return saasdiscovery.NewRegistry(All()...)
})

// Registry is the registry of All. It fails only when a definition in this
// package is invalid, which the package's tests refuse.
func Registry() (*saasdiscovery.Registry, error) { return registry() }
