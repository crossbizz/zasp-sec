package saasdiscovery

import (
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
)

// Registry is the set of platforms a deployment knows. The collector, the
// authorization probe and the connector catalog all read it; nothing else
// lists platforms.
type Registry struct {
	platforms map[string]Platform
}

// NewRegistry refuses an invalid definition, a repeated platform token and a
// repeated Nango key.
func NewRegistry(platforms ...Platform) (*Registry, error) {
	if len(platforms) < 1 || len(platforms) > 64 {
		return nil, ErrInvalid
	}
	registry := &Registry{platforms: make(map[string]Platform, len(platforms))}
	keys := map[string]bool{}
	for _, platform := range platforms {
		if platform.Validate() != nil || keys[platform.Nango.Key] {
			return nil, ErrInvalid
		}
		if _, exists := registry.platforms[platform.Token]; exists {
			return nil, ErrInvalid
		}
		keys[platform.Nango.Key] = true
		registry.platforms[platform.Token] = platform
	}
	return registry, nil
}

// Platform returns the definition of a platform token.
func (registry *Registry) Platform(token string) (Platform, bool) {
	if registry == nil {
		return Platform{}, false
	}
	platform, ok := registry.platforms[token]
	return platform, ok
}

// Platforms returns every definition, ordered by token.
func (registry *Registry) Platforms() []Platform {
	if registry == nil {
		return nil
	}
	result := make([]Platform, 0, len(registry.platforms))
	for _, platform := range registry.platforms {
		result = append(result, platform)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Token < result[right].Token })
	return result
}

// NangoEntries are the proxy entries of every platform, for the Nango
// adapter of the collector and of the authorization probe.
func (registry *Registry) NangoEntries() []nango.Entry {
	platforms := registry.Platforms()
	entries := make([]nango.Entry, 0, len(platforms))
	for _, platform := range platforms {
		entry := platform.Nango
		entry.Rules = append([]nango.Rule(nil), entry.Rules...)
		entry.HostSuffixes = append([]string(nil), entry.HostSuffixes...)
		entries = append(entries, entry)
	}
	return entries
}

// ValidTenant reports whether tenantID has the platform's tenant grammar
// and, for a platform with a per-tenant host, whether the tenant's host is
// one the platform allows.
func (platform Platform) ValidTenant(tenantID string) bool {
	if !ValidTenantID(tenantID) || platform.TenantPattern == nil || !platform.TenantPattern.MatchString(tenantID) {
		return false
	}
	_, allowed := platform.TenantHost(tenantID)
	return allowed
}

// SubjectID is the saas_tenant subject id of a tenant of the platform.
func (platform Platform) SubjectID(tenantID string) string {
	return platform.Token + "/" + tenantID
}
