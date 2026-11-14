package apiserver

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
)

const postgresRedTeamRecordProbeResultsSQL = `SELECT zasp_red_team_record_probe_results($1,$2,$3,$4,$5,$6,$7::jsonb)`

var redTeamProbeIDPattern = regexp.MustCompile(`^zasp(\.[a-z][a-z_]{2,40}){4}\.v1$`)

// RedTeamProbeResult is the outcome of one probe of the probe library in one
// attempt of a run. It names the probe; it never holds the target's answer.
type RedTeamProbeResult struct {
	ProbeID  string `json:"probe_id"`
	Category string `json:"category"`
	Outcome  string `json:"outcome"`
}

// RedTeamProbeCategory is one category of the probe library as the public
// catalog lists it.
type RedTeamProbeCategory struct {
	Category   string                    `json:"category"`
	Title      string                    `json:"title"`
	ProbeCount int                       `json:"probe_count"`
	Techniques []string                  `json:"techniques"`
	Frameworks []compliancemap.Reference `json:"frameworks"`
}

// RedTeamProbeCatalog is the public description of the embedded probe library.
type RedTeamProbeCatalog struct {
	Version           string                 `json:"version"`
	Digest            string                 `json:"digest"`
	ProbeCount        int                    `json:"probe_count"`
	DefaultSampleSize int                    `json:"default_sample_size"`
	Categories        []RedTeamProbeCategory `json:"categories"`
}

// CurrentRedTeamProbeCatalog describes the probe library of this build. It
// lists counts, techniques and framework tags, never probe text.
func CurrentRedTeamProbeCatalog() RedTeamProbeCatalog {
	catalog := RedTeamProbeCatalog{Version: probes.Version, Digest: probes.Digest(), DefaultSampleSize: probes.DefaultSampleSize, Categories: []RedTeamProbeCategory{}}
	for _, summary := range probes.Summaries() {
		catalog.ProbeCount += summary.ProbeCount
		catalog.Categories = append(catalog.Categories, RedTeamProbeCategory{Category: summary.Category, Title: summary.Title, ProbeCount: summary.ProbeCount, Techniques: append([]string(nil), summary.Techniques...), Frameworks: append([]compliancemap.Reference(nil), summary.Frameworks...)})
	}
	return catalog
}

func validRedTeamProbeResults(values []RedTeamProbeResult) bool {
	if len(values) > probes.MaximumRunProbes {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		probe, ok := probes.Lookup(value.ProbeID)
		// A stored result may name a probe of an earlier library version, so
		// only the identifier's shape is required when the probe is unknown.
		if !redTeamProbeIDPattern.MatchString(value.ProbeID) || len(value.ProbeID) > 128 || seen[value.ProbeID] || !probes.ValidCategory(value.Category) || ok && probe.Category != value.Category || !stringIn(value.Outcome, "protected", "unsafe") {
			return false
		}
		seen[value.ProbeID] = true
	}
	return true
}

func (repository *RedTeamExecutionRepository) recordRedTeamProbeResults(ctx context.Context, scope domain.Scope, input RedTeamRunCompletion) error {
	if !validRedTeamProbeResults(input.ProbeResults) {
		return ErrRepositoryOperation
	}
	for _, result := range input.ProbeResults {
		if _, known := probes.Lookup(result.ProbeID); !known {
			return ErrRepositoryOperation
		}
	}
	encoded, err := json.Marshal(input.ProbeResults)
	if err != nil {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRedTeamRecordProbeResultsSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.RunID, input.Worker, input.LeaseToken, encoded)
	if err != nil {
		return discoveryProviderError(err)
	}
	var recorded struct {
		Recorded int `json:"recorded"`
	}
	if !exactJSONFields(payload, "recorded") || decodeStrictDiscovery(payload, &recorded) != nil || recorded.Recorded != len(input.ProbeResults) {
		return ErrRepositoryUnavailable
	}
	return nil
}
