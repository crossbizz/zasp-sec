package aigateway

import (
	"context"
	"regexp"
	"strings"
	"time"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	regexp.MustCompile(`(?i)\b(?:ghp_|sk-)[a-z0-9_-]+\b`),
}

func RedactApprovedFields(input map[string]string) (map[string]string, error) {
	if len(input) == 0 || len(input) > 32 {
		return nil, ErrInvalidRequest
	}
	allowed := map[string]bool{"title": true, "severity": true, "finding_id": true, "evidence_summary": true}
	result := map[string]string{}
	for key, value := range input {
		if allowed[key] {
			for _, pattern := range sensitivePatterns {
				value = pattern.ReplaceAllString(value, "[REDACTED]")
			}
			if !validText(value) || strings.Contains(strings.ToLower(value), "password=") {
				return nil, ErrInvalidRequest
			}
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil, ErrInvalidRequest
	}
	return result, nil
}

type GovernanceConfig struct {
	Purposes, Models, Providers                         []string
	RequireNoStorage                                    bool
	MaximumTokens, MaximumCostCents, MaximumConcurrency int
	Deadline                                            time.Duration
}
type GovernedRequest struct {
	Purpose          string            `json:"purpose"`
	Model            string            `json:"model"`
	Provider         string            `json:"provider"`
	Tokens           int               `json:"tokens"`
	CostCents        int               `json:"cost_cents"`
	Fields           map[string]string `json:"fields"`
	RequireNoStorage bool              `json:"require_no_storage"`
}
type GovernedResult struct {
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	NoStorage      bool   `json:"no_storage"`
}
type GovernedProvider func(context.Context, GovernedRequest) (GovernedResult, error)
type Governor struct {
	config    GovernanceConfig
	provider  GovernedProvider
	semaphore chan struct{}
}

func NewGovernor(config GovernanceConfig, provider GovernedProvider) (*Governor, error) {
	if provider == nil || !validAllowlist(config.Purposes) || !validAllowlist(config.Models) || !validAllowlist(config.Providers) || !config.RequireNoStorage || config.MaximumTokens < 1 || config.MaximumTokens > 8192 || config.MaximumCostCents < 1 || config.MaximumCostCents > 100 || config.MaximumConcurrency < 1 || config.MaximumConcurrency > 100 || config.Deadline <= 0 || config.Deadline > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	config.Purposes = append([]string(nil), config.Purposes...)
	config.Models = append([]string(nil), config.Models...)
	config.Providers = append([]string(nil), config.Providers...)
	return &Governor{config: config, provider: provider, semaphore: make(chan struct{}, config.MaximumConcurrency)}, nil
}
func (g *Governor) Generate(ctx context.Context, request GovernedRequest) (result GovernedResult, err error) {
	defer func() {
		if recover() != nil {
			result = GovernedResult{}
			err = ErrGeneration
		}
	}()
	if g == nil || ctx == nil || ctx.Err() != nil || !containsString(g.config.Purposes, request.Purpose) || !containsString(g.config.Models, request.Model) || !containsString(g.config.Providers, request.Provider) || request.Tokens < 1 || request.Tokens > g.config.MaximumTokens || request.CostCents < 0 || request.CostCents > g.config.MaximumCostCents || request.RequireNoStorage != g.config.RequireNoStorage {
		return GovernedResult{}, ErrInvalidRequest
	}
	fields, err := RedactApprovedFields(request.Fields)
	if err != nil {
		return GovernedResult{}, err
	}
	request.Fields = fields
	select {
	case g.semaphore <- struct{}{}:
		defer func() { <-g.semaphore }()
	default:
		return GovernedResult{}, ErrGeneration
	}
	operation, cancel := context.WithTimeout(ctx, g.config.Deadline)
	defer cancel()
	result, err = g.provider(operation, request)
	if err != nil || operation.Err() != nil || result.Provider != request.Provider || result.Model != request.Model || result.NoStorage != request.RequireNoStorage || !validText(result.Explanation) || !validText(result.Recommendation) {
		return GovernedResult{}, ErrGeneration
	}
	return result, nil
}
func validAllowlist(values []string) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !validToken(value) {
			return false
		}
		seen[value] = true
	}
	return true
}
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
