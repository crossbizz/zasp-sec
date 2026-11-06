package preflight

import (
	"context"
	"time"
)

// The shared runner calls this while its global context is still live, before
// AWS credential early returns and before report aggregation/cancellation.
func (r *Runner) observeCoreDependencies(ctx context.Context, report *Report, c CoreDependencies) {
	if ctx == nil || r == nil || report == nil || !validCoreDependencies(c) {
		return
	}
	if c.Stytch == nil {
		dependencyCode(report, "stytch_project_reachable", "target_unconfigured")
		dependencyCode(report, "stytch_session_reachable", "target_unconfigured")
	}
	if c.Neon == nil {
		dependencyCode(report, "neon_pool_reachable", "target_unconfigured")
		dependencyCode(report, "neon_migration_compatible", "target_unconfigured")
	}
	if c.Stytch != nil {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		r.observeStytch(bounded, report, c.Stytch)
		cancel()
	}
	if c.Neon != nil {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		r.observeNeon(bounded, report, c.Neon)
		cancel()
	}
}

var dependencyHints = map[string]string{
	"stytch:GetOrganization":   "verify exact project environment and organization; supply authorized existing project read credentials",
	"stytch:GetMemberSessions": "verify existing selected member session, organization and expiry; no session is created or renewed",
	"postgres:Connect":         "verify exact Neon pooled host, verified TLS, database, principal and explicit private password; no owner or ambient fallback",
	"postgres:InspectProfile":  "verify exact compiled canonical61 and selected private78/79/80 profile; grant only existing authorized metadata read/ready access, never migration owner fallback",
}

func (r *Runner) dependencyFailure(report *Report, name, operation string, target any, outcome string) {
	hint, ok := dependencyHints[operation]
	if !ok {
		return
	}
	switch outcome {
	case "denied", "unreachable", "malformed", "binding_mismatch":
	default:
		return
	}
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			o := &report.Checks[i].Observations[j]
			if o.Name == name && len(o.Failures) < 32 {
				o.Failures = append(o.Failures, Failure{Operation: operation, TargetDigest: singleTargetDigest(target), Outcome: outcome, Hint: hint})
				return
			}
		}
	}
}
func dependencyCode(report *Report, name, code string) {
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			if report.Checks[i].Observations[j].Name == name {
				report.Checks[i].Observations[j].Code = code
				return
			}
		}
	}
}
