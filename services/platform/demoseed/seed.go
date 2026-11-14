package demoseed

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
)

const (
	countsSQL = `SELECT
 (SELECT count(*) FROM public.zasp_inventory_entities WHERE (organization_id, workspace_id, environment_id, product_kind, state) = ($1, $2, $3, 'agent', 'active')),
 (SELECT count(*) FROM public.zasp_risk_findings WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3) AND status = 'open'),
 (SELECT count(*) FROM public.zasp_mcp_servers($1, $2, $3)),
 (SELECT count(*) FROM public.zasp_risk_attack_paths WHERE (organization_id, workspace_id, environment_id) = ($1, $2, $3))`
)

// Seed provisions the demo scope, runs every dataset integration through its
// real collector and applies the result. A second run refreshes the same
// integrations: the inventory identities are the provider identities, so
// nothing is duplicated.
func (seeder *Seeder) Seed(ctx context.Context, request Request) (Report, error) {
	request, err := seeder.place(ctx, request)
	if err != nil {
		return Report{}, err
	}
	if request, err = request.normalize(); err != nil {
		return Report{}, err
	}
	dataset, err := demodata.Load()
	if err != nil {
		return Report{}, err
	}
	resolved, err := seeder.resolve(ctx, request)
	if err != nil {
		return Report{}, err
	}
	scope := resolved.scope
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	report := Report{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, OrganizationName: resolved.organizationName, EnvironmentName: resolved.environmentName,
		PrincipalID: resolved.principal, OrganizationCreated: resolved.organizationCreated, MemberCreated: resolved.memberCreated, Dedicated: resolved.dedicated}
	seeder.say("demo scope: organization %s (%s), workspace %s, environment %s (%s)", resolved.organizationName, o, w, resolved.environmentName, e)

	var foreign int
	if err := seeder.database.QueryRow(ctx, foreignIntegrationsSQL, o, w, e).Scan(&foreign); err != nil {
		return Report{}, err
	}
	if foreign > 0 {
		return Report{}, fmt.Errorf("%w: environment %s holds %d integration(s) that are not demo integrations", ErrNotDemo, e, foreign)
	}

	observed := seeder.now().Truncate(time.Second)
	failed := []finding{}
	for _, integration := range dataset {
		if !request.wants(integration.Provider) {
			report.Skipped = append(report.Skipped, integration.Name+" (provider "+integration.Provider+" not selected)")
			continue
		}
		entry, findings, err := seeder.seedIntegration(ctx, resolved, integration, observed)
		if err != nil {
			return Report{}, fmt.Errorf("%s: %w", integration.Key, err)
		}
		failed = append(failed, findings...)
		report.Integrations = append(report.Integrations, entry)
		seeder.say("  %-44s %4d entities", integration.Name, entry.Entities)
	}
	// The registry decisions come before the posture refresh, which reads
	// them: a blocked server in use is a finding.
	decided := 0
	if err := seeder.inTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		if decided, err = seedRegistry(ctx, tx, resolved); err != nil {
			return err
		}
		return projectFindings(ctx, tx, scope, failed)
	}); err != nil {
		return Report{}, err
	}
	if decided > 0 {
		report.Extras = append(report.Extras, fmt.Sprintf("%d approved-servers registry decision(s)", decided))
	}
	extras, err := seeder.seedExtras(ctx, resolved)
	if err != nil {
		return Report{}, err
	}
	report.Extras = append(report.Extras, extras...)
	if err := seeder.database.QueryRow(ctx, countsSQL, o, w, e).Scan(&report.Agents, &report.OpenFindings, &report.MCPServers, &report.AttackPaths); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (seeder *Seeder) inTransaction(ctx context.Context, work func(pgx.Tx) error) error {
	tx, err := seeder.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := work(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// seedIntegration collects one integration with its real collector and
// applies the snapshot. An integration with an earlier state is collected
// twice: what the provider answered before, a day earlier, and what it
// answers now.
func (seeder *Seeder) seedIntegration(ctx context.Context, resolved target, integration demodata.Integration, observed time.Time) (IntegrationReport, []finding, error) {
	scope := resolved.scope
	entry := IntegrationReport{Key: integration.Key, Name: integration.Name, Provider: integration.Provider}
	var failed []finding
	passes := []bool{false}
	if integration.HasEarlier() {
		passes = []bool{true, false}
	}
	for _, earlier := range passes {
		at := observed
		if earlier {
			at = observed.Add(-24 * time.Hour)
		}
		err := seeder.inTransaction(ctx, func(tx pgx.Tx) error {
			id, created, err := ensureIntegration(ctx, tx, scope, integration)
			if err != nil {
				return err
			}
			entry.ID, entry.Created = id.String(), entry.Created || created
			snapshot, err := demodata.Collect(ctx, integration, demodata.Target{Scope: scope, IntegrationID: id, ObservedAt: at, Earlier: earlier})
			if err != nil {
				return err
			}
			entry.Entities, failed, err = applySnapshot(ctx, tx, scope, id, resolved.principal, at, snapshot)
			return err
		})
		if err != nil {
			return IntegrationReport{}, nil, err
		}
	}
	return entry, failed, nil
}
