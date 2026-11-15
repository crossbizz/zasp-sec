// Command zasp-demo fills a dedicated scope of a deployment with the demo
// dataset, so that an evaluation has agents, findings, MCP servers and
// attack paths to look at, and removes it again.
//
//	zasp-demo seed --email person@example.com
//	zasp-demo status
//	zasp-demo remove --yes
//
// It is an operator command, like zasp-bootstrap: it runs with the migration
// operator's database identity and the deployment's identity provider
// credentials, reads the same settings, and is not reachable from the
// product API. It gives nobody a session and changes no setting of the
// deployment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/demoseed"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

const usage = `usage: zasp-demo <command> [options]

  seed --email <address>   Create or refresh the demo data for this person.
      --into-existing-organization <id>   Put the demo in a workspace of its own inside this organization.
      --dedicated-organization            Put the demo in an organization of its own.
      --organization <name>               Name of the dedicated organization (default "Zasp Demo").
      --domain <domain>                   Email domain of the dedicated organization (default demo.<domain of the address>).
      --workspace <name>                  Name of the demo workspace (default "Zasp Demo").
      --environment <name>                Name of the demo environment (default "Zasp Demo"; "Demo" inside an existing organization).
      --providers <list>                  Only these providers, comma separated (default all).
      --dry-run                           Run the collectors and print what would be seeded. Nothing is written or sent.
  status                   List the scopes that hold demo data.
  remove --yes             Delete the demo data and the scopes created for it.
      --organization-id <id>              Only the demo of this organization.
      --dry-run                           Print what would be removed.

Settings (the ones zasp-bootstrap reads): ZASP_POSTGRES_DSN (the operator), ZASP_PUBLIC_ORIGIN,
ZASP_DEPLOYMENT_MODE, ZASP_ORGANIZATION_ID, ZASP_STYTCH_BASE_URL, ZASP_STYTCH_PROJECT_ID, ZASP_STYTCH_SECRET,
ZASP_STYTCH_ORGANIZATION_ID, ZASP_OPENFGA_STORE_ID, ZASP_OPENFGA_MODEL_ID.
`

type refusal struct{ reason string }

func (r refusal) Error() string { return r.reason }

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "demo refused: "+err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, getenv func(string) string, output io.Writer) error {
	if len(arguments) == 0 {
		fmt.Fprint(output, usage)
		return refusal{"a command is required: seed, status or remove"}
	}
	switch arguments[0] {
	case "seed":
		return seed(arguments[1:], getenv, output)
	case "status":
		return status(arguments[1:], getenv, output)
	case "remove":
		return remove(arguments[1:], getenv, output)
	case "help", "-h", "--help":
		fmt.Fprint(output, usage)
		return nil
	}
	return refusal{"unknown command " + arguments[0] + ": seed, status or remove"}
}

func flags(name string) *flag.FlagSet {
	set := flag.NewFlagSet("zasp-demo "+name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func bounded(timeout time.Duration) (context.Context, context.CancelFunc) {
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(signals, timeout)
	return ctx, func() { cancel(); stop() }
}

// seeder connects as the operator. withDirectory also builds the identity
// provider client, which only seeding needs.
func seeder(ctx context.Context, getenv func(string) string, output io.Writer, withDirectory bool) (*demoseed.Seeder, func(), error) {
	dsn := getenv("ZASP_POSTGRES_DSN")
	if dsn == "" {
		return nil, nil, refusal{"ZASP_POSTGRES_DSN is not set (the operator DSN, as for zasp-bootstrap)"}
	}
	var directory demoseed.Directory
	if withDirectory {
		origin := strings.TrimSuffix(getenv("ZASP_PUBLIC_ORIGIN"), "/")
		if origin == "" {
			return nil, nil, refusal{"ZASP_PUBLIC_ORIGIN is not set (an invitation returns to its /auth/callback)"}
		}
		adapter, err := apiserver.NewStytchDirectory(apiserver.StytchDirectoryConfig{
			BaseURL: getenv("ZASP_STYTCH_BASE_URL"), ProjectID: getenv("ZASP_STYTCH_PROJECT_ID"), Secret: getenv("ZASP_STYTCH_SECRET"),
			InviteRedirectURL: origin + "/auth/callback", Timeout: 20 * time.Second,
			Now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) },
		})
		if err != nil {
			return nil, nil, refusal{"the identity provider settings are missing or malformed (ZASP_STYTCH_BASE_URL, ZASP_STYTCH_PROJECT_ID, ZASP_STYTCH_SECRET)"}
		}
		directory = adapter
	}
	connection, err := runtimepostgres.Connect(ctx, dsn)
	if err != nil {
		return nil, nil, refusal{"the operator database is unreachable"}
	}
	built, err := demoseed.New(connection, directory, output)
	if err != nil {
		_ = connection.Close(context.WithoutCancel(ctx))
		return nil, nil, err
	}
	return built, func() { _ = connection.Close(context.WithoutCancel(ctx)) }, nil
}

func seed(arguments []string, getenv func(string) string, output io.Writer) error {
	set := flags("seed")
	var request demoseed.Request
	var providers string
	var dryRun bool
	timeout := set.Duration("timeout", 3*time.Minute, "total deadline")
	set.StringVar(&request.Email, "email", "", "")
	set.StringVar(&request.ExistingOrganizationID, "into-existing-organization", "", "")
	set.BoolVar(&request.Dedicated, "dedicated-organization", false, "")
	set.StringVar(&request.Organization, "organization", "", "")
	set.StringVar(&request.Domain, "domain", "", "")
	set.StringVar(&request.Workspace, "workspace", "", "")
	set.StringVar(&request.Environment, "environment", "", "")
	set.StringVar(&providers, "providers", "", "")
	set.BoolVar(&dryRun, "dry-run", false, "")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *timeout < 10*time.Second || *timeout > 15*time.Minute {
		return refusal{"usage: zasp-demo seed --email <address> [options] (zasp-demo help)"}
	}
	if request.Email == "" {
		return refusal{"--email is required: the address of the person who will look at the demo"}
	}
	if providers != "" {
		request.Providers = strings.Split(providers, ",")
	}
	ctx, cancel := bounded(*timeout)
	defer cancel()
	if dryRun {
		return preview(ctx, request, output)
	}
	mode, pinned := getenv("ZASP_DEPLOYMENT_MODE"), getenv("ZASP_ORGANIZATION_ID")
	switch mode {
	case "saas":
	case "single_tenant":
		// A single-tenant deployment serves exactly its configured
		// Organization: the demo can only be a workspace inside it.
		if pinned == "" {
			return refusal{"ZASP_ORGANIZATION_ID is required in single_tenant mode"}
		}
		if request.Dedicated || request.Organization != "" || request.Domain != "" || request.ExistingOrganizationID != "" && request.ExistingOrganizationID != pinned {
			return refusal{"a single-tenant deployment serves one organization: the demo goes into a workspace of organization " + pinned}
		}
		request.ExistingOrganizationID = pinned
	default:
		return refusal{"ZASP_DEPLOYMENT_MODE must be saas or single_tenant"}
	}
	request.SignInOrganizationReference = getenv("ZASP_STYTCH_ORGANIZATION_ID")
	request.AuthorizationStoreID, request.AuthorizationModelID = getenv("ZASP_OPENFGA_STORE_ID"), getenv("ZASP_OPENFGA_MODEL_ID")
	built, closeConnection, err := seeder(ctx, getenv, output, true)
	if err != nil {
		return err
	}
	defer closeConnection()
	report, err := built.Seed(ctx, request)
	if err != nil {
		return explain(err)
	}
	fmt.Fprintf(output, "\nSeeded %d integrations: %d agents, %d open findings, %d MCP servers, %d attack paths.\n", len(report.Integrations), report.Agents, report.OpenFindings, report.MCPServers, report.AttackPaths)
	for _, extra := range report.Extras {
		fmt.Fprintf(output, "Also: %s.\n", extra)
	}
	for _, skipped := range report.Skipped {
		fmt.Fprintf(output, "Skipped: %s.\n", skipped)
	}
	fmt.Fprintf(output, "Where: organization %q (%s), environment %q (%s).\n", report.OrganizationName, report.OrganizationID, report.EnvironmentName, report.EnvironmentID)
	switch {
	case !report.Dedicated:
		fmt.Fprintf(output, "%s signs in as usual and chooses the environment %q.\n", request.Email, report.EnvironmentName)
	case report.MemberCreated:
		fmt.Fprintf(output, "The identity provider invited %s to the demo organization. They open the demo from that invitation.\n", request.Email)
	default:
		fmt.Fprintf(output, "%s is already a member of the demo organization and opens it from the invitation they received.\n", request.Email)
	}
	fmt.Fprintln(output, "Evidence files of demo entities are not stored: an evidence download answers that the object is missing.")
	return nil
}

// preview runs every collector of the dataset in memory and prints what a
// seeding would produce. It connects to nothing.
func preview(ctx context.Context, request demoseed.Request, output io.Writer) error {
	dataset, err := demodata.Load()
	if err != nil {
		return err
	}
	scope, integrationID, err := previewScope()
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, provider := range request.Providers {
		wanted[provider] = true
	}
	fmt.Fprintf(output, "Dry run: nothing is written and nobody is invited.\nDataset %q for %s:\n", demodata.Company, request.Email)
	total := 0
	for _, integration := range dataset {
		if len(wanted) > 0 && !wanted[integration.Provider] {
			continue
		}
		snapshot, err := demodata.Collect(ctx, integration, demodata.Target{Scope: scope, IntegrationID: integrationID, ObservedAt: time.Now().UTC().Truncate(time.Second)})
		if err != nil {
			return err
		}
		agents, entities, err := demodata.Count(snapshot)
		if err != nil {
			return err
		}
		total += agents
		fmt.Fprintf(output, "  %-46s %3d agents, %3d entities\n", integration.Name, agents, entities)
	}
	fmt.Fprintf(output, "%d agents in all. Run the command without --dry-run to seed them.\n", total)
	return nil
}

func previewScope() (domain.Scope, domain.ProductID, error) {
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		id, err := domain.NewProductID()
		if err != nil {
			return domain.Scope{}, domain.ProductID{}, err
		}
		ids[index] = id
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	return scope, ids[3], err
}

func status(arguments []string, getenv func(string) string, output io.Writer) error {
	set := flags("status")
	organization := set.String("organization-id", "", "")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return refusal{"usage: zasp-demo status [--organization-id <id>]"}
	}
	ctx, cancel := bounded(time.Minute)
	defer cancel()
	built, closeConnection, err := seeder(ctx, getenv, io.Discard, false)
	if err != nil {
		return err
	}
	defer closeConnection()
	scopes, err := built.Status(ctx, *organization)
	if err != nil {
		return explain(err)
	}
	if len(scopes) == 0 {
		fmt.Fprintln(output, "No demo data is seeded.")
		return nil
	}
	for _, scope := range scopes {
		printScope(output, scope)
	}
	return nil
}

func printScope(output io.Writer, scope demoseed.ScopeStatus) {
	fmt.Fprintf(output, "Demo data in organization %q (%s), workspace %q, environment %q (%s):\n", scope.OrganizationName, scope.OrganizationID, scope.WorkspaceName, scope.EnvironmentName, scope.EnvironmentID)
	fmt.Fprintf(output, "  %d integrations, %d agents, %d open findings, %d MCP servers, %d attack paths; %d member(s) can see it; last seeded %s\n",
		scope.Integrations, scope.Agents, scope.OpenFindings, scope.MCPServers, scope.AttackPaths, scope.Members, scope.LastSeededAt)
	if scope.ForeignIntegrations > 0 {
		fmt.Fprintf(output, "  %d integration(s) in this environment are not demo integrations: remove refuses it\n", scope.ForeignIntegrations)
	}
}

func remove(arguments []string, getenv func(string) string, output io.Writer) error {
	set := flags("remove")
	organization := set.String("organization-id", "", "")
	yes := set.Bool("yes", false, "")
	dryRun := set.Bool("dry-run", false, "")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return refusal{"usage: zasp-demo remove --yes [--organization-id <id>] [--dry-run]"}
	}
	ctx, cancel := bounded(5 * time.Minute)
	defer cancel()
	built, closeConnection, err := seeder(ctx, getenv, io.Discard, false)
	if err != nil {
		return err
	}
	defer closeConnection()
	scopes, err := built.Status(ctx, *organization)
	if err != nil {
		return explain(err)
	}
	if len(scopes) == 0 {
		fmt.Fprintln(output, "No demo data is seeded. Nothing was removed.")
		return nil
	}
	if *dryRun || !*yes {
		fmt.Fprintln(output, "Would remove:")
		for _, scope := range scopes {
			printScope(output, scope)
		}
		if !*dryRun {
			return refusal{"remove deletes the demo data and the demo scopes listed above; run it again with --yes"}
		}
		return nil
	}
	removals, err := built.Remove(ctx, *organization)
	for _, removal := range removals {
		var rows int64
		for _, count := range removal.DeletedRows {
			rows += count
		}
		fmt.Fprintf(output, "Removed the demo of organization %q (%s), environment %q: %d rows deleted.\n", removal.OrganizationName, removal.OrganizationID, removal.EnvironmentName, rows)
		switch {
		case removal.OrganizationDeleted:
			fmt.Fprintln(output, "  The demo environment, workspace and organization were deleted. The identity provider keeps its organization and member; delete them there if you want them gone.")
		case removal.WorkspaceDeleted:
			fmt.Fprintln(output, "  The demo environment and workspace were deleted.")
		case removal.EnvironmentDeleted:
			fmt.Fprintln(output, "  The demo environment was deleted.")
		default:
			fmt.Fprintln(output, "  The demo environment was emptied but could not be deleted.")
		}
		for _, table := range demoseed.Tables(removal.Remaining) {
			fmt.Fprintf(output, "  Kept by the database (not deletable by the operator): %s, %d row(s), retired.\n", table, removal.Remaining[table])
		}
	}
	if err != nil {
		return explain(err)
	}
	return nil
}

// explain turns a seeder error into what the operator should do.
func explain(err error) error {
	switch {
	case errors.Is(err, demoseed.ErrNotMember):
		return refusal{err.Error() + ". Seeding into an existing organization creates no membership: make the person a member first (./zasp bootstrap-admin adds an administrator), or use --dedicated-organization."}
	case errors.Is(err, demoseed.ErrNotDemo):
		return refusal{err.Error() + ". The demo only ever goes into, and is only ever removed from, an environment that holds nothing else."}
	case errors.Is(err, demoseed.ErrProvider):
		return refusal{err.Error() + ". See docs/operations/first-organization-bootstrap.md, 'Provider prerequisites'."}
	}
	return refusal{err.Error()}
}
