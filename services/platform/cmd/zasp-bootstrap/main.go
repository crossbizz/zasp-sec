// Command zasp-bootstrap provisions the first Organization of a deployment and
// invites its first Organization Admin. It is an operator command: it runs
// with the migration operator's database identity and the deployment's
// identity provider credentials, and it is not reachable from the product API.
//
// Running it again with the same arguments changes nothing and reports the
// existing records.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"


	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/bootstrap"
)

// Each refusal names one fixed stage. Provider responses, database errors and
// configuration values never reach the output.
const (
	stageArguments     = "arguments"
	stageConfiguration = "configuration"
	stageDatabase      = "database"
	stageProvider      = "identity-provider"
	stageConflict      = "existing-records"
	stageRecords       = "product-records"
	stageAuthorization = "authorization-binding"
)

type refusal struct{ stage string }

func (r refusal) Error() string { return "bootstrap refused: stage=" + r.stage }

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		var refused refusal
		if !errors.As(err, &refused) {
			refused = refusal{stage: stageRecords}
		}
		fmt.Fprintln(os.Stderr, refused.Error())
		os.Exit(1)
	}
}

type options struct {
	name, domain, adminEmail, organizationID string
	timeout                                  time.Duration
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("zasp-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var parsed options
	flags.StringVar(&parsed.name, "organization-name", "", "customer Organization name")
	flags.StringVar(&parsed.domain, "domain", "", "customer email domain, lower case")
	flags.StringVar(&parsed.adminEmail, "admin-email", "", "designated first Organization Admin email, lower case")
	flags.StringVar(&parsed.organizationID, "organization-id", "", "the configured product Organization ID; single-tenant deployments only")
	flags.DurationVar(&parsed.timeout, "timeout", time.Minute, "total deadline (5s..5m)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || parsed.name == "" || parsed.domain == "" || parsed.adminEmail == "" ||
		parsed.timeout < 5*time.Second || parsed.timeout > 5*time.Minute {
		return options{}, refusal{stage: stageArguments}
	}
	return parsed, nil
}

func run(arguments []string, getenv func(string) string, output io.Writer) error {
	parsed, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	dsn := getenv("ZASP_POSTGRES_DSN")
	origin := strings.TrimSuffix(getenv("ZASP_PUBLIC_ORIGIN"), "/")
	storeID, modelID := getenv("ZASP_OPENFGA_STORE_ID"), getenv("ZASP_OPENFGA_MODEL_ID")
	mode, pinned := getenv("ZASP_DEPLOYMENT_MODE"), getenv("ZASP_ORGANIZATION_ID")
	// The authorization store and model are bound together or not at all.
	if dsn == "" || origin == "" || (storeID == "") != (modelID == "") || mode != "saas" && mode != "single_tenant" {
		return refusal{stage: stageConfiguration}
	}
	// A single-tenant deployment serves exactly its configured Organization,
	// so the bootstrap may only ever create that one.
	if mode == "single_tenant" {
		if pinned == "" || parsed.organizationID != "" && parsed.organizationID != pinned {
			return refusal{stage: stageConfiguration}
		}
		parsed.organizationID = pinned
	} else if pinned != "" || parsed.organizationID != "" {
		// SaaS Organizations receive generated IDs; none is pinned.
		return refusal{stage: stageConfiguration}
	}
	directoryConfig := apiserver.StytchDirectoryConfig{
		BaseURL: getenv("ZASP_STYTCH_BASE_URL"), ProjectID: getenv("ZASP_STYTCH_PROJECT_ID"), Secret: getenv("ZASP_STYTCH_SECRET"),
		InviteRedirectURL: origin + "/auth/callback", Timeout: 20 * time.Second,
		Now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) },
	}
	// Refuse a malformed provider configuration before touching the database.
	if _, err := apiserver.NewStytchDirectory(directoryConfig); err != nil {
		return refusal{stage: stageConfiguration}
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, parsed.timeout)
	defer cancel()
	connection, err := runtimepostgres.Connect(ctx, dsn)
	if err != nil {
		return refusal{stage: stageDatabase}
	}
	defer func() { _ = connection.Close(context.WithoutCancel(ctx)) }()
	store, err := bootstrap.NewPostgresStore(connection)
	if err != nil {
		return refusal{stage: stageDatabase}
	}
	// A single-tenant deployment serves one provider Organization. Once the
	// product Organization or the deployment configuration names it, this
	// command resolves only that one and never creates another.
	expected := ""
	if mode == "single_tenant" {
		configured := getenv("ZASP_STYTCH_ORGANIZATION_ID")
		bound, err := store.BoundProviderOrganization(ctx, parsed.organizationID)
		switch {
		case errors.Is(err, bootstrap.ErrConflict), err == nil && bound != "" && configured != "" && bound != configured:
			return refusal{stage: stageConflict}
		case err != nil:
			return refusal{stage: stageDatabase}
		}
		expected = bound
		if expected == "" {
			expected = configured
		}
	}
	directoryConfig.ExpectedOrganization = expected
	directory, err := apiserver.NewStytchDirectory(directoryConfig)
	if err != nil {
		return refusal{stage: stageConfiguration}
	}
	provisioner, err := bootstrap.NewProvisioner(directory, store)
	if err != nil {
		return refusal{stage: stageConfiguration}
	}
	result, err := provisioner.Provision(ctx, bootstrap.Request{Name: parsed.name, Domain: parsed.domain, AdminEmail: parsed.adminEmail, OrganizationID: parsed.organizationID, ExpectedOrganizationReference: expected})
	if err != nil {
		return refusal{stage: provisionStage(err)}
	}
	if storeID != "" {
		if err := store.BindAuthorization(ctx, result.OrganizationID, storeID, modelID); err != nil {
			return refusal{stage: stageAuthorization}
		}
	}
	return json.NewEncoder(output).Encode(result)
}

func provisionStage(err error) string {
	switch {
	case errors.Is(err, bootstrap.ErrInvalid):
		return stageArguments
	case errors.Is(err, bootstrap.ErrProvider):
		return stageProvider
	case errors.Is(err, bootstrap.ErrConflict):
		return stageConflict
	default:
		return stageRecords
	}
}
