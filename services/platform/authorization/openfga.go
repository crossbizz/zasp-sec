package authorization

import (
	"context"
	"time"

	sdk "github.com/openfga/go-sdk"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// OpenFGA borrows the authenticated official client from runtimeservices.Clients.
// The runtime owner closes it; this adapter neither creates nor mutates a client.
type OpenFGA struct {
	client           *fga.OpenFgaClient
	storeID, modelID string
	timeout          time.Duration
}

func NewOpenFGA(client *fga.OpenFgaClient, config runtimeservices.Config) (*OpenFGA, error) {
	if client == nil || !config.Enabled || config.Validate() != nil {
		return nil, ErrInvalid
	}
	return &OpenFGA{client: client, storeID: config.StoreID, modelID: config.ModelID, timeout: config.Timeout}, nil
}

// A dedicated adapter checks the same mapped decisions through an FGA-only
// connection. It cannot acquire a Temporal client as a side effect.
func NewOpenFGAAuthorizationOnly(client *fga.OpenFgaClient, config runtimeservices.Config) (*OpenFGA, error) {
	if client == nil || config.ValidateAuthorizationOnly() != nil {
		return nil, ErrInvalid
	}
	return &OpenFGA{client: client, storeID: config.StoreID, modelID: config.ModelID, timeout: config.Timeout}, nil
}

// Check performs no caching and no legacy fallback. A model-read readiness
// result is never used here. Grant revision validation belongs to the caller.
func (c *OpenFGA) Check(ctx context.Context, r CheckRequest) (Decision, error) {
	if c == nil || c.client == nil {
		return Decision{}, ErrUnavailable
	}
	decision := Decision{ModelID: c.modelID}
	binding, err := Map(r)
	if err != nil || ctx == nil {
		return decision, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body := fga.ClientCheckRequest{User: binding.User, Relation: binding.Relation, Object: binding.Object}
	if r.PrincipalKind != "user" {
		values := map[string]interface{}{"task": r.TaskID}
		body.Context = &values
	}
	consistency := sdk.ConsistencyPreference("HIGHER_CONSISTENCY")
	result, err := c.client.Check(bounded).Body(body).Options(fga.ClientCheckOptions{StoreId: &c.storeID, AuthorizationModelId: &c.modelID, Consistency: &consistency}).Execute()
	if err != nil || result == nil {
		return decision, ErrUnavailable
	}
	decision.Allowed = result.GetAllowed()
	return decision, nil
}
