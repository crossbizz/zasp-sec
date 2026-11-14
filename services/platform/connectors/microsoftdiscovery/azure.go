package microsoftdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// Azure OpenAI and Azure AI Foundry, read from Azure Resource Manager with the
// same application the Microsoft connection already uses. Nothing is read
// from a resource's data plane.
//
// The phase runs only when the credential carries a Resource Manager token
// (the deployment opted in). One page reads one page of the Cognitive
// Services accounts of one subscription, and the model deployments of the
// AI accounts on it:
//
//	GET /subscriptions                                      which subscriptions the application may read
//	GET /subscriptions/{id}/providers/Microsoft.CognitiveServices/accounts
//	GET {account}/deployments                               for each Azure OpenAI or AI Foundry account
//
// The application needs the Azure role Reader (or Cognitive Services User,
// or any role with Microsoft.CognitiveServices/accounts/read and
// .../deployments/read) on each subscription. Without a role the list of
// subscriptions is empty and the phase emits nothing. Foundry agents are not
// Resource Manager resources and are not read here.
//
// The paths, api-versions and response members are from the Resource Manager
// REST reference as remembered: UNVERIFIED against a real subscription.
const (
	microsoftARMHost              = "management.azure.com"
	microsoftARMSubscriptionsPath = "/subscriptions"
	microsoftARMSubscriptionsAPI  = "2022-12-01"
	microsoftARMCognitiveAPI      = "2023-05-01"
	microsoftPhaseAzure           = "azure"
	// One page reads the deployments of at most this many accounts. The
	// accounts beyond it are still listed, marked as not having had their
	// deployments read.
	microsoftMaximumAzureDeploymentReads = 40
	microsoftMaximumAzureSubscriptions   = 200
)

var (
	microsoftARMAccountIDPattern = regexp.MustCompile(`^/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/resourceGroups/([A-Za-z0-9._()-]{1,90})/providers/Microsoft\.CognitiveServices/accounts/([A-Za-z0-9][A-Za-z0-9._-]{1,63})$`)
	microsoftARMNamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	microsoftARMLocationPattern  = regexp.MustCompile(`^[a-z0-9]{2,40}$`)
	microsoftARMHostPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,8}$`)
	// The account kinds that serve models: Azure OpenAI and AI Foundry.
	microsoftARMAIKinds = map[string]string{"openai": "azure_openai", "aiservices": "azure_ai_foundry"}
)

// armGet sends one GET to Resource Manager and returns the status and, for
// 200, the bounded body.
func (api *MicrosoftCollectionAPI) armGet(ctx context.Context, token []byte, path, query string) (int, []byte, string, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "https://"+microsoftARMHost+path+"?"+query, nil)
	if err != nil {
		return 0, nil, "", ErrInvalid
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := doMicrosoftCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeMicrosoftCollectionResponse(response)
		return 0, nil, "", providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil, response.Header.Get("Retry-After"), nil
	}
	body, ok := readMicrosoftCollectionBody(response.Body, microsoftMaximumResponseBytes)
	if !ok {
		return 0, nil, "", providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return http.StatusOK, body, "", nil
}

type armList struct {
	NextLink *string            `json:"nextLink"`
	Value    *[]json.RawMessage `json:"value"`
}

// fetchAzurePage reads one page of one subscription's AI accounts.
func (api *MicrosoftCollectionAPI) fetchAzurePage(ctx context.Context, credential []byte, envelope microsoftCredential, request CollectionPageRequest, state microsoftPageState) (CollectionPage, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	if envelope.armToken == nil {
		return CollectionPage{}, ErrInvalid
	}
	first := state.Subscription == "" && state.Continuation == ""
	finish := func(entities, relationships []json.RawMessage, next microsoftPageState, complete bool) (CollectionPage, error) {
		cursor, done := nextMicrosoftCompleteCursor(request.Cursor, request.Subject), true
		if !complete {
			var ok bool
			if cursor, done, ok = nextMicrosoftStateCursor(request.Subject, next); !ok {
				return CollectionPage{}, malformed
			}
		}
		page, err := NewMicrosoftCollectionPage(request.Subject, cursor, done, entities, relationships)
		if err != nil || bytes.Contains(page.Raw, credential) || bytes.Contains(page.Raw, envelope.graphToken) || bytes.Contains(page.Raw, envelope.armToken) {
			return CollectionPage{}, malformed
		}
		if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || int64(len(page.Raw)) > request.RemainingBytes {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	status, body, retryAfter, err := api.armGet(ctx, envelope.armToken, microsoftARMSubscriptionsPath, "api-version="+microsoftARMSubscriptionsAPI)
	if err != nil {
		return CollectionPage{}, err
	}
	// The application was never given a role in Azure: Resource Manager
	// refuses it. That says nothing about the rest of the tenant, so the
	// phase ends with nothing emitted. The same refusal later in the phase is
	// a failure.
	if first && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		return finish(nil, nil, microsoftPageState{}, true)
	}
	if status != http.StatusOK {
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
	}
	var listed armList
	if !decodeMicrosoftCollectionResponse(body, &listed) || listed.Value == nil || len(*listed.Value) > microsoftMaximumAzureSubscriptions {
		return CollectionPage{}, malformed
	}
	subscriptions := make([]string, 0, len(*listed.Value))
	for _, raw := range *listed.Value {
		var subscription struct {
			SubscriptionID string `json:"subscriptionId"`
			State          string `json:"state"`
		}
		if !decodeMicrosoftCollectionResponse(raw, &subscription) || !microsoftObjectIDPattern.MatchString(subscription.SubscriptionID) {
			return CollectionPage{}, malformed
		}
		if subscription.State == "" || subscription.State == "Enabled" {
			subscriptions = append(subscriptions, strings.ToLower(subscription.SubscriptionID))
		}
	}
	sort.Strings(subscriptions)
	// The subscription of this page: the one the cursor names, or the first.
	// One that disappeared since the cursor was written is passed over.
	current := state.Subscription
	if current == "" && len(subscriptions) > 0 {
		current = subscriptions[0]
	}
	following := ""
	for _, subscription := range subscriptions {
		if subscription > current {
			following = subscription
			break
		}
	}
	if current == "" {
		return finish(nil, nil, microsoftPageState{}, true)
	}
	advance := func(entities, relationships []json.RawMessage, continuation string) (CollectionPage, error) {
		if continuation != "" {
			return finish(entities, relationships, microsoftPageState{Phase: microsoftPhaseAzure, Lineage: state.Lineage + 1, Subscription: current, Continuation: continuation}, false)
		}
		if following != "" {
			return finish(entities, relationships, microsoftPageState{Phase: microsoftPhaseAzure, Lineage: state.Lineage + 1, Subscription: following}, false)
		}
		return finish(entities, relationships, microsoftPageState{}, true)
	}
	present := false
	for _, subscription := range subscriptions {
		present = present || subscription == current
	}
	if !present {
		return advance(nil, nil, "")
	}
	accountsPath := "/subscriptions/" + current + "/providers/Microsoft.CognitiveServices/accounts"
	query := "api-version=" + microsoftARMCognitiveAPI
	if state.Continuation != "" {
		query += "&$skiptoken=" + strings.ReplaceAll(url.QueryEscape(state.Continuation), "+", "%20")
	}
	status, body, retryAfter, err = api.armGet(ctx, envelope.armToken, accountsPath, query)
	if err != nil {
		return CollectionPage{}, err
	}
	if status != http.StatusOK {
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
	}
	var accounts armList
	if !decodeMicrosoftCollectionResponse(body, &accounts) || accounts.Value == nil {
		return CollectionPage{}, malformed
	}
	continuation := ""
	if accounts.NextLink != nil && *accounts.NextLink != "" {
		var ok bool
		if continuation, ok = microsoftNextContinuation(*accounts.NextLink, microsoftARMHost, accountsPath); !ok || continuation == state.Continuation || bytes.Contains([]byte(continuation), envelope.armToken) {
			return CollectionPage{}, malformed
		}
	}
	tenantEntityID := deterministicMicrosoftInventoryID(request.Subject, "microsoft_tenant", request.Subject.ID)
	var entities, relationships []json.RawMessage
	emit := func(kind, native, display string, stable, attributes any) bool {
		encodedStable, _ := json.Marshal(stable)
		encodedAttributes, _ := json.Marshal(attributes)
		entityID := deterministicMicrosoftInventoryID(request.Subject, kind, native)
		entity, entityErr := marshalMicrosoftEntity(entityID, kind, "microsoft:azure:"+native, display, encodedStable, encodedAttributes)
		relationship, relationshipErr := marshalMicrosoftRelationship(deterministicMicrosoftInventoryID(request.Subject, "contains", "azure:"+native), "microsoft:tenant:"+request.Subject.ID+":azure:"+native, tenantEntityID, entityID)
		if entityErr != nil || relationshipErr != nil {
			return false
		}
		entities, relationships = append(entities, entity), append(relationships, relationship)
		return true
	}
	seen := map[string]bool{}
	reads := 0
	for _, raw := range *accounts.Value {
		var account struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Location   string `json:"location"`
			Properties struct {
				ProvisioningState   string `json:"provisioningState"`
				Endpoint            string `json:"endpoint"`
				PublicNetworkAccess string `json:"publicNetworkAccess"`
				DisableLocalAuth    *bool  `json:"disableLocalAuth"`
			} `json:"properties"`
		}
		if !decodeMicrosoftCollectionResponse(raw, &account) {
			return CollectionPage{}, malformed
		}
		resourceKind, ai := microsoftARMAIKinds[strings.ToLower(account.Kind)]
		if !ai {
			// Speech, vision and the other Cognitive Services kinds serve no
			// model deployments and are not inventory of this collector.
			continue
		}
		match := microsoftARMAccountIDPattern.FindStringSubmatch(account.ID)
		location := strings.ToLower(strings.ReplaceAll(account.Location, " ", ""))
		if len(match) != 4 || strings.ToLower(match[1]) != current || match[3] != account.Name || !microsoftARMLocationPattern.MatchString(location) || seen[strings.ToLower(account.ID)] {
			return CollectionPage{}, malformed
		}
		native := strings.ToLower(account.ID)
		seen[native] = true
		attributes := map[string]any{"status": microsoftARMState(account.Properties.ProvisioningState), "resource_kind": resourceKind}
		if parsed, parseErr := url.Parse(account.Properties.Endpoint); parseErr == nil && parsed.Scheme == "https" && microsoftARMHostPattern.MatchString(strings.ToLower(parsed.Hostname())) {
			attributes["endpoint_host"] = strings.ToLower(parsed.Hostname())
		}
		switch strings.ToLower(account.Properties.PublicNetworkAccess) {
		case "enabled", "disabled":
			attributes["public_network_access"] = strings.ToLower(account.Properties.PublicNetworkAccess)
		}
		if account.Properties.DisableLocalAuth != nil {
			attributes["local_auth_disabled"] = *account.Properties.DisableLocalAuth
		}
		attributes["deployments"] = "not_listed"
		var deployments []json.RawMessage
		if reads < microsoftMaximumAzureDeploymentReads {
			reads++
			status, body, retryAfter, err = api.armGet(ctx, envelope.armToken, account.ID+"/deployments", "api-version="+microsoftARMCognitiveAPI)
			if err != nil {
				return CollectionPage{}, err
			}
			switch {
			case status == http.StatusOK:
				var page armList
				if !decodeMicrosoftCollectionResponse(body, &page) || page.Value == nil {
					return CollectionPage{}, malformed
				}
				deployments, attributes["deployments"] = *page.Value, "listed"
			// The account was deleted since the list, or the role covers the
			// account and not its deployments: the account is still listed.
			case status == http.StatusNotFound || status == http.StatusForbidden:
			default:
				return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
			}
		}
		stable := struct {
			Name         string `json:"name"`
			ObjectType   string `json:"object_type"`
			Region       string `json:"region"`
			Subscription string `json:"subscription"`
			Tenant       string `json:"tenant"`
		}{account.Name, "azure_ai_account", location, current, request.Subject.ID}
		if !emit("microsoft_ai_resource", native, account.Name, stable, attributes) {
			return CollectionPage{}, malformed
		}
		for _, rawDeployment := range deployments {
			var deployment struct {
				Name       string `json:"name"`
				Properties struct {
					ProvisioningState string `json:"provisioningState"`
					Model             struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"model"`
				} `json:"properties"`
			}
			if !decodeMicrosoftCollectionResponse(rawDeployment, &deployment) || !microsoftARMNamePattern.MatchString(deployment.Name) || seen[native+"/deployments/"+strings.ToLower(deployment.Name)] {
				return CollectionPage{}, malformed
			}
			deploymentNative := native + "/deployments/" + strings.ToLower(deployment.Name)
			seen[deploymentNative] = true
			deploymentAttributes := map[string]any{"status": microsoftARMState(deployment.Properties.ProvisioningState)}
			if validMicrosoftCollectionText(deployment.Properties.Model.Name, 128) {
				deploymentAttributes["model"] = deployment.Properties.Model.Name
			}
			if validMicrosoftCollectionText(deployment.Properties.Model.Version, 64) {
				deploymentAttributes["model_version"] = deployment.Properties.Model.Version
			}
			deploymentStable := struct {
				Name         string `json:"name"`
				ObjectType   string `json:"object_type"`
				Resource     string `json:"resource"`
				Subscription string `json:"subscription"`
				Tenant       string `json:"tenant"`
			}{deployment.Name, "azure_ai_deployment", account.Name, current, request.Subject.ID}
			if !emit("microsoft_ai_deployment", deploymentNative, account.Name+"/"+deployment.Name, deploymentStable, deploymentAttributes) {
				return CollectionPage{}, malformed
			}
		}
	}
	return advance(entities, relationships, continuation)
}

// microsoftARMState is a provisioning state in the status form the other
// Microsoft kinds use; one worded in an unexpected way is UNKNOWN.
func microsoftARMState(value string) string {
	if len(value) < 1 || len(value) > 32 {
		return "UNKNOWN"
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return "UNKNOWN"
		}
	}
	return strings.ToUpper(value)
}
