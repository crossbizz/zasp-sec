package idpdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	oktaMaximumPageItems       = 200
	oktaMaximumResponseBytes   = int64(8 * 1024 * 1024)
	oktaMinimumCollectionBytes = int64(4096)
)

var (
	oktaPageCursorPattern     = regexp.MustCompile(`^okta:(users|userroles|groups|groupmembers|grouproles|applications|appusers|appgroups|clientroles):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	oktaCompleteCursorPattern = regexp.MustCompile(`^okta:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	oktaObjectIDPattern       = regexp.MustCompile(`^(00u|00g|0oa)[A-Za-z0-9]{16,64}$`)
	oktaRoleIDPattern         = regexp.MustCompile(`^[A-Za-z0-9]{15,64}$`)
	oktaClientIDPattern       = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)
)

type oktaPageState struct {
	Phase       string `json:"p"`
	Lineage     int    `json:"l"`
	After       string `json:"a,omitempty"`
	ResumeAfter string `json:"r,omitempty"`
	PrincipalID string `json:"i,omitempty"`
	AppID       string `json:"x,omitempty"`
	ClientID    string `json:"c,omitempty"`
}

type OktaCollectionAPI struct {
	issuer  string
	tenant  string
	client  *http.Client
	timeout time.Duration
}

var _ CollectionAPI = (*OktaCollectionAPI)(nil)

func NewOktaCollectionAPI(issuer string, timeout time.Duration) (*OktaCollectionAPI, error) {
	match := issuerPattern.FindStringSubmatch(issuer)
	if len(match) != 2 || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: match[1] + ".okta.com"}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 * 1024,
	}
	return newOktaCollectionAPI(issuer, transport, timeout)
}

func newOktaCollectionAPI(issuer string, roundTripper http.RoundTripper, timeout time.Duration) (*OktaCollectionAPI, error) {
	match := issuerPattern.FindStringSubmatch(issuer)
	if len(match) != 2 || roundTripper == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &OktaCollectionAPI{issuer: issuer, tenant: match[1] + ".okta.com", client: &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: rejectOktaCollectionRedirect}, timeout: timeout}, nil
}

func (api *OktaCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	state, includeTenant, ok := api.validPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.client == nil || ctx == nil || !validOktaCollectionCredential(credential) || !ok {
		return CollectionPage{}, ErrInvalid
	}
	path, paginated, ok := oktaCollectionPath(state)
	if !ok {
		return CollectionPage{}, ErrInvalid
	}
	pageLimit := 1
	if state.Phase == "groupmembers" || state.Phase == "appusers" || state.Phase == "appgroups" {
		pageLimit = request.RemainingRelationships
		if pageLimit > oktaMaximumPageItems {
			pageLimit = oktaMaximumPageItems
		}
		if pageLimit < 1 {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
	} else if state.Phase == "userroles" || state.Phase == "grouproles" || state.Phase == "clientroles" {
		pageLimit = oktaMaximumPageItems
	}
	query := url.Values{}
	if paginated {
		query.Set("limit", strconv.Itoa(pageLimit))
		if state.After != "" {
			query.Set("after", state.After)
		}
	}
	providerURL := api.issuer + path
	if len(query) != 0 {
		providerURL += "?" + query.Encode()
	}
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, providerURL, nil)
	if err != nil {
		return CollectionPage{}, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(credential))
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest = providerRequest.WithContext(bounded)
	response, err := doOktaCollectionRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeOktaCollectionResponse(response)
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", time.Now().UTC())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
	}
	responseLimit := request.RemainingBytes
	if responseLimit > oktaMaximumResponseBytes {
		responseLimit = oktaMaximumResponseBytes
	}
	body, ok := readOktaCollectionBody(response.Body, responseLimit)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	var objects []json.RawMessage
	if !decodeOktaCollectionResponse(body, &objects) || len(objects) > pageLimit {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	var entities, relationships []json.RawMessage
	if state.Phase == "users" || state.Phase == "groups" || state.Phase == "applications" {
		entities, relationships, ok = normalizeOktaCollectionPage(request.Subject, state.Phase, includeTenant, objects)
	} else if state.Phase == "userroles" || state.Phase == "grouproles" || state.Phase == "clientroles" {
		entities, relationships, ok = normalizeOktaRoleAssignments(request.Subject, state, objects)
	} else {
		entities, relationships, ok = normalizeOktaAssignmentReferences(request.Subject, state, objects)
	}
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	nextAfter, ok := api.oktaNextCursor(response.Header, path)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	next, complete, transitionOK := nextOktaCollectionCursor(request.Subject, request.Cursor, state, objects, nextAfter)
	if !transitionOK {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	page, err := NewOktaCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || int64(len(page.Raw)) > request.RemainingBytes {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

func (api *OktaCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, api.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return ErrProvider
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	response, err := doOktaCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeOktaCollectionResponse(response)
		return ErrProvider
	}
	defer response.Body.Close()
	body, ok := readOktaCollectionBody(response.Body, 64*1024)
	var metadata struct {
		Issuer string `json:"issuer"`
	}
	if response.StatusCode != http.StatusOK || !ok || !decodeOktaCollectionResponse(body, &metadata) || metadata.Issuer != api.issuer {
		return ErrProvider
	}
	return nil
}

func normalizeOktaCollectionPage(subject collection.SubjectBinding, phase string, includeTenant bool, objects []json.RawMessage) ([]json.RawMessage, []json.RawMessage, bool) {
	tenantEntityID := deterministicOktaInventoryID(subject, "okta_tenant", subject.ID)
	entities := make([]json.RawMessage, 0, len(objects)+1)
	relationships := make([]json.RawMessage, 0, len(objects))
	if includeTenant {
		stable, _ := json.Marshal(struct {
			Tenant string `json:"tenant"`
			Name   string `json:"name"`
		}{subject.ID, strings.TrimSuffix(subject.ID, ".okta.com")})
		entity, err := marshalOktaEntity(tenantEntityID, "okta_tenant", "okta:tenant:"+subject.ID, subject.ID, stable, json.RawMessage(`{}`))
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
	}
	seen := make(map[string]struct{}, len(objects))
	for _, raw := range objects {
		var id, name, status, kind, serviceClientID string
		switch phase {
		case "users":
			var user struct {
				ID      string `json:"id"`
				Status  string `json:"status"`
				Profile struct {
					Login       string `json:"login"`
					DisplayName string `json:"displayName"`
				} `json:"profile"`
			}
			if !decodeOktaCollectionResponse(raw, &user) || !strings.HasPrefix(user.ID, "00u") || !validOktaCollectionText(user.Profile.Login, 256) || !validOktaUserStatus(user.Status) {
				return nil, nil, false
			}
			id, name, status, kind = user.ID, user.Profile.DisplayName, user.Status, "okta_user"
			if name == "" {
				name = user.Profile.Login
			}
		case "groups":
			var group struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Profile struct {
					Name string `json:"name"`
				} `json:"profile"`
			}
			if !decodeOktaCollectionResponse(raw, &group) || !strings.HasPrefix(group.ID, "00g") || !validOktaCollectionText(group.Profile.Name, 256) || !validOktaGroupType(group.Type) {
				return nil, nil, false
			}
			id, name, status, kind = group.ID, group.Profile.Name, group.Type, "okta_group"
		case "applications":
			var application struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Label       string `json:"label"`
				Status      string `json:"status"`
				SignOnMode  string `json:"signOnMode"`
				Credentials struct {
					OAuthClient struct {
						ClientID string `json:"client_id"`
					} `json:"oauthClient"`
				} `json:"credentials"`
			}
			if !decodeOktaCollectionResponse(raw, &application) || !strings.HasPrefix(application.ID, "0oa") || !validOktaCollectionText(application.Name, 128) || !validOktaCollectionText(application.Label, 256) || !validOktaApplicationStatus(application.Status) || !validOktaSignOnMode(application.SignOnMode) {
				return nil, nil, false
			}
			if application.SignOnMode == "OPENID_CONNECT" {
				if !oktaClientIDPattern.MatchString(application.Credentials.OAuthClient.ClientID) {
					return nil, nil, false
				}
				serviceClientID = application.Credentials.OAuthClient.ClientID
			} else if application.Credentials.OAuthClient.ClientID != "" {
				return nil, nil, false
			}
			id, name, status, kind = application.ID, application.Label, application.Status, "okta_application"
		default:
			return nil, nil, false
		}
		if !oktaObjectIDPattern.MatchString(id) || !validOktaCollectionText(name, 256) {
			return nil, nil, false
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, false
		}
		seen[id] = struct{}{}
		entityID := deterministicOktaInventoryID(subject, kind, id)
		stable, _ := json.Marshal(struct {
			Tenant     string `json:"tenant"`
			ObjectType string `json:"object_type"`
			Name       string `json:"name"`
		}{subject.ID, strings.TrimPrefix(kind, "okta_"), name})
		attributes, _ := json.Marshal(struct {
			Status string `json:"status"`
		}{status})
		entity, err := marshalOktaEntity(entityID, kind, "okta:"+strings.TrimPrefix(kind, "okta_")+":"+id, name, stable, attributes)
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationship, err := marshalOktaRelationship(deterministicOktaInventoryID(subject, "contains", id), "contains", "okta:tenant:"+subject.ID+":"+id, tenantEntityID, entityID)
		if err != nil {
			return nil, nil, false
		}
		relationships = append(relationships, relationship)
		if serviceClientID != "" {
			servicePrincipalID := deterministicOktaInventoryID(subject, "okta_service_principal", serviceClientID)
			serviceStable, _ := json.Marshal(struct {
				Tenant     string `json:"tenant"`
				ObjectType string `json:"object_type"`
				Name       string `json:"name"`
			}{subject.ID, "service_principal", serviceClientID})
			serviceEntity, marshalErr := marshalOktaEntity(servicePrincipalID, "okta_service_principal", "okta:service_principal:"+serviceClientID, name+" service principal", serviceStable, attributes)
			if marshalErr != nil {
				return nil, nil, false
			}
			contained, marshalErr := marshalOktaTypedRelationship(deterministicOktaInventoryID(subject, "contains", serviceClientID), "contains", "okta:tenant:"+subject.ID+":service_principal:"+serviceClientID, tenantEntityID, servicePrincipalID, "tenant_service_principal")
			if marshalErr != nil {
				return nil, nil, false
			}
			assigned, marshalErr := marshalOktaTypedRelationship(deterministicOktaInventoryID(subject, "assigned_to", serviceClientID+":"+id), "assigned_to", "okta:service_principal:"+serviceClientID+":application:"+id, servicePrincipalID, entityID, "service_principal_application")
			if marshalErr != nil {
				return nil, nil, false
			}
			entities = append(entities, serviceEntity)
			relationships = append(relationships, contained, assigned)
		}
	}
	return entities, relationships, true
}

type oktaRoleAssignment struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	AssignmentType string `json:"assignmentType"`
}

func normalizeOktaRoleAssignments(subject collection.SubjectBinding, state oktaPageState, objects []json.RawMessage) ([]json.RawMessage, []json.RawMessage, bool) {
	principalKind, expectedAssignment := "", ""
	principalNativeID := state.PrincipalID
	switch state.Phase {
	case "userroles":
		principalKind, expectedAssignment = "okta_user", "USER"
	case "grouproles":
		principalKind, expectedAssignment = "okta_group", "GROUP"
	case "clientroles":
		principalKind, expectedAssignment, principalNativeID = "okta_service_principal", "CLIENT", state.ClientID
	default:
		return nil, nil, false
	}
	principalID := deterministicOktaInventoryID(subject, principalKind, principalNativeID)
	entities := make([]json.RawMessage, 0, len(objects))
	relationships := make([]json.RawMessage, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, raw := range objects {
		var role oktaRoleAssignment
		if !decodeOktaCollectionResponse(raw, &role) || !oktaRoleIDPattern.MatchString(role.ID) || !validOktaCollectionText(role.Label, 256) || !validOktaRoleType(role.Type) || role.Status != "ACTIVE" && role.Status != "INACTIVE" || state.Phase == "userroles" && role.AssignmentType != "USER" && role.AssignmentType != "GROUP" || state.Phase != "userroles" && role.AssignmentType != expectedAssignment {
			return nil, nil, false
		}
		if state.Phase == "userroles" && role.AssignmentType == "GROUP" {
			continue
		}
		if _, duplicate := seen[role.ID]; duplicate {
			return nil, nil, false
		}
		seen[role.ID] = struct{}{}
		roleEntityID := deterministicOktaInventoryID(subject, "okta_role", role.ID)
		stable, _ := json.Marshal(struct {
			Tenant     string `json:"tenant"`
			ObjectType string `json:"object_type"`
			Name       string `json:"name"`
			Role       string `json:"role"`
			Scope      string `json:"scope"`
		}{subject.ID, "admin_role", role.Label, role.Type, strings.ToLower(role.AssignmentType)})
		attributes, _ := json.Marshal(struct {
			Status string `json:"status"`
		}{role.Status})
		entity, err := marshalOktaEntity(roleEntityID, "okta_role", "okta:role_assignment:"+role.ID, role.Label, stable, attributes)
		if err != nil {
			return nil, nil, false
		}
		relationship, err := marshalOktaTypedRelationship(deterministicOktaInventoryID(subject, "assigned_to", principalNativeID+":"+role.ID), "assigned_to", "okta:"+strings.TrimPrefix(principalKind, "okta_")+":"+principalNativeID+":role:"+role.ID, principalID, roleEntityID, "principal_admin_role")
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
	}
	return entities, relationships, true
}

func normalizeOktaAssignmentReferences(subject collection.SubjectBinding, state oktaPageState, objects []json.RawMessage) ([]json.RawMessage, []json.RawMessage, bool) {
	relationships := make([]json.RawMessage, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, raw := range objects {
		var reference struct {
			ID    string `json:"id"`
			Scope string `json:"scope,omitempty"`
		}
		if !decodeOktaCollectionResponse(raw, &reference) || !oktaObjectIDPattern.MatchString(reference.ID) {
			return nil, nil, false
		}
		if _, duplicate := seen[reference.ID]; duplicate {
			return nil, nil, false
		}
		seen[reference.ID] = struct{}{}
		var kind, source, relationshipType, from, to string
		switch state.Phase {
		case "groupmembers":
			if !strings.HasPrefix(reference.ID, "00u") {
				return nil, nil, false
			}
			kind, relationshipType = "member_of", "user_group_membership"
			source = "okta:user:" + reference.ID + ":group:" + state.PrincipalID
			from = deterministicOktaInventoryID(subject, "okta_user", reference.ID)
			to = deterministicOktaInventoryID(subject, "okta_group", state.PrincipalID)
		case "appusers":
			if !strings.HasPrefix(reference.ID, "00u") || reference.Scope != "USER" && reference.Scope != "GROUP" {
				return nil, nil, false
			}
			if reference.Scope == "GROUP" {
				continue
			}
			kind, relationshipType = "assigned_to", "user_application_assignment"
			source = "okta:user:" + reference.ID + ":application:" + state.AppID
			from = deterministicOktaInventoryID(subject, "okta_user", reference.ID)
			to = deterministicOktaInventoryID(subject, "okta_application", state.AppID)
		case "appgroups":
			if !strings.HasPrefix(reference.ID, "00g") {
				return nil, nil, false
			}
			kind, relationshipType = "assigned_to", "group_application_assignment"
			source = "okta:group:" + reference.ID + ":application:" + state.AppID
			from = deterministicOktaInventoryID(subject, "okta_group", reference.ID)
			to = deterministicOktaInventoryID(subject, "okta_application", state.AppID)
		default:
			return nil, nil, false
		}
		relationshipID := deterministicOktaInventoryID(subject, kind, source)
		relationship, err := marshalOktaTypedRelationship(relationshipID, kind, source, from, to, relationshipType)
		if err != nil {
			return nil, nil, false
		}
		relationships = append(relationships, relationship)
	}
	return nil, relationships, true
}

func validOktaRoleType(value string) bool {
	switch value {
	case "ACCESS_CERTIFICATIONS_ADMIN", "ACCESS_REQUESTS_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "APP_ADMIN", "CUSTOM", "GROUP_MEMBERSHIP_ADMIN", "HELP_DESK_ADMIN", "MOBILE_ADMIN", "ORG_ADMIN", "READ_ONLY_ADMIN", "REPORT_ADMIN", "SUPER_ADMIN", "USER_ADMIN", "WORKFLOWS_ADMIN":
		return true
	default:
		return false
	}
}

func validOktaUserStatus(value string) bool {
	switch value {
	case "STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "LOCKED_OUT", "PASSWORD_EXPIRED", "SUSPENDED", "DEPROVISIONED":
		return true
	default:
		return false
	}
}

func validOktaGroupType(value string) bool {
	switch value {
	case "OKTA_GROUP", "APP_GROUP", "BUILT_IN":
		return true
	default:
		return false
	}
}

func validOktaApplicationStatus(value string) bool {
	return value == "ACTIVE" || value == "INACTIVE"
}

func validOktaSignOnMode(value string) bool {
	switch value {
	case "AUTO_LOGIN", "BASIC_AUTH", "BOOKMARK", "BROWSER_PLUGIN", "OPENID_CONNECT", "SAML_1_1", "SAML_2_0", "SECURE_PASSWORD_STORE", "WS_FEDERATION":
		return true
	default:
		return false
	}
}

func marshalOktaEntity(id, kind, sourceNativeID, displayName string, stable, attributes json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stable, attributes})
}

func marshalOktaRelationship(id, kind, sourceNativeID, from, to string) (json.RawMessage, error) {
	return marshalOktaTypedRelationship(id, kind, sourceNativeID, from, to, "tenant_object")
}

func marshalOktaTypedRelationship(id, kind, sourceNativeID, from, to, relationshipType string) (json.RawMessage, error) {
	attributes, err := json.Marshal(struct {
		Type string `json:"type"`
	}{relationshipType})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, from, to, attributes})
}

func (api *OktaCollectionAPI) validPageRequest(request CollectionPageRequest) (oktaPageState, bool, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if api == nil || request.Provider != collection.ProviderOkta || request.Subject.Kind != "okta_tenant" || request.Subject.ID != api.tenant || (!initialCursor && (request.Cursor.Provider != collection.ProviderOkta || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < oktaMinimumCollectionBytes {
		return oktaPageState{}, false, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return oktaPageState{Phase: "users", Lineage: 1}, true, request.Page == 1
	}
	if match := oktaCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return oktaPageState{Phase: "users", Lineage: 1}, true, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderOkta, request.Subject)
	}
	match := oktaPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || len(match[3]) > 1800 || request.Page < 1 {
		return oktaPageState{}, false, false
	}
	lineage, err := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state oktaPageState
	if err != nil || decodeErr != nil || lineage != request.Page || len(payload) < 2 || len(payload) > 1350 || json.Unmarshal(payload, &state) != nil || state.Phase != match[1] || state.Lineage != lineage || match[4] != providercollection.CursorBinding(collection.ProviderOkta, request.Subject, match[1], lineage, match[3]) || !validOktaPageState(state) {
		return oktaPageState{}, false, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return oktaPageState{}, false, false
	}
	return state, false, true
}

func validOktaPageState(state oktaPageState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || state.After != "" && !validOktaAfter(state.After) || state.ResumeAfter != "" && !validOktaAfter(state.ResumeAfter) {
		return false
	}
	switch state.Phase {
	case "users", "groups", "applications":
		return state.PrincipalID == "" && state.AppID == "" && state.ClientID == "" && state.ResumeAfter == ""
	case "userroles":
		return strings.HasPrefix(state.PrincipalID, "00u") && oktaObjectIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == "" && state.After == ""
	case "groupmembers":
		return strings.HasPrefix(state.PrincipalID, "00g") && oktaObjectIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == ""
	case "grouproles":
		return strings.HasPrefix(state.PrincipalID, "00g") && oktaObjectIDPattern.MatchString(state.PrincipalID) && state.AppID == "" && state.ClientID == "" && state.After == ""
	case "appusers", "appgroups":
		return state.PrincipalID == "" && strings.HasPrefix(state.AppID, "0oa") && oktaObjectIDPattern.MatchString(state.AppID) && (state.ClientID == "" || oktaClientIDPattern.MatchString(state.ClientID))
	case "clientroles":
		return state.PrincipalID == "" && strings.HasPrefix(state.AppID, "0oa") && oktaObjectIDPattern.MatchString(state.AppID) && oktaClientIDPattern.MatchString(state.ClientID) && state.After == ""
	default:
		return false
	}
}

func oktaCollectionPath(state oktaPageState) (string, bool, bool) {
	switch state.Phase {
	case "users":
		return "/api/v1/users", true, true
	case "userroles":
		return "/api/v1/users/" + url.PathEscape(state.PrincipalID) + "/roles", false, true
	case "groups":
		return "/api/v1/groups", true, true
	case "groupmembers":
		return "/api/v1/groups/" + url.PathEscape(state.PrincipalID) + "/users", true, true
	case "grouproles":
		return "/api/v1/groups/" + url.PathEscape(state.PrincipalID) + "/roles", false, true
	case "applications":
		return "/api/v1/apps", true, true
	case "appusers":
		return "/api/v1/apps/" + url.PathEscape(state.AppID) + "/users", true, true
	case "appgroups":
		return "/api/v1/apps/" + url.PathEscape(state.AppID) + "/groups", true, true
	case "clientroles":
		return "/oauth2/v1/clients/" + url.PathEscape(state.ClientID) + "/roles", false, true
	default:
		return "", false, false
	}
}

func (api *OktaCollectionAPI) oktaNextCursor(header http.Header, expectedPath string) (string, bool) {
	values := header.Values("Link")
	if len(values) == 0 {
		return "", true
	}
	next := ""
	for _, value := range strings.Split(strings.Join(values, ","), ",") {
		parts := strings.Split(strings.TrimSpace(value), ";")
		if len(parts) != 2 {
			return "", false
		}
		relation := strings.TrimSpace(parts[1])
		if relation != `rel="next"` && relation != `rel="self"` {
			return "", false
		}
		if relation == `rel="self"` {
			continue
		}
		if next != "" || len(parts[0]) < 3 || parts[0][0] != '<' || parts[0][len(parts[0])-1] != '>' {
			return "", false
		}
		parsed, err := url.Parse(parts[0][1 : len(parts[0])-1])
		if err != nil || parsed.Scheme+"://"+parsed.Host != api.issuer || parsed.User != nil || parsed.Path != expectedPath || parsed.Fragment != "" {
			return "", false
		}
		query := parsed.Query()
		if len(query) < 1 || len(query) > 2 || len(query["after"]) != 1 || query.Get("after") == "" || query.Has("limit") && len(query["limit"]) != 1 {
			return "", false
		}
		for key := range query {
			if key != "after" && key != "limit" {
				return "", false
			}
		}
		if query.Has("limit") {
			limit, limitErr := strconv.Atoi(query.Get("limit"))
			if limitErr != nil || limit < 1 || limit > oktaMaximumPageItems {
				return "", false
			}
		}
		next = query.Get("after")
		if !validOktaAfter(next) {
			return "", false
		}
	}
	return next, true
}

func nextOktaCollectionCursor(subject collection.SubjectBinding, prior collection.Cursor, state oktaPageState, objects []json.RawMessage, nextAfter string) (collection.Cursor, bool, bool) {
	nextLineage := state.Lineage + 1
	state.Lineage = nextLineage
	switch state.Phase {
	case "users":
		if len(objects) == 0 {
			if nextAfter != "" {
				return collection.Cursor{}, false, false
			}
			return nextOktaStateCursor(subject, oktaPageState{Phase: "groups", Lineage: nextLineage})
		}
		id, ok := oktaObjectID(objects[0], "00u")
		if !ok {
			return collection.Cursor{}, false, false
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "userroles", Lineage: nextLineage, ResumeAfter: nextAfter, PrincipalID: id})
	case "userroles":
		if nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		if state.ResumeAfter != "" {
			return nextOktaStateCursor(subject, oktaPageState{Phase: "users", Lineage: nextLineage, After: state.ResumeAfter})
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "groups", Lineage: nextLineage})
	case "groups":
		if len(objects) == 0 {
			if nextAfter != "" {
				return collection.Cursor{}, false, false
			}
			return nextOktaStateCursor(subject, oktaPageState{Phase: "applications", Lineage: nextLineage})
		}
		id, ok := oktaObjectID(objects[0], "00g")
		if !ok {
			return collection.Cursor{}, false, false
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "groupmembers", Lineage: nextLineage, ResumeAfter: nextAfter, PrincipalID: id})
	case "groupmembers":
		if len(objects) == 0 && nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		if nextAfter != "" {
			state.After = nextAfter
			return nextOktaStateCursor(subject, state)
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "grouproles", Lineage: nextLineage, ResumeAfter: state.ResumeAfter, PrincipalID: state.PrincipalID})
	case "grouproles":
		if nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		if state.ResumeAfter != "" {
			return nextOktaStateCursor(subject, oktaPageState{Phase: "groups", Lineage: nextLineage, After: state.ResumeAfter})
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "applications", Lineage: nextLineage})
	case "applications":
		if len(objects) == 0 {
			if nextAfter != "" {
				return collection.Cursor{}, false, false
			}
			return nextOktaCompleteCursor(prior, subject.ID), true, true
		}
		appID, clientID, ok := oktaApplicationAuthority(objects[0])
		if !ok {
			return collection.Cursor{}, false, false
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "appusers", Lineage: nextLineage, ResumeAfter: nextAfter, AppID: appID, ClientID: clientID})
	case "appusers":
		if len(objects) == 0 && nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		if nextAfter != "" {
			state.After = nextAfter
			return nextOktaStateCursor(subject, state)
		}
		return nextOktaStateCursor(subject, oktaPageState{Phase: "appgroups", Lineage: nextLineage, ResumeAfter: state.ResumeAfter, AppID: state.AppID, ClientID: state.ClientID})
	case "appgroups":
		if len(objects) == 0 && nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		if nextAfter != "" {
			state.After = nextAfter
			return nextOktaStateCursor(subject, state)
		}
		if state.ClientID != "" {
			return nextOktaStateCursor(subject, oktaPageState{Phase: "clientroles", Lineage: nextLineage, ResumeAfter: state.ResumeAfter, AppID: state.AppID, ClientID: state.ClientID})
		}
		return nextOktaAfterApplication(subject, prior, nextLineage, state.ResumeAfter)
	case "clientroles":
		if nextAfter != "" {
			return collection.Cursor{}, false, false
		}
		return nextOktaAfterApplication(subject, prior, nextLineage, state.ResumeAfter)
	default:
		return collection.Cursor{}, false, false
	}
}

func nextOktaAfterApplication(subject collection.SubjectBinding, prior collection.Cursor, lineage int, resumeAfter string) (collection.Cursor, bool, bool) {
	if resumeAfter != "" {
		return nextOktaStateCursor(subject, oktaPageState{Phase: "applications", Lineage: lineage, After: resumeAfter})
	}
	return nextOktaCompleteCursor(prior, subject.ID), true, true
}

func oktaObjectID(raw json.RawMessage, prefix string) (string, bool) {
	var object struct {
		ID string `json:"id"`
	}
	if !decodeOktaCollectionResponse(raw, &object) || !strings.HasPrefix(object.ID, prefix) || !oktaObjectIDPattern.MatchString(object.ID) {
		return "", false
	}
	return object.ID, true
}

func oktaApplicationAuthority(raw json.RawMessage) (string, string, bool) {
	var application struct {
		ID          string `json:"id"`
		SignOnMode  string `json:"signOnMode"`
		Credentials struct {
			OAuthClient struct {
				ClientID string `json:"client_id"`
			} `json:"oauthClient"`
		} `json:"credentials"`
	}
	if !decodeOktaCollectionResponse(raw, &application) || !strings.HasPrefix(application.ID, "0oa") || !oktaObjectIDPattern.MatchString(application.ID) {
		return "", "", false
	}
	if application.SignOnMode == "OPENID_CONNECT" {
		return application.ID, application.Credentials.OAuthClient.ClientID, oktaClientIDPattern.MatchString(application.Credentials.OAuthClient.ClientID)
	}
	return application.ID, "", application.Credentials.OAuthClient.ClientID == ""
}

func validOktaCollectionCredential(value []byte) bool {
	if len(value) < 16 || len(value) > 8192 || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOktaCollectionText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOktaAfter(value string) bool {
	return validOktaCollectionText(value, 1536) && !strings.ContainsAny(value, "&=?#")
}

func deterministicOktaInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("okta\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func nextOktaCompleteCursor(prior collection.Cursor, subjectID string) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subjectID + "\x1fcomplete"))
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: subjectID}
	return collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: fmt.Sprintf("okta:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderOkta, subject), digest[:8])}
}

func nextOktaPageCursor(subject collection.SubjectBinding, phase string, page int, after string) collection.Cursor {
	state := oktaPageState{Phase: phase, Lineage: page}
	if after != "" && after != "start" {
		decoded, err := base64.RawURLEncoding.DecodeString(after)
		if err != nil {
			return collection.Cursor{}
		}
		state.After = string(decoded)
	}
	cursor, _, ok := nextOktaStateCursor(subject, state)
	if !ok {
		return collection.Cursor{}
	}
	return cursor
}

func nextOktaStateCursor(subject collection.SubjectBinding, state oktaPageState) (collection.Cursor, bool, bool) {
	if !validOktaPageState(state) {
		return collection.Cursor{}, false, false
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 1350 {
		return collection.Cursor{}, false, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderOkta, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: fmt.Sprintf("okta:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, false, len(cursor.Value) <= 2048
}

func decodeOktaCollectionResponse(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func readOktaCollectionBody(body io.Reader, maximum int64) ([]byte, bool) {
	if maximum < 1 {
		return nil, false
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	return value, err == nil && len(value) > 0 && int64(len(value)) <= maximum
}

func doOktaCollectionRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrProvider
		}
	}()
	return client.Do(request)
}

func closeOktaCollectionResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func rejectOktaCollectionRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
