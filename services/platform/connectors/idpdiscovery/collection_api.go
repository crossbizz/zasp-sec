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
	oktaPageCursorPattern     = regexp.MustCompile(`^okta:(users|groups|applications):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+|start):([0-9a-f]{16})$`)
	oktaCompleteCursorPattern = regexp.MustCompile(`^okta:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	oktaObjectIDPattern       = regexp.MustCompile(`^(00u|00g|0oa)[A-Za-z0-9]{16,64}$`)
)

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
	phase, after, lineagePage, includeTenant, ok := api.validPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.client == nil || ctx == nil || !validOktaCollectionCredential(credential) || !ok {
		return CollectionPage{}, ErrInvalid
	}
	pageLimit := request.RemainingItems
	if includeTenant {
		pageLimit--
	}
	if pageLimit < 1 {
		return CollectionPage{}, ErrInvalid
	}
	if pageLimit > oktaMaximumPageItems {
		pageLimit = oktaMaximumPageItems
	}
	path := map[string]string{"users": "/api/v1/users", "groups": "/api/v1/groups", "applications": "/api/v1/apps"}[phase]
	query := url.Values{}
	query.Set("limit", strconv.Itoa(pageLimit))
	if after != "" {
		query.Set("after", after)
	}
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, api.issuer+path+"?"+query.Encode(), nil)
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
	entities, relationships, ok := normalizeOktaCollectionPage(request.Subject, phase, includeTenant, objects)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	nextAfter, ok := api.oktaNextCursor(response.Header, path)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	complete := false
	next := collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1"}
	if nextAfter != "" {
		next = nextOktaPageCursor(request.Subject, phase, lineagePage+1, base64.RawURLEncoding.EncodeToString([]byte(nextAfter)))
	} else {
		switch phase {
		case "users":
			next = nextOktaPageCursor(request.Subject, "groups", lineagePage+1, "start")
		case "groups":
			next = nextOktaPageCursor(request.Subject, "applications", lineagePage+1, "start")
		case "applications":
			complete = true
			next = nextOktaCompleteCursor(request.Cursor, request.Subject.ID)
		default:
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
	}
	page, err := NewOktaCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
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
		var id, name, status, kind string
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
			if !decodeOktaCollectionResponse(raw, &user) || !strings.HasPrefix(user.ID, "00u") || !validOktaCollectionText(user.Profile.Login, 256) || !validOktaCollectionText(user.Status, 64) {
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
			if !decodeOktaCollectionResponse(raw, &group) || !strings.HasPrefix(group.ID, "00g") || !validOktaCollectionText(group.Profile.Name, 256) || !validOktaCollectionText(group.Type, 64) {
				return nil, nil, false
			}
			id, name, status, kind = group.ID, group.Profile.Name, group.Type, "okta_group"
		case "applications":
			var application struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Label  string `json:"label"`
				Status string `json:"status"`
			}
			if !decodeOktaCollectionResponse(raw, &application) || !strings.HasPrefix(application.ID, "0oa") || !validOktaCollectionText(application.Name, 128) || !validOktaCollectionText(application.Label, 256) || !validOktaCollectionText(application.Status, 64) {
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
	}
	return entities, relationships, true
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
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, from, to, json.RawMessage(`{"type":"tenant_object"}`)})
}

func (api *OktaCollectionAPI) validPageRequest(request CollectionPageRequest) (string, string, int, bool, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if api == nil || request.Provider != collection.ProviderOkta || request.Subject.Kind != "okta_tenant" || request.Subject.ID != api.tenant || (!initialCursor && (request.Cursor.Provider != collection.ProviderOkta || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < oktaMinimumCollectionBytes {
		return "", "", 0, false, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return "users", "", 1, true, request.Page == 1
	}
	if match := oktaCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return "users", "", 1, true, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderOkta, request.Subject)
	}
	match := oktaPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || len(match[3]) > 2048 || request.Page < 1 {
		return "", "", 0, false, false
	}
	page, err := strconv.Atoi(match[2])
	if err != nil || page != request.Page || match[4] != providercollection.CursorBinding(collection.ProviderOkta, request.Subject, match[1], page, match[3]) {
		return "", "", 0, false, false
	}
	if match[3] == "start" {
		return match[1], "", page, false, match[1] != "users"
	}
	decoded, err := base64.RawURLEncoding.DecodeString(match[3])
	if err != nil || !validOktaAfter(string(decoded)) {
		return "", "", 0, false, false
	}
	return match[1], string(decoded), page, false, true
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
	return collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: fmt.Sprintf("okta:%s:%d:%s:%s", phase, page, after, providercollection.CursorBinding(collection.ProviderOkta, subject, phase, page, after))}
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
