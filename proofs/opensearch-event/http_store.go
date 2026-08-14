package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maximumResponseBytes = 1 << 20
	maximumRequestBytes  = 64 << 10
	requestTimeout       = 5 * time.Second
	readRetryDelay       = 25 * time.Millisecond
)

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type validatedEndpoint struct {
	baseURL, hostname, port string
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type httpBackend struct {
	client    *http.Client
	transport *http.Transport
	endpoint  validatedEndpoint
	spec      IndexSpec
}

type createIndexResponse struct {
	Acknowledged       bool   `json:"acknowledged"`
	ShardsAcknowledged bool   `json:"shards_acknowledged"`
	Index              string `json:"index"`
}

type deleteIndexResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

type mappingField struct {
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
}

type mappingMetadata struct {
	Proof  string `json:"zasp_proof"`
	Marker string `json:"zasp_marker"`
	Role   string `json:"zasp_role"`
}

type mappingDefinition struct {
	Dynamic    string                  `json:"dynamic"`
	Metadata   mappingMetadata         `json:"_meta"`
	Properties map[string]mappingField `json:"properties"`
}

type mappingIndex struct {
	Mappings mappingDefinition `json:"mappings"`
}

type settingsIndex struct {
	Settings map[string]string `json:"settings"`
}

type catIndex struct {
	Index string `json:"index"`
}

type shardResult struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Skipped    int `json:"skipped,omitempty"`
	Failed     int `json:"failed"`
}

type indexDocumentResponse struct {
	Index       string      `json:"_index"`
	ID          string      `json:"_id"`
	Version     int         `json:"_version"`
	Result      string      `json:"result"`
	Shards      shardResult `json:"_shards"`
	Sequence    int         `json:"_seq_no"`
	PrimaryTerm int         `json:"_primary_term"`
}

type searchTotal struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

type searchHit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Score  *float64               `json:"_score"`
	Source NormalizedSessionEvent `json:"_source"`
}

type searchHits struct {
	Total    searchTotal `json:"total"`
	MaxScore *float64    `json:"max_score"`
	Hits     []searchHit `json:"hits"`
}

type searchResponse struct {
	Took     int         `json:"took"`
	TimedOut bool        `json:"timed_out"`
	Shards   shardResult `json:"_shards"`
	Hits     searchHits  `json:"hits"`
}

func newHTTPBackend(ctx context.Context, rawEndpoint string, spec IndexSpec) (*httpBackend, error) {
	endpoint, err := validateEndpoint(ctx, rawEndpoint, nil)
	if err != nil || !validIndexState(spec, expectedIndexSpec(spec.Marker)) {
		return nil, errConfiguration
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           loopbackDialerWithResolver(endpoint, net.DefaultResolver),
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &httpBackend{client: client, transport: transport, endpoint: endpoint, spec: copyIndexSpec(spec)}, nil
}

func (h *httpBackend) Close() {
	if h != nil && h.transport != nil {
		h.transport.CloseIdleConnections()
	}
}

func validateEndpoint(ctx context.Context, raw string, resolver hostResolver) (validatedEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Port() == "80" || parsed.Opaque != "" {
		return validatedEndpoint{}, errConfiguration
	}
	portNumber, err := strconv.Atoi(parsed.Port())
	if err != nil || portNumber < 1024 || portNumber > 65535 {
		return validatedEndpoint{}, errConfiguration
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "0.0.0.0" || host == "::" {
		return validatedEndpoint{}, errConfiguration
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			return validatedEndpoint{}, errConfiguration
		}
	} else {
		if host != "localhost" {
			return validatedEndpoint{}, errConfiguration
		}
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, lookupErr := resolver.LookupHost(ctx, host)
		if lookupErr != nil || !allLoopback(addresses) {
			return validatedEndpoint{}, errConfiguration
		}
	}
	return validatedEndpoint{baseURL: parsed.String(), hostname: host, port: parsed.Port()}, nil
}

func allLoopback(addresses []string) bool {
	if len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func loopbackDialerWithResolver(endpoint validatedEndpoint, resolver hostResolver) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return loopbackDialerWithResolverAndDialer(endpoint, resolver, dialer.DialContext)
}

func loopbackDialerWithResolverAndDialer(endpoint validatedEndpoint, resolver hostResolver, dial dialContextFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		host = strings.ToLower(strings.Trim(host, "[]"))
		if err != nil || host != endpoint.hostname || port != endpoint.port || resolver == nil {
			return nil, errConfiguration
		}
		addresses, err := resolver.LookupHost(ctx, host)
		if err != nil || !allLoopback(addresses) {
			return nil, errConfiguration
		}
		var lastErr error
		for _, candidate := range addresses {
			connection, dialErr := dial(ctx, network, net.JoinHostPort(candidate, port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			return nil, errConfiguration
		}
		return nil, lastErr
	}
}

func (h *httpBackend) ListIndexes(ctx context.Context, prefix string) ([]IndexState, error) {
	if prefix != proofPrefix+h.spec.Marker {
		return nil, errOwnership
	}
	query := url.Values{"format": {"json"}, "h": {"index"}, "expand_wildcards": {"all"}}
	raw, err := h.do(ctx, http.MethodGet, "/_cat/indices/"+url.PathEscape(prefix)+"*", query, nil, true, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var response []catIndex
	if decodeExactJSON(raw, &response) != nil {
		return nil, errProvider
	}
	names := make(map[string]struct{}, len(response))
	for _, entry := range response {
		if !strings.HasPrefix(entry.Index, prefix) || entry.Index == "" {
			return nil, errOwnership
		}
		if _, duplicate := names[entry.Index]; duplicate {
			return nil, errProvider
		}
		names[entry.Index] = struct{}{}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	states := make([]IndexState, 0, len(ordered))
	for _, name := range ordered {
		states = append(states, IndexState{Name: name})
	}
	return states, nil
}

func (h *httpBackend) CreateIndex(ctx context.Context, spec IndexSpec) (IndexState, error) {
	if !validIndexState(spec, h.spec) {
		return IndexState{}, errOwnership
	}
	properties := make(map[string]mappingField, len(spec.Fields))
	for name, fieldType := range spec.Fields {
		if strings.HasPrefix(fieldType, "date:") {
			properties[name] = mappingField{Type: "date", Format: strings.TrimPrefix(fieldType, "date:")}
		} else {
			properties[name] = mappingField{Type: fieldType}
		}
	}
	body := struct {
		Settings struct {
			Shards   int `json:"number_of_shards"`
			Replicas int `json:"number_of_replicas"`
		} `json:"settings"`
		Mappings mappingDefinition `json:"mappings"`
	}{Mappings: mappingDefinition{Dynamic: spec.Dynamic, Metadata: mappingMetadata{Proof: "m0-08", Marker: spec.Marker, Role: spec.Role}, Properties: properties}}
	body.Settings.Shards, body.Settings.Replicas = spec.Shards, spec.Replicas
	raw, err := h.do(ctx, http.MethodPut, "/"+url.PathEscape(spec.Name), nil, body, false, http.StatusOK)
	if err != nil {
		return IndexState{}, err
	}
	var response createIndexResponse
	if decodeExactJSON(raw, &response) != nil || !response.Acknowledged || !response.ShardsAcknowledged || response.Index != spec.Name {
		return IndexState{}, errProvider
	}
	return copyIndexSpec(spec), nil
}

func (h *httpBackend) InspectIndex(ctx context.Context, name string) (IndexState, error) {
	if name != h.spec.Name {
		return IndexState{}, errOwnership
	}
	mappingRaw, err := h.do(ctx, http.MethodGet, "/"+url.PathEscape(name)+"/_mapping", nil, nil, true, http.StatusOK)
	if err != nil {
		return IndexState{}, err
	}
	var mappings map[string]mappingIndex
	if decodeExactJSON(mappingRaw, &mappings) != nil || len(mappings) != 1 {
		return IndexState{}, errProvider
	}
	mapping, exists := mappings[name]
	if !exists {
		return IndexState{}, errOwnership
	}
	settingsQuery := url.Values{"flat_settings": {"true"}, "include_defaults": {"false"}}
	settingsRaw, err := h.do(ctx, http.MethodGet, "/"+url.PathEscape(name)+"/_settings/index.number_of_shards,index.number_of_replicas", settingsQuery, nil, true, http.StatusOK)
	if err != nil {
		return IndexState{}, err
	}
	var settings map[string]settingsIndex
	if decodeExactJSON(settingsRaw, &settings) != nil || len(settings) != 1 {
		return IndexState{}, errProvider
	}
	indexSettings, exists := settings[name]
	if !exists || len(indexSettings.Settings) != 2 {
		return IndexState{}, errOwnership
	}
	shards, shardErr := strconv.Atoi(indexSettings.Settings["index.number_of_shards"])
	replicas, replicaErr := strconv.Atoi(indexSettings.Settings["index.number_of_replicas"])
	if shardErr != nil || replicaErr != nil {
		return IndexState{}, errOwnership
	}
	fields := make(map[string]string, len(mapping.Mappings.Properties))
	for field, definition := range mapping.Mappings.Properties {
		if definition.Type == "date" {
			if definition.Format == "" {
				return IndexState{}, errOwnership
			}
			fields[field] = "date:" + definition.Format
		} else {
			if definition.Type == "" || definition.Format != "" {
				return IndexState{}, errOwnership
			}
			fields[field] = definition.Type
		}
	}
	return IndexState{
		Name: name, Marker: mapping.Mappings.Metadata.Marker, Role: mapping.Mappings.Metadata.Role,
		Dynamic: mapping.Mappings.Dynamic, Shards: shards, Replicas: replicas, Fields: fields,
	}, nil
}

func (h *httpBackend) IndexSessionEvent(ctx context.Context, scope OrganizationScope, event NormalizedSessionEvent) error {
	if !validScopeAndEvent(scope, event) {
		return errScope
	}
	if !validEvent(event) {
		return errContent
	}
	query := url.Values{"refresh": {"wait_for"}, "timeout": {"5s"}}
	path := "/" + url.PathEscape(h.spec.Name) + "/_doc/" + url.PathEscape(event.EventID)
	raw, err := h.do(ctx, http.MethodPut, path, query, event, false, http.StatusOK, http.StatusCreated)
	if err != nil {
		return err
	}
	var response indexDocumentResponse
	if decodeExactJSON(raw, &response) != nil || response.Index != h.spec.Name || response.ID != event.EventID ||
		response.Version != 1 || response.Result != "created" || response.Shards.Total != 1 ||
		response.Shards.Successful != 1 || response.Shards.Failed != 0 || response.PrimaryTerm < 1 || response.Sequence < 0 {
		return errProvider
	}
	return nil
}

func (h *httpBackend) QuerySession(ctx context.Context, scope OrganizationScope, filter SessionFilter) ([]NormalizedSessionEvent, error) {
	if !scopeValuePattern.MatchString(scope.OrganizationID()) || !scopeValuePattern.MatchString(filter.SessionID) || !scopeValuePattern.MatchString(filter.EnvironmentID) {
		return nil, errScope
	}
	body := scopedQuery(scope.OrganizationID(), filter)
	return h.search(ctx, body, scope.OrganizationID())
}

func (h *httpBackend) ListDocuments(ctx context.Context, name string, limit int) ([]NormalizedSessionEvent, error) {
	if name != h.spec.Name {
		return nil, errOwnership
	}
	if limit != 2 {
		return nil, errConfiguration
	}
	body := map[string]any{"size": limit, "track_total_hits": true, "query": map[string]any{"match_all": map[string]any{}}}
	return h.search(ctx, body, "")
}

func (h *httpBackend) search(ctx context.Context, body map[string]any, requiredOrganization string) ([]NormalizedSessionEvent, error) {
	raw, err := h.do(ctx, http.MethodPost, "/"+url.PathEscape(h.spec.Name)+"/_search", nil, body, true, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var response searchResponse
	if decodeExactJSON(raw, &response) != nil || response.TimedOut || response.Took < 0 || response.Shards.Total != 1 ||
		response.Shards.Successful != 1 || response.Shards.Skipped != 0 || response.Shards.Failed != 0 ||
		response.Hits.Total.Relation != "eq" || response.Hits.Total.Value != len(response.Hits.Hits) || len(response.Hits.Hits) > 2 {
		return nil, errProvider
	}
	result := make([]NormalizedSessionEvent, 0, len(response.Hits.Hits))
	ids := make(map[string]struct{}, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		if hit.Index != h.spec.Name || hit.ID == "" || hit.ID != hit.Source.EventID || !validOptionalScore(hit.Score) || !validEvent(hit.Source) {
			return nil, errContent
		}
		if requiredOrganization != "" && hit.Source.OrganizationID != requiredOrganization {
			return nil, errScope
		}
		if _, duplicate := ids[hit.ID]; duplicate {
			return nil, errContent
		}
		ids[hit.ID] = struct{}{}
		result = append(result, hit.Source)
	}
	return result, nil
}

func validOptionalScore(score *float64) bool {
	return score == nil || (*score >= 0 && *score < 1e12)
}

func (h *httpBackend) DeleteIndex(ctx context.Context, name string) error {
	if name != h.spec.Name {
		return errOwnership
	}
	raw, err := h.do(ctx, http.MethodDelete, "/"+url.PathEscape(name), nil, nil, false, http.StatusOK)
	if err != nil {
		return err
	}
	var response deleteIndexResponse
	if decodeExactJSON(raw, &response) != nil || !response.Acknowledged {
		return errProvider
	}
	return nil
}

func scopedQuery(organizationID string, filter SessionFilter) map[string]any {
	filters := []any{
		map[string]any{"term": map[string]any{"organization_id": organizationID}},
		map[string]any{"term": map[string]any{"session_id": filter.SessionID}},
		map[string]any{"term": map[string]any{"environment_id": filter.EnvironmentID}},
	}
	return map[string]any{"size": 2, "track_total_hits": true, "query": map[string]any{"bool": map[string]any{"filter": filters}}}
}

func validScopeAndEvent(scope OrganizationScope, event NormalizedSessionEvent) bool {
	return scopeValuePattern.MatchString(scope.OrganizationID()) && scope.OrganizationID() == event.OrganizationID
}

func validEvent(event NormalizedSessionEvent) bool {
	values := []string{event.EventID, event.OrganizationID, event.WorkspaceID, event.EnvironmentID, event.SessionID, event.AgentID, event.SourceEventID}
	for _, value := range values {
		if !scopeValuePattern.MatchString(value) {
			return false
		}
	}
	if event.Source != "runtime-gateway" || event.EventClass != "tool" || event.Action != "invoke" || event.Decision != "allowed" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, event.EventTime)
	return err == nil && parsed.Format(time.RFC3339) == event.EventTime
}

func (h *httpBackend) do(ctx context.Context, method, path string, query url.Values, body any, safeRead bool, expectedStatus ...int) ([]byte, error) {
	if ctx == nil || !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return nil, errConfiguration
	}
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > maximumRequestBytes {
			return nil, errConfiguration
		}
	}
	attempts := 1
	if safeRead {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(readRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, errProvider
			case <-timer.C:
			}
		}
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		requestURL := h.endpoint.baseURL + path
		if len(query) != 0 {
			requestURL += "?" + query.Encode()
		}
		request, err := http.NewRequestWithContext(requestCtx, method, requestURL, bytes.NewReader(encoded))
		if err != nil {
			cancel()
			return nil, errConfiguration
		}
		request.Header.Set("accept", "application/json")
		if body != nil {
			request.Header.Set("content-type", "application/json")
		}
		response, err := h.client.Do(request)
		if err != nil {
			cancel()
			if safeRead && attempt+1 < attempts && ctx.Err() == nil {
				continue
			}
			return nil, errProvider
		}
		limited := io.LimitReader(response.Body, maximumResponseBytes+1)
		responseBody, readErr := io.ReadAll(limited)
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || len(responseBody) > maximumResponseBytes {
			return nil, errProvider
		}
		if !statusExpected(response.StatusCode, expectedStatus) {
			if safeRead && attempt+1 < attempts && transientStatus(response.StatusCode) && ctx.Err() == nil {
				continue
			}
			return nil, errProvider
		}
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("content-type"), ";")[0]))
		if contentType != "application/json" {
			return nil, errProvider
		}
		return responseBody, nil
	}
	return nil, errProvider
}

func statusExpected(status int, expected []int) bool {
	for _, candidate := range expected {
		if status == candidate {
			return true
		}
	}
	return false
}

func transientStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func decodeExactJSON(raw []byte, target any) error {
	if len(raw) == 0 || target == nil {
		return errors.New("invalid JSON")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	if err := validateExactJSONSchema(json.RawMessage(raw), reflect.TypeOf(target)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validateExactJSONSchema(raw json.RawMessage, targetType reflect.Type) error {
	if targetType == nil {
		return errors.New("missing JSON schema")
	}
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	return validateExactJSONValue(raw, targetType)
}

func validateExactJSONValue(raw json.RawMessage, targetType reflect.Type) error {
	if targetType.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return validateExactJSONValue(raw, targetType.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null required JSON value")
	}
	switch targetType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return errors.New("invalid JSON object")
		}
		fields := make(map[string]reflect.Type)
		for index := 0; index < targetType.NumField(); index++ {
			field := targetType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
			if !strings.Contains(field.Tag.Get("json"), "omitempty") {
				if _, exists := object[name]; !exists {
					return errors.New("missing required JSON schema key")
				}
			}
		}
		for key, value := range object {
			fieldType, exists := fields[key]
			if !exists {
				return errors.New("non-exact JSON schema key")
			}
			if err := validateExactJSONValue(value, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil || values == nil {
			return errors.New("invalid JSON array")
		}
		for _, value := range values {
			if err := validateExactJSONValue(value, targetType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		if targetType.Key().Kind() != reflect.String {
			return errors.New("invalid JSON map")
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil || values == nil {
			return errors.New("invalid JSON map")
		}
		for _, value := range values {
			if err := validateExactJSONValue(value, targetType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
