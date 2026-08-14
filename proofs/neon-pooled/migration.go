package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	migrationSuccessSummary = "Neon migration proof passed: up=true down=true baseline_restored=true branch_deleted=true."
	neonAPIResponseLimit    = 64 * 1024
	neonOfficialAPIBaseURL  = "https://console.neon.tech/api/v2"
	migrationSchemaPrefix   = "zasp_m005_"
	migrationBranchPrefix   = "zasp-m0-05-"
	migrationAnnotationKey  = "zasp-proof-marker"
	neonBranchObjectType    = "console/branch"
)

var (
	//go:embed migrations/0001_proof.up.sql
	upMigrationTemplate string
	//go:embed migrations/0001_proof.down.sql
	downMigrationTemplate string

	apiResourcePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,59}$`)
	branchIDPattern         = regexp.MustCompile(`^br-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	endpointIDPattern       = regexp.MustCompile(`^ep-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	markerPattern           = regexp.MustCompile(`^[a-f0-9]{16}$`)
	schemaIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	uuidPattern             = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

	errMigrationConfiguration = errors.New("migration configuration rejected")
	errMigrationAPI           = errors.New("Neon API request failed")
	errMigrationOwnership     = errors.New("migration resource ownership rejected")
	errMigrationDatabase      = errors.New("migration database operation failed")
	errMigrationBaseline      = errors.New("migration baseline was not restored")
	errMigrationCleanup       = errors.New("migration branch cleanup failed")
)

type migrationRunConfig struct {
	apiKey         string
	cleanupTimeout time.Duration
	databaseURL    string
	marker         string
	projectID      string
	pollInterval   time.Duration
}

type migrationDependencies struct {
	api          *neonAPIClient
	openDatabase migrationDatabaseOpener
}

type migrationAssets struct {
	schema string
	up     string
	down   string
}

type migrationDatabase interface {
	Fingerprint(context.Context, string) (string, error)
	Up(context.Context, migrationAssets) error
	VerifyShape(context.Context, string) error
	Down(context.Context, migrationAssets) error
	Close(context.Context) error
}

type migrationDatabaseOpener func(context.Context, validatedConnection) (migrationDatabase, error)

type neonAPIClient struct {
	apiKey     string
	baseURL    *url.URL
	httpClient *http.Client
}

type neonEndpoint struct {
	Host      string `json:"host"`
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	BranchID  string `json:"branch_id"`
	Type      string `json:"type"`
	State     string `json:"current_state"`
	Disabled  bool   `json:"disabled"`
}

type neonBranch struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	ParentID  string `json:"parent_id"`
	Name      string `json:"name"`
	State     string `json:"current_state"`
	Default   bool   `json:"default"`
	Protected bool   `json:"protected"`
}

type neonOperation struct {
	ID            string `json:"id"`
	ProjectID     string `json:"project_id"`
	BranchID      string `json:"branch_id"`
	EndpointID    string `json:"endpoint_id"`
	Status        string `json:"status"`
	FailuresCount int    `json:"failures_count"`
}

type ownedBranch struct {
	projectID            string
	parentID             string
	branchID             string
	branchName           string
	marker               string
	endpointID           string
	endpointHost         string
	providerMarkerProven bool
}

type endpointsResponse struct {
	Endpoints []neonEndpoint `json:"endpoints"`
}

type branchesResponse struct {
	Branches    []neonBranch              `json:"branches"`
	Annotations map[string]neonAnnotation `json:"annotations"`
	Pagination  struct {
		Next string `json:"next"`
	} `json:"pagination"`
}

type neonAnnotation struct {
	Object struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"object"`
	Value map[string]string `json:"value"`
}

type branchOperationsResponse struct {
	Branch     neonBranch      `json:"branch"`
	Endpoints  []neonEndpoint  `json:"endpoints"`
	Operations []neonOperation `json:"operations"`
}

type operationResponse struct {
	Operation neonOperation `json:"operation"`
}

func newNeonAPIClient(rawBaseURL, apiKey string, client *http.Client) (*neonAPIClient, error) {
	if apiKey == "" || client == nil {
		return nil, errMigrationConfiguration
	}
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.User != nil {
		return nil, errMigrationConfiguration
	}
	host := strings.ToLower(baseURL.Hostname())
	isOfficial := baseURL.Scheme == "https" && host == "console.neon.tech" && baseURL.Path == "/api/v2"
	isLoopback := baseURL.Scheme == "http" && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() && baseURL.Path == ""
	if !isOfficial && !isLoopback {
		return nil, errMigrationConfiguration
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &neonAPIClient{apiKey: apiKey, baseURL: baseURL, httpClient: &copyClient}, nil
}

func executeMigrationProof(ctx context.Context, config migrationRunConfig, dependencies migrationDependencies) (summary string, resultErr error) {
	if dependencies.api == nil || dependencies.openDatabase == nil ||
		config.apiKey == "" || config.apiKey != dependencies.api.apiKey ||
		!apiResourcePattern.MatchString(config.projectID) || !markerPattern.MatchString(config.marker) {
		return "", errMigrationConfiguration
	}
	parentHost, err := directHostFromURL(config.databaseURL)
	if err != nil {
		return "", errMigrationConfiguration
	}
	parent, err := dependencies.api.findParentEndpoint(ctx, config.projectID, parentHost)
	if err != nil {
		return "", err
	}
	branchName := migrationBranchPrefix + config.marker
	if err := dependencies.api.requireUniqueBranchName(ctx, config.projectID, branchName); err != nil {
		return "", err
	}
	target, operations, createAttempted, createErr := dependencies.api.createBranch(ctx, config.projectID, parent.BranchID, branchName, config.marker)
	if !createAttempted {
		return "", createErr
	}
	confirmationCtx, confirmationCancel := context.WithTimeout(context.WithoutCancel(ctx), migrationCleanupTimeout(config))
	confirmedTarget, confirmationErr := dependencies.api.confirmOwnedBranchUntil(
		confirmationCtx, target, config.projectID, parent.BranchID, branchName, config.marker, config.pollInterval,
	)
	confirmationCancel()
	if confirmationErr != nil && !confirmedTarget.validForCleanup(config.projectID, parent.BranchID, config.marker) {
		return "", errMigrationCleanup
	}
	target = confirmedTarget

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationCleanupTimeout(config))
		defer cancel()
		if err := dependencies.api.deleteOwnedBranch(cleanupCtx, target, config.pollInterval); err != nil {
			summary = ""
			resultErr = errMigrationCleanup
		}
	}()
	if confirmationErr != nil {
		if createErr != nil {
			return "", createErr
		}
		return "", errMigrationAPI
	}
	if createErr != nil {
		return "", createErr
	}
	if !target.validFor(config.projectID, parent.BranchID, config.marker) {
		return "", errMigrationOwnership
	}

	if err := dependencies.api.waitOperations(ctx, target, operations, config.pollInterval); err != nil {
		return "", err
	}
	if err := dependencies.api.waitResourcesReady(ctx, target, config.pollInterval); err != nil {
		return "", err
	}
	connection, err := validatedDirectPGXConnection(config.databaseURL, target.endpointHost)
	if err != nil {
		return "", errMigrationConfiguration
	}
	database, err := dependencies.openDatabase(ctx, connection)
	if err != nil {
		return "", errMigrationDatabase
	}
	assets, err := renderMigrationAssets(migrationSchemaPrefix + config.marker)
	if err != nil {
		_ = database.Close(ctx)
		return "", errMigrationConfiguration
	}
	runErr := runMigrationRoundTrip(ctx, database, assets)
	closeErr := database.Close(ctx)
	if runErr != nil {
		return "", runErr
	}
	if closeErr != nil {
		return "", errMigrationDatabase
	}
	return migrationSuccessSummary, nil
}

func migrationCleanupTimeout(config migrationRunConfig) time.Duration {
	if config.cleanupTimeout > 0 {
		return config.cleanupTimeout
	}
	return 45 * time.Second
}

func runMigrationRoundTrip(ctx context.Context, database migrationDatabase, assets migrationAssets) error {
	baseline, err := database.Fingerprint(ctx, assets.schema)
	if err != nil {
		return errMigrationDatabase
	}
	if err := database.Up(ctx, assets); err != nil {
		return errMigrationDatabase
	}
	if err := database.VerifyShape(ctx, assets.schema); err != nil {
		return errMigrationDatabase
	}
	if err := database.Down(ctx, assets); err != nil {
		return errMigrationDatabase
	}
	after, err := database.Fingerprint(ctx, assets.schema)
	if err != nil {
		return errMigrationDatabase
	}
	if after != baseline {
		return errMigrationBaseline
	}
	return nil
}

func directHostFromURL(raw string) (string, error) {
	if _, err := pooledNeonURL(raw); err != nil {
		return "", errMigrationConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errMigrationConfiguration
	}
	labels := strings.Split(strings.ToLower(parsed.Hostname()), ".")
	if strings.HasSuffix(labels[0], "-pooler") {
		labels[0] = strings.TrimSuffix(labels[0], "-pooler")
	}
	return strings.Join(labels, "."), nil
}

func renderMigrationAssets(schema string) (migrationAssets, error) {
	if !schemaIdentifierPattern.MatchString(schema) {
		return migrationAssets{}, errMigrationConfiguration
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if strings.Count(upMigrationTemplate, "%s") != 2 || strings.Count(downMigrationTemplate, "%s") != 1 {
		return migrationAssets{}, errMigrationConfiguration
	}
	return migrationAssets{
		schema: schema,
		up:     strings.TrimSpace(fmt.Sprintf(upMigrationTemplate, quoted, quoted)),
		down:   strings.TrimSpace(fmt.Sprintf(downMigrationTemplate, quoted)),
	}, nil
}

func (client *neonAPIClient) listEndpoints(ctx context.Context, projectID string) ([]neonEndpoint, error) {
	if !apiResourcePattern.MatchString(projectID) {
		return nil, errMigrationConfiguration
	}
	var response endpointsResponse
	if err := client.doJSON(ctx, http.MethodGet, "/projects/"+projectID+"/endpoints", nil, http.StatusOK, &response); err != nil {
		return nil, err
	}
	return response.Endpoints, nil
}

func (client *neonAPIClient) findParentEndpoint(ctx context.Context, projectID, directHost string) (neonEndpoint, error) {
	endpoints, err := client.listEndpoints(ctx, projectID)
	if err != nil {
		return neonEndpoint{}, err
	}
	matches := make([]neonEndpoint, 0, 1)
	for _, endpoint := range endpoints {
		if strings.ToLower(endpoint.Host) == directHost {
			matches = append(matches, endpoint)
		}
	}
	if len(matches) != 1 || !validEndpoint(matches[0], projectID, "") || matches[0].Type != "read_write" || matches[0].Disabled {
		return neonEndpoint{}, errMigrationAPI
	}
	return matches[0], nil
}

func (client *neonAPIClient) requireUniqueBranchName(ctx context.Context, projectID, branchName string) error {
	branches, err := client.listBranches(ctx, projectID, branchName)
	if err != nil {
		return err
	}
	for _, branch := range branches {
		if branch.Name == branchName {
			return errMigrationOwnership
		}
	}
	return nil
}

func (client *neonAPIClient) confirmOwnedBranch(ctx context.Context, expected ownedBranch, projectID, parentID, branchName, marker string) (ownedBranch, error) {
	response, err := client.listBranchesResponse(ctx, projectID, branchName)
	if err != nil {
		return ownedBranch{}, err
	}
	matches := make([]neonBranch, 0, 1)
	for _, branch := range response.Branches {
		annotation, annotated := response.Annotations[branch.ID]
		if branch.ProjectID == projectID && branch.ParentID == parentID && branch.Name == branchName &&
			validCreatedBranchState(branch.State) && !branch.Default && !branch.Protected && validBranchID(branch.ID) &&
			annotated && annotation.Object.Type == neonBranchObjectType && annotation.Object.ID == branch.ID &&
			annotation.Value[migrationAnnotationKey] == marker {
			matches = append(matches, branch)
		}
	}
	if len(matches) != 1 {
		return ownedBranch{}, errMigrationOwnership
	}
	branchTarget := ownedBranch{
		projectID: projectID, parentID: parentID, branchID: matches[0].ID,
		branchName: branchName, marker: marker, providerMarkerProven: true,
	}
	endpoints, err := client.listEndpoints(ctx, projectID)
	if err != nil {
		return branchTarget, err
	}
	endpointMatches := make([]neonEndpoint, 0, 1)
	branchEndpointCount := 0
	for _, endpoint := range endpoints {
		if endpoint.BranchID == matches[0].ID {
			branchEndpointCount++
		}
		if endpoint.BranchID == matches[0].ID && endpoint.Type == "read_write" && !endpoint.Disabled &&
			validCreatedEndpointState(endpoint.State) && validEndpoint(endpoint, projectID, matches[0].ID) {
			endpointMatches = append(endpointMatches, endpoint)
		}
	}
	if len(endpointMatches) != 1 {
		if branchEndpointCount == 0 {
			return branchTarget, errMigrationAPI
		}
		return branchTarget, errMigrationOwnership
	}
	target := branchTarget
	target.endpointID = endpointMatches[0].ID
	target.endpointHost = endpointMatches[0].Host
	if !target.validFor(projectID, parentID, marker) {
		return branchTarget, errMigrationOwnership
	}
	if (expected.branchID != "" && target.branchID != expected.branchID) ||
		(expected.endpointID != "" && target.endpointID != expected.endpointID) ||
		(expected.endpointHost != "" && target.endpointHost != expected.endpointHost) {
		return branchTarget, errMigrationOwnership
	}
	return target, nil
}

func (client *neonAPIClient) confirmOwnedBranchUntil(ctx context.Context, expected ownedBranch, projectID, parentID, branchName, marker string, pollInterval time.Duration) (ownedBranch, error) {
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	var branchOnlyTarget ownedBranch
	for {
		target, err := client.confirmOwnedBranch(ctx, expected, projectID, parentID, branchName, marker)
		if err == nil {
			return target, nil
		}
		if target.validForCleanup(projectID, parentID, marker) {
			branchOnlyTarget = target
			if errors.Is(err, errMigrationOwnership) {
				return branchOnlyTarget, errMigrationOwnership
			}
		}
		select {
		case <-ctx.Done():
			return branchOnlyTarget, errMigrationAPI
		case <-time.After(pollInterval):
		}
	}
}

func (client *neonAPIClient) listBranches(ctx context.Context, projectID, search string) ([]neonBranch, error) {
	response, err := client.listBranchesResponse(ctx, projectID, search)
	if err != nil {
		return nil, err
	}
	return response.Branches, nil
}

func (client *neonAPIClient) listBranchesResponse(ctx context.Context, projectID, search string) (branchesResponse, error) {
	if !apiResourcePattern.MatchString(projectID) || !validBranchName(search) {
		return branchesResponse{}, errMigrationConfiguration
	}
	query := url.Values{"limit": {"10000"}, "search": {search}}
	var response branchesResponse
	if err := client.doJSON(ctx, http.MethodGet, "/projects/"+projectID+"/branches?"+query.Encode(), nil, http.StatusOK, &response); err != nil {
		return branchesResponse{}, err
	}
	if response.Pagination.Next != "" {
		return branchesResponse{}, errMigrationAPI
	}
	return response, nil
}

func (client *neonAPIClient) createBranch(ctx context.Context, projectID, parentID, branchName, marker string) (ownedBranch, []neonOperation, bool, error) {
	if !apiResourcePattern.MatchString(projectID) || !validBranchID(parentID) || !validBranchName(branchName) || !markerPattern.MatchString(marker) {
		return ownedBranch{}, nil, false, errMigrationConfiguration
	}
	body := struct {
		Branch struct {
			ParentID  string `json:"parent_id"`
			Name      string `json:"name"`
			Protected bool   `json:"protected"`
		} `json:"branch"`
		Endpoints []struct {
			Type string `json:"type"`
		} `json:"endpoints"`
		Annotation map[string]string `json:"annotation_value"`
	}{}
	body.Branch.ParentID = parentID
	body.Branch.Name = branchName
	body.Branch.Protected = false
	body.Endpoints = append(body.Endpoints, struct {
		Type string `json:"type"`
	}{Type: "read_write"})
	body.Annotation = map[string]string{migrationAnnotationKey: marker}

	var response branchOperationsResponse
	target := ownedBranch{
		projectID: projectID, parentID: parentID, branchName: branchName, marker: marker,
	}
	if err := client.doJSON(ctx, http.MethodPost, "/projects/"+projectID+"/branches", body, http.StatusCreated, &response); err != nil {
		return target, nil, true, err
	}
	if response.Branch.ProjectID != projectID || response.Branch.ParentID != parentID ||
		response.Branch.Name != branchName || response.Branch.Default || response.Branch.Protected ||
		!validCreatedBranchState(response.Branch.State) || !validBranchID(response.Branch.ID) || response.Branch.ID == parentID {
		return target, nil, true, errMigrationAPI
	}
	candidate := target
	candidate.branchID = response.Branch.ID
	if len(response.Endpoints) != 1 {
		return target, nil, true, errMigrationAPI
	}
	endpoint := response.Endpoints[0]
	candidate.endpointID = endpoint.ID
	candidate.endpointHost = strings.ToLower(endpoint.Host)
	if !validEndpoint(endpoint, projectID, response.Branch.ID) ||
		endpoint.Type != "read_write" || endpoint.Disabled || !validCreatedEndpointState(endpoint.State) ||
		!validUnprovenTarget(candidate, projectID, parentID, marker) {
		return target, nil, true, errMigrationAPI
	}
	if len(response.Operations) == 0 || !validOperations(response.Operations, candidate) {
		return target, nil, true, errMigrationAPI
	}
	return candidate, response.Operations, true, nil
}

func (client *neonAPIClient) waitOperations(ctx context.Context, target ownedBranch, operations []neonOperation, pollInterval time.Duration) error {
	if !target.validFor(target.projectID, target.parentID, target.marker) || !validOperations(operations, target) {
		return errMigrationOwnership
	}
	return client.waitOperationSet(ctx, target, operations, pollInterval)
}

func (client *neonAPIClient) waitDeleteOperations(ctx context.Context, target ownedBranch, operations []neonOperation, pollInterval time.Duration) error {
	if !target.validForCleanup(target.projectID, target.parentID, target.marker) || !validOperations(operations, target) {
		return errMigrationOwnership
	}
	return client.waitOperationSet(ctx, target, operations, pollInterval)
}

func (client *neonAPIClient) waitOperationSet(ctx context.Context, target ownedBranch, operations []neonOperation, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	for _, initial := range operations {
		operation := initial
		for operation.Status != "finished" {
			if terminalOperationStatus(operation.Status) {
				return errMigrationAPI
			}
			var response operationResponse
			path := "/projects/" + target.projectID + "/operations/" + operation.ID
			if err := client.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &response); err != nil {
				return err
			}
			if !validOperation(response.Operation, target) || response.Operation.ID != operation.ID {
				return errMigrationAPI
			}
			operation = response.Operation
			if operation.Status != "finished" {
				select {
				case <-ctx.Done():
					return errMigrationAPI
				case <-time.After(pollInterval):
				}
			}
		}
	}
	return nil
}

func (client *neonAPIClient) waitResourcesReady(ctx context.Context, target ownedBranch, pollInterval time.Duration) error {
	if !target.validFor(target.projectID, target.parentID, target.marker) {
		return errMigrationOwnership
	}
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	for {
		response, err := client.listBranchesResponse(ctx, target.projectID, target.branchName)
		if err != nil {
			return err
		}
		branchMatches := make([]neonBranch, 0, 1)
		for _, branch := range response.Branches {
			annotation, annotated := response.Annotations[branch.ID]
			if branch.ID == target.branchID && branch.ProjectID == target.projectID && branch.ParentID == target.parentID &&
				branch.Name == target.branchName && !branch.Default && !branch.Protected && annotated &&
				annotation.Object.Type == neonBranchObjectType && annotation.Object.ID == branch.ID &&
				annotation.Value[migrationAnnotationKey] == target.marker {
				branchMatches = append(branchMatches, branch)
			}
		}
		endpoints, err := client.listEndpoints(ctx, target.projectID)
		if err != nil {
			return err
		}
		endpointMatches := make([]neonEndpoint, 0, 1)
		for _, endpoint := range endpoints {
			if endpoint.ID == target.endpointID && endpoint.Host == target.endpointHost &&
				endpoint.Type == "read_write" && !endpoint.Disabled && validEndpoint(endpoint, target.projectID, target.branchID) {
				endpointMatches = append(endpointMatches, endpoint)
			}
		}
		if len(branchMatches) != 1 || len(endpointMatches) != 1 {
			return errMigrationAPI
		}
		if branchMatches[0].State == "ready" && (endpointMatches[0].State == "active" || endpointMatches[0].State == "idle") {
			return nil
		}
		if !validCreatedBranchState(branchMatches[0].State) || !validCreatedEndpointState(endpointMatches[0].State) {
			return errMigrationAPI
		}
		select {
		case <-ctx.Done():
			return errMigrationAPI
		case <-time.After(pollInterval):
		}
	}
}

func (client *neonAPIClient) deleteOwnedBranch(ctx context.Context, target ownedBranch, pollInterval time.Duration) error {
	if !target.validForCleanup(target.projectID, target.parentID, target.marker) {
		return errMigrationOwnership
	}
	response, status, err := client.deleteBranch(ctx, target)
	if err != nil {
		return errMigrationCleanup
	}
	if status == http.StatusOK {
		if response.Branch.ID != target.branchID || response.Branch.ProjectID != target.projectID ||
			response.Branch.ParentID != target.parentID || response.Branch.Name != target.branchName ||
			response.Branch.Default || response.Branch.Protected || len(response.Operations) == 0 ||
			!validOperations(response.Operations, target) {
			return errMigrationCleanup
		}
		if err := client.waitDeleteOperations(ctx, target, response.Operations, pollInterval); err != nil {
			return errMigrationCleanup
		}
	}
	return client.requireOwnedBranchAbsent(ctx, target)
}

func (client *neonAPIClient) deleteBranch(ctx context.Context, target ownedBranch) (branchOperationsResponse, int, error) {
	if ctx == nil {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	requestURL := *client.baseURL
	requestURL.Path = strings.TrimSuffix(client.baseURL.Path, "/") + "/projects/" + target.projectID + "/branches/" + target.branchID
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, requestURL.String(), nil)
	if err != nil {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.apiKey)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, neonAPIResponseLimit+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > neonAPIResponseLimit {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	if response.StatusCode == http.StatusNoContent {
		if len(encoded) != 0 {
			return branchOperationsResponse{}, 0, errMigrationAPI
		}
		return branchOperationsResponse{}, http.StatusNoContent, nil
	}
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") || len(encoded) == 0 {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	var decoded branchOperationsResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return branchOperationsResponse{}, 0, errMigrationAPI
	}
	return decoded, http.StatusOK, nil
}

func (client *neonAPIClient) requireOwnedBranchAbsent(ctx context.Context, target ownedBranch) error {
	branches, err := client.listBranches(ctx, target.projectID, target.branchName)
	if err != nil {
		return errMigrationCleanup
	}
	for _, branch := range branches {
		if branch.ID == target.branchID || branch.Name == target.branchName {
			return errMigrationCleanup
		}
	}
	return nil
}

func (client *neonAPIClient) doJSON(ctx context.Context, method, path string, requestBody any, expectedStatus int, responseBody any) error {
	if ctx == nil || !strings.HasPrefix(path, "/projects/") {
		return errMigrationAPI
	}
	requestURL := *client.baseURL
	requestURL.Path = strings.TrimSuffix(client.baseURL.Path, "/") + strings.SplitN(path, "?", 2)[0]
	if parts := strings.SplitN(path, "?", 2); len(parts) == 2 {
		query, err := url.ParseQuery(parts[1])
		if err != nil {
			return errMigrationAPI
		}
		requestURL.RawQuery = query.Encode()
	}
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil || len(encoded) > neonAPIResponseLimit {
			return errMigrationAPI
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return errMigrationAPI
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.apiKey)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return errMigrationAPI
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, neonAPIResponseLimit))
		return errMigrationAPI
	}
	limited := io.LimitReader(response.Body, neonAPIResponseLimit+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > neonAPIResponseLimit || len(encoded) == 0 {
		return errMigrationAPI
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(responseBody); err != nil {
		return errMigrationAPI
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errMigrationAPI
	}
	return nil
}

func (target ownedBranch) validFor(projectID, parentID, marker string) bool {
	return target.validForCleanup(projectID, parentID, marker) &&
		validEndpointID(target.endpointID) && validDirectNeonHost(target.endpointHost) &&
		strings.HasPrefix(target.endpointHost, target.endpointID+".")
}

func (target ownedBranch) validForCleanup(projectID, parentID, marker string) bool {
	return target.providerMarkerProven && validUnprovenTarget(target, projectID, parentID, marker)
}

func validUnprovenTarget(target ownedBranch, projectID, parentID, marker string) bool {
	return target.projectID == projectID && target.parentID == parentID && target.marker == marker &&
		apiResourcePattern.MatchString(projectID) && validBranchID(parentID) && validBranchID(target.branchID) &&
		target.branchID != parentID && target.branchName == migrationBranchPrefix+marker && validBranchName(target.branchName)
}

func validEndpoint(endpoint neonEndpoint, projectID, branchID string) bool {
	if endpoint.ProjectID != projectID || !validEndpointID(endpoint.ID) || !validBranchID(endpoint.BranchID) || !validDirectNeonHost(strings.ToLower(endpoint.Host)) {
		return false
	}
	if branchID != "" && endpoint.BranchID != branchID {
		return false
	}
	return strings.ToLower(endpoint.Host) == endpoint.Host && strings.HasPrefix(endpoint.Host, endpoint.ID+".")
}

func validDirectNeonHost(host string) bool {
	if host == "" || strings.Contains(host, ":") {
		return false
	}
	fakeURL := "postgresql://proof:proof@" + host + "/proof?sslmode=require"
	if _, err := pooledNeonURL(fakeURL); err != nil {
		return false
	}
	return !strings.HasSuffix(strings.Split(host, ".")[0], "-pooler")
}

func validOperations(operations []neonOperation, target ownedBranch) bool {
	for _, operation := range operations {
		if !validOperation(operation, target) {
			return false
		}
	}
	return true
}

func validOperation(operation neonOperation, target ownedBranch) bool {
	if !uuidPattern.MatchString(operation.ID) || operation.ProjectID != target.projectID || operation.BranchID != target.branchID || operation.FailuresCount != 0 {
		return false
	}
	if operation.EndpointID != "" && ((target.endpointID != "" && operation.EndpointID != target.endpointID) || !validEndpointID(operation.EndpointID)) {
		return false
	}
	switch operation.Status {
	case "scheduling", "running", "finished", "failed", "error", "cancelling", "cancelled", "skipped":
		return true
	default:
		return false
	}
}

func validCreatedBranchState(state string) bool {
	return state == "init" || state == "ready"
}

func validCreatedEndpointState(state string) bool {
	return state == "init" || state == "active" || state == "idle"
}

func terminalOperationStatus(status string) bool {
	switch status {
	case "failed", "error", "cancelled", "skipped":
		return true
	default:
		return false
	}
}

func validBranchID(value string) bool {
	return len(value) <= 60 && branchIDPattern.MatchString(value)
}

func validEndpointID(value string) bool {
	return len(value) <= 60 && endpointIDPattern.MatchString(value)
}

func validBranchName(value string) bool {
	return strings.HasPrefix(value, migrationBranchPrefix) && markerPattern.MatchString(strings.TrimPrefix(value, migrationBranchPrefix))
}

type pgxMigrationDatabase struct {
	connection *pgx.Conn
}

func openPGXMigrationDatabase(ctx context.Context, target validatedConnection) (migrationDatabase, error) {
	if pgEnvironmentConfigured() || validateEffectivePGXConfig(target.config, target.expected) != nil || strings.Contains(target.expected.host, "-pooler.") {
		return nil, errMigrationConfiguration
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(connectCtx, target.config.Copy())
	if err != nil {
		return nil, errMigrationDatabase
	}
	return &pgxMigrationDatabase{connection: connection}, nil
}

const fingerprintQuery = `
SELECT COALESCE(jsonb_agg(jsonb_build_array(kind, object_name, detail) ORDER BY kind, object_name, detail)::text, '[]')
FROM (
    SELECT 'namespace'::text AS kind, n.nspname::text AS object_name, ''::text AS detail
      FROM pg_catalog.pg_namespace n WHERE n.nspname = $1
    UNION ALL
    SELECT 'relation', c.relname, c.relkind::text
      FROM pg_catalog.pg_namespace n
      JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid
     WHERE n.nspname = $1
    UNION ALL
    SELECT 'column', c.relname || '.' || a.attname,
           pg_catalog.format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text || ':' || COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
      FROM pg_catalog.pg_namespace n
      JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
     WHERE n.nspname = $1
    UNION ALL
    SELECT 'constraint', c.relname || '.' || k.conname, pg_catalog.pg_get_constraintdef(k.oid, true)
      FROM pg_catalog.pg_namespace n
      JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid
      JOIN pg_catalog.pg_constraint k ON k.conrelid = c.oid
     WHERE n.nspname = $1
) AS fingerprint_rows`

func (database *pgxMigrationDatabase) Fingerprint(ctx context.Context, schema string) (string, error) {
	var encoded string
	if err := database.connection.QueryRow(ctx, fingerprintQuery, schema).Scan(&encoded); err != nil {
		return "", errMigrationDatabase
	}
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:]), nil
}

func (database *pgxMigrationDatabase) Up(ctx context.Context, assets migrationAssets) error {
	_, err := database.connection.Exec(ctx, assets.up)
	return fixedDatabaseError(err)
}

func (database *pgxMigrationDatabase) VerifyShape(ctx context.Context, schema string) error {
	rows, err := database.connection.Query(ctx, `
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = $1 AND table_name = 'migration_probe'
ORDER BY ordinal_position`, schema)
	if err != nil {
		return errMigrationDatabase
	}
	defer rows.Close()
	want := [][3]string{{"id", "bigint", "NO"}, {"proof_value", "text", "NO"}, {"created_at", "timestamp with time zone", "NO"}}
	got := make([][3]string, 0, len(want))
	for rows.Next() {
		var row [3]string
		if err := rows.Scan(&row[0], &row[1], &row[2]); err != nil {
			return errMigrationDatabase
		}
		got = append(got, row)
	}
	if rows.Err() != nil || len(got) != len(want) {
		return errMigrationDatabase
	}
	for index := range want {
		if got[index] != want[index] {
			return errMigrationDatabase
		}
	}
	var primaryKeyCount int
	if err := database.connection.QueryRow(ctx, `
SELECT count(*)
FROM information_schema.table_constraints
WHERE table_schema = $1 AND table_name = 'migration_probe' AND constraint_type = 'PRIMARY KEY'`, schema).Scan(&primaryKeyCount); err != nil || primaryKeyCount != 1 {
		return errMigrationDatabase
	}
	return nil
}

func (database *pgxMigrationDatabase) Down(ctx context.Context, assets migrationAssets) error {
	_, err := database.connection.Exec(ctx, assets.down)
	return fixedDatabaseError(err)
}

func (database *pgxMigrationDatabase) Close(ctx context.Context) error {
	if err := database.connection.Close(ctx); err != nil {
		return errMigrationDatabase
	}
	return nil
}

func fixedDatabaseError(err error) error {
	if err != nil {
		return errMigrationDatabase
	}
	return nil
}
