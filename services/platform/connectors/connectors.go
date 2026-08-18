package connectors

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrInvalid          = errors.New("connector input rejected")
	ErrCredentialDenied = errors.New("AWS credential check denied")
	ErrNormalization    = errors.New("connector normalization rejected")
	ErrFreshness        = errors.New("integration freshness rejected")
	ErrConnection       = errors.New("connection reference rejected")
	ErrOAuth            = errors.New("OAuth callback rejected")
	ErrProxy            = errors.New("proxy request rejected")
)

var (
	roleARNPattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	hostPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type AWSConfig struct {
	RoleARN, ExternalID, Region string
}

type AWSIdentity struct {
	AccountID, PrincipalARN string
}

type AWSClient interface {
	AssumeRoleIdentity(context.Context, AWSConfig) (AWSIdentity, error)
}

type AWSCredentialAdapter struct{ client AWSClient }

func NewAWSCredentialAdapter(client AWSClient) (*AWSCredentialAdapter, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	return &AWSCredentialAdapter{client: client}, nil
}

func (adapter *AWSCredentialAdapter) Check(ctx context.Context, config AWSConfig) (AWSIdentity, error) {
	account, valid := validAWSConfig(config)
	if adapter == nil || adapter.client == nil || !valid || !activeContext(ctx) {
		return AWSIdentity{}, ErrInvalid
	}
	identity, err := safeAssume(adapter.client, ctx, config)
	if err != nil {
		return AWSIdentity{}, ErrCredentialDenied
	}
	if identity.AccountID != account || !strings.HasPrefix(identity.PrincipalARN, "arn:aws:sts::"+account+":assumed-role/") || !bounded(identity.PrincipalARN, 1024) {
		return AWSIdentity{}, ErrCredentialDenied
	}
	return identity, nil
}

func safeAssume(client AWSClient, ctx context.Context, config AWSConfig) (identity AWSIdentity, err error) {
	defer func() {
		if recover() != nil {
			identity = AWSIdentity{}
			err = ErrCredentialDenied
		}
	}()
	return client.AssumeRoleIdentity(ctx, config)
}

func validAWSConfig(config AWSConfig) (string, bool) {
	match := roleARNPattern.FindStringSubmatch(config.RoleARN)
	return func() string {
		if len(match) == 2 {
			return match[1]
		}
		return ""
	}(), len(match) == 2 && bounded(config.ExternalID, 256) && regionPattern.MatchString(config.Region)
}

type Entity struct{ ID, Kind, Name, ExternalID string }
type Relationship struct{ ID, From, Type, To string }
type Evidence struct{ ID, ResourceID, CheckID, Severity, Status string }
type Batch struct {
	Scope         domain.Scope
	Entities      []Entity
	Relationships []Relationship
	Evidence      []Evidence
}

func (batch Batch) Validate() error {
	if batch.Scope.Validate() != nil || len(batch.Entities) == 0 || len(batch.Entities) > 10000 || len(batch.Relationships) > 20000 || len(batch.Evidence) > 20000 {
		return ErrNormalization
	}
	entityIDs := map[string]struct{}{}
	for _, item := range batch.Entities {
		if !validEntity(item) {
			return ErrNormalization
		}
		if _, exists := entityIDs[item.ID]; exists {
			return ErrNormalization
		}
		entityIDs[item.ID] = struct{}{}
	}
	for _, item := range batch.Relationships {
		if !validID(item.ID) || !validID(item.From) || !tokenPattern.MatchString(item.Type) || !validID(item.To) {
			return ErrNormalization
		}
		if _, ok := entityIDs[item.From]; !ok {
			return ErrNormalization
		}
		if _, ok := entityIDs[item.To]; !ok {
			return ErrNormalization
		}
	}
	for _, item := range batch.Evidence {
		if !validID(item.ID) || !validID(item.ResourceID) || !tokenPattern.MatchString(item.CheckID) || !oneOf(item.Severity, "low", "medium", "high", "critical") || !oneOf(item.Status, "FAIL", "PASS") {
			return ErrNormalization
		}
		if _, ok := entityIDs[item.ResourceID]; !ok {
			return ErrNormalization
		}
	}
	return nil
}

type CartographyNode struct{ Kind, ExternalID, Name string }

func RunCartography(ctx context.Context, scope domain.Scope, nodes []CartographyNode) (Batch, error) {
	if !activeContext(ctx) || len(nodes) == 0 || len(nodes) > 10000 {
		return Batch{}, ErrNormalization
	}
	batch := Batch{Scope: scope, Entities: make([]Entity, 0, len(nodes))}
	for _, node := range nodes {
		batch.Entities = append(batch.Entities, newEntity(scope, "cartography", node.Kind, node.ExternalID, node.Name))
	}
	sortEntities(batch.Entities)
	if batch.Validate() != nil {
		return Batch{}, ErrNormalization
	}
	return batch, nil
}

type ProwlerFinding struct{ CheckID, ResourceARN, Severity, Status string }

func RunProwler(ctx context.Context, scope domain.Scope, findings []ProwlerFinding) (Batch, error) {
	if !activeContext(ctx) || len(findings) == 0 || len(findings) > 10000 {
		return Batch{}, ErrNormalization
	}
	batch := Batch{Scope: scope}
	seen := map[string]struct{}{}
	for _, finding := range findings {
		entity := newEntity(scope, "prowler", "aws_resource", finding.ResourceARN, finding.ResourceARN)
		if _, exists := seen[entity.ID]; !exists {
			batch.Entities = append(batch.Entities, entity)
			seen[entity.ID] = struct{}{}
		}
		batch.Evidence = append(batch.Evidence, Evidence{ID: stableID(scope, "evidence", finding.CheckID+"\x00"+finding.ResourceARN), ResourceID: entity.ID, CheckID: finding.CheckID, Severity: finding.Severity, Status: finding.Status})
	}
	sortEntities(batch.Entities)
	sort.Slice(batch.Evidence, func(i, j int) bool { return batch.Evidence[i].ID < batch.Evidence[j].ID })
	if batch.Validate() != nil {
		return Batch{}, ErrNormalization
	}
	return batch, nil
}

type AWSFixture struct{ AccountID, RoleARN, PolicyARN string }

func NormalizeAWS(scope domain.Scope, value AWSFixture) (Batch, error) {
	account := newEntity(scope, "aws", "aws_account", value.AccountID, value.AccountID)
	role := newEntity(scope, "aws", "aws_role", value.RoleARN, value.RoleARN)
	policy := newEntity(scope, "aws", "aws_policy", value.PolicyARN, value.PolicyARN)
	return validatedBatch(makeBatch(scope, []Entity{account, role, policy}, [][3]string{{role.ID, "belongs_to", account.ID}, {role.ID, "uses_policy", policy.ID}}))
}

type KubernetesFixture struct{ Cluster, Namespace, ServiceAccount, Workload string }

func NormalizeKubernetes(scope domain.Scope, value KubernetesFixture) (Batch, error) {
	cluster := newEntity(scope, "kubernetes", "cluster", value.Cluster, value.Cluster)
	namespace := newEntity(scope, "kubernetes", "namespace", value.Cluster+"/"+value.Namespace, value.Namespace)
	serviceAccount := newEntity(scope, "kubernetes", "service_account", value.Cluster+"/"+value.Namespace+"/"+value.ServiceAccount, value.ServiceAccount)
	workload := newEntity(scope, "kubernetes", "workload", value.Cluster+"/"+value.Namespace+"/"+value.Workload, value.Workload)
	return validatedBatch(makeBatch(scope, []Entity{cluster, namespace, serviceAccount, workload}, [][3]string{{namespace.ID, "belongs_to", cluster.ID}, {serviceAccount.ID, "belongs_to", namespace.ID}, {workload.ID, "uses_identity", serviceAccount.ID}}))
}

type GitHubFixture struct{ Organization, Repository, App, Workflow, Permission string }

func NormalizeGitHub(scope domain.Scope, value GitHubFixture) (Batch, error) {
	organization := newEntity(scope, "github", "github_organization", value.Organization, value.Organization)
	repository := newEntity(scope, "github", "repository", value.Organization+"/"+value.Repository, value.Repository)
	app := newEntity(scope, "github", "github_app", value.Organization+"/"+value.App, value.App)
	workflow := newEntity(scope, "github", "workflow", value.Organization+"/"+value.Repository+"/"+value.Workflow, value.Workflow)
	permission := newEntity(scope, "github", "permission", value.Permission, value.Permission)
	return validatedBatch(makeBatch(scope, []Entity{organization, repository, app, workflow, permission}, [][3]string{{repository.ID, "belongs_to", organization.ID}, {workflow.ID, "belongs_to", repository.ID}, {app.ID, "has_permission", permission.ID}, {workflow.ID, "uses_identity", app.ID}}))
}

type IdPFixture struct{ Provider, User, Group, Application, ServicePrincipal string }

func NormalizeIdP(scope domain.Scope, value IdPFixture) (Batch, error) {
	user := newEntity(scope, value.Provider, "identity", value.User, value.User)
	group := newEntity(scope, value.Provider, "group", value.Group, value.Group)
	app := newEntity(scope, value.Provider, "application", value.Application, value.Application)
	principal := newEntity(scope, value.Provider, "service_principal", value.ServicePrincipal, value.ServicePrincipal)
	return validatedBatch(makeBatch(scope, []Entity{user, group, app, principal}, [][3]string{{user.ID, "member_of", group.ID}, {group.ID, "has_access", app.ID}, {principal.ID, "has_access", app.ID}}))
}

func validatedBatch(batch Batch) (Batch, error) {
	if batch.Validate() != nil {
		return Batch{}, ErrNormalization
	}
	return batch, nil
}

func makeBatch(scope domain.Scope, entities []Entity, edges [][3]string) Batch {
	batch := Batch{Scope: scope, Entities: entities}
	for _, edge := range edges {
		batch.Relationships = append(batch.Relationships, Relationship{ID: stableID(scope, "relationship", edge[0]+"\x00"+edge[1]+"\x00"+edge[2]), From: edge[0], Type: edge[1], To: edge[2]})
	}
	sortEntities(batch.Entities)
	sort.Slice(batch.Relationships, func(i, j int) bool { return batch.Relationships[i].ID < batch.Relationships[j].ID })
	return batch
}

type FreshnessState struct {
	Scope          domain.Scope
	LastSuccess    time.Time
	LastError      string
	RateLimitUntil time.Time
	StaleAfter     time.Time
	Stale          bool
	Inventory      []Entity
}
type FreshnessStore struct {
	mu     sync.RWMutex
	states map[domain.ProductID]FreshnessState
}

func NewFreshnessStore() *FreshnessStore {
	return &FreshnessStore{states: map[domain.ProductID]FreshnessState{}}
}
func (store *FreshnessStore) RecordSuccess(scope domain.Scope, id domain.ProductID, at time.Time, inventory []Entity) error {
	if !usableFreshness(store, scope, id, at) || len(inventory) == 0 || len(inventory) > 10000 {
		return ErrFreshness
	}
	for _, item := range inventory {
		if !validEntity(item) {
			return ErrFreshness
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.states[id]
	if !state.Scope.IsZero() && state.Scope != scope {
		return ErrFreshness
	}
	if !state.LastSuccess.IsZero() && !at.After(state.LastSuccess) {
		return ErrFreshness
	}
	state.LastSuccess = at
	state.Scope = scope
	state.LastError = ""
	state.RateLimitUntil = time.Time{}
	state.StaleAfter = at.Add(24 * time.Hour)
	state.Inventory = append([]Entity(nil), inventory...)
	store.states[id] = state
	return nil
}
func (store *FreshnessStore) RecordFailure(scope domain.Scope, id domain.ProductID, at time.Time, message string, rateLimitUntil time.Time) error {
	if !usableFreshness(store, scope, id, at) || !bounded(message, 256) || !canonicalOptionalTime(rateLimitUntil) || !rateLimitUntil.IsZero() && rateLimitUntil.Before(at) {
		return ErrFreshness
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, ok := store.states[id]
	if !ok || state.Scope != scope || at.Before(state.LastSuccess) {
		return ErrFreshness
	}
	state.LastError = message
	state.RateLimitUntil = rateLimitUntil
	store.states[id] = state
	return nil
}
func (store *FreshnessStore) Get(scope domain.Scope, id domain.ProductID, now time.Time) (FreshnessState, error) {
	if !usableFreshness(store, scope, id, now) {
		return FreshnessState{}, ErrFreshness
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	state, ok := store.states[id]
	if !ok || state.Scope != scope {
		return FreshnessState{}, ErrFreshness
	}
	state.Inventory = append([]Entity(nil), state.Inventory...)
	state.Stale = !state.StaleAfter.IsZero() && !now.Before(state.StaleAfter)
	return state, nil
}

type Connection struct {
	Scope                              domain.Scope
	Provider, Reference, RawCredential string
}
type ConnectionStore struct {
	mu     sync.RWMutex
	values map[string]Connection
}

func NewConnectionStore() *ConnectionStore { return &ConnectionStore{values: map[string]Connection{}} }
func (store *ConnectionStore) Put(scope domain.Scope, provider, reference, rawCredential string) (Connection, error) {
	if store == nil || store.values == nil || scope.Validate() != nil || !tokenPattern.MatchString(provider) || !bounded(reference, 256) || !bounded(rawCredential, 4096) {
		return Connection{}, ErrConnection
	}
	value := Connection{Scope: scope, Provider: provider, Reference: reference}
	key := scopeKey(scope) + "\x00" + provider
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
	return value, nil
}
func (store *ConnectionStore) Get(scope domain.Scope, provider string) (Connection, error) {
	if store == nil || scope.Validate() != nil {
		return Connection{}, ErrConnection
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.values[scopeKey(scope)+"\x00"+provider]
	if !ok {
		return Connection{}, ErrConnection
	}
	return value, nil
}

type OAuthCallback struct{ State, ExpectedState, Code, CodeVerifier, ExpectedChallenge string }

func ValidateOAuthCallback(value OAuthCallback) (string, error) {
	if !bounded(value.State, 256) || len(value.State) != len(value.ExpectedState) || subtle.ConstantTimeCompare([]byte(value.State), []byte(value.ExpectedState)) != 1 || !bounded(value.Code, 2048) || len(value.CodeVerifier) < 43 || len(value.CodeVerifier) > 128 {
		return "", ErrOAuth
	}
	digest := sha256.Sum256([]byte(value.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if len(challenge) != len(value.ExpectedChallenge) || subtle.ConstantTimeCompare([]byte(challenge), []byte(value.ExpectedChallenge)) != 1 {
		return "", ErrOAuth
	}
	return value.Code, nil
}

type ProxyPolicy struct{ hosts map[string]struct{} }

func NewProxyPolicy(hosts []string) *ProxyPolicy {
	policy := &ProxyPolicy{hosts: map[string]struct{}{}}
	for _, host := range hosts {
		host = strings.ToLower(host)
		if validHost(host) {
			policy.hosts[host] = struct{}{}
		}
	}
	return policy
}
func (policy *ProxyPolicy) Validate(method, target string) error {
	if policy == nil || len(policy.hosts) == 0 || method != "GET" || len(target) > 2048 {
		return ErrProxy
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Port() != "" && parsed.Port() != "443" || parsed.Fragment != "" || parsed.RawPath != "" && strings.Contains(parsed.RawPath, "..") {
		return ErrProxy
	}
	host := strings.ToLower(parsed.Hostname())
	if !validHost(host) {
		return ErrProxy
	}
	if _, ok := policy.hosts[host]; !ok {
		return ErrProxy
	}
	return nil
}

func newEntity(scope domain.Scope, source, kind, externalID, name string) Entity {
	return Entity{ID: stableID(scope, kind, source+"\x00"+externalID), Kind: kind, Name: name, ExternalID: externalID}
}
func stableID(scope domain.Scope, kind, value string) string {
	digest := sha256.Sum256([]byte(scope.OrganizationID().String() + "\x00" + kind + "\x00" + value))
	return "src_" + hex.EncodeToString(digest[:])
}
func validEntity(value Entity) bool {
	return validID(value.ID) && tokenPattern.MatchString(value.Kind) && bounded(value.Name, 512) && bounded(value.ExternalID, 1024)
}
func validID(value string) bool {
	if !strings.HasPrefix(value, "src_") || len(value) != 68 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "src_"))
	return err == nil
}
func sortEntities(values []Entity) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}
func activeContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}
func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
func usableFreshness(store *FreshnessStore, scope domain.Scope, id domain.ProductID, at time.Time) bool {
	return store != nil && store.states != nil && scope.Validate() == nil && !id.IsZero() && canonicalTime(at)
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}
func canonicalOptionalTime(value time.Time) bool { return value.IsZero() || canonicalTime(value) }
func validHost(host string) bool {
	return hostPattern.MatchString(host) && net.ParseIP(host) == nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") && !strings.Contains(host, "..")
}
func scopeKey(scope domain.Scope) string {
	return scope.OrganizationID().String() + "\x00" + scope.WorkspaceID().String() + "\x00" + scope.EnvironmentID().String()
}
