package issuer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"io"
	"os"
	"path/filepath"

	"slices"
	"time"
)

type Tenant = delegation.Tenant
type Scope = delegation.Scope
type Binding = delegation.Binding

var ErrDenied = delegation.ErrDenied

func cloneScope(s Scope) Scope {
	return Scope{Operations: slices.Clone(s.Operations), Resources: slices.Clone(s.Resources)}
}

// Agent links a workload credential to one tenant-scoped identity. An identity
// provisioned for delegated work must present a valid grant on every use.
type Agent struct {
	Tenant
	ID         string `json:"agent_id"`
	Credential string `json:"credential_id"`
	Delegated  bool   `json:"delegated"`
	Purpose    Scope  `json:"purpose"`
}

type Task struct {
	Binding
	Scope
	MaxDepth int `json:"max_depth"`
}

type Policy struct {
	Tenant
	Scope
}

type Configuration struct {
	Seed     []byte   `json:"signing_seed"`
	Agents   []Agent  `json:"agents"`
	Tasks    []Task   `json:"tasks"`
	Policies []Policy `json:"policies"`
}

type principal struct {
	Tenant
	ID string
}
type taskKey struct {
	Tenant
	ID string
}
type Authority struct {
	key         ed25519.PrivateKey
	agents      map[principal]Agent
	credentials map[principal]Agent
	tasks       map[taskKey]Task
	policies    map[Tenant]Scope
}

func Load(path string) (*Authority, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrDenied
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) || actual.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	defer clear(raw)
	var cfg Configuration
	if err != nil || len(raw) > 1<<20 || decodeConfig(raw, &cfg) != nil {
		return nil, ErrDenied
	}
	defer clear(cfg.Seed)
	return NewAuthority(cfg)
}

func NewAuthority(cfg Configuration) (*Authority, error) {
	if len(cfg.Seed) != ed25519.SeedSize || len(cfg.Agents) == 0 || len(cfg.Tasks) == 0 {
		return nil, ErrDenied
	}
	a := &Authority{key: ed25519.NewKeyFromSeed(cfg.Seed), agents: map[principal]Agent{}, credentials: map[principal]Agent{}, tasks: map[taskKey]Task{}, policies: map[Tenant]Scope{}}
	for _, p := range cfg.Policies {
		if !p.Tenant.Valid() || !p.Scope.Valid() || a.policies[p.Tenant].Operations != nil {
			return nil, ErrDenied
		}
		a.policies[p.Tenant] = cloneScope(p.Scope)
	}
	for _, g := range cfg.Agents {
		id, cred := principal{g.Tenant, g.ID}, principal{g.Tenant, g.Credential}
		if !g.Tenant.Valid() || !delegation.ValidIdentifier(g.ID) || !delegation.ValidIdentifier(g.Credential) || !g.Purpose.Valid() ||
			a.agents[id].ID != "" || a.credentials[cred].ID != "" || a.policies[g.Tenant].Operations == nil {
			return nil, ErrDenied
		}
		g.Purpose = cloneScope(g.Purpose)
		a.agents[id], a.credentials[cred] = g, g
	}
	for _, t := range cfg.Tasks {
		root, ok := a.agents[principal{t.Tenant, t.Agent}]
		k := taskKey{t.Tenant, t.Task}
		if !ok || root.Delegated || !t.Binding.Valid() || !t.Scope.Valid() || t.MaxDepth < 1 || t.MaxDepth > delegation.MaxDepth || a.tasks[k].Task != "" {
			return nil, ErrDenied
		}
		t.Scope = cloneScope(t.Scope)
		a.tasks[k] = t
	}
	return a, nil
}

type IssueRequest struct {
	Scope
	Task        string `json:"parent_task_id"`
	Child       string `json:"child_agent_id"`
	MaxDepth    int    `json:"max_depth"`
	TTL         int    `json:"ttl_seconds"`
	ParentToken string `json:"parent_token,omitempty"`
}

type Grant struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires_at"`
	Depth   int    `json:"depth"`
}

func (a *Authority) Required(t Tenant, credential string) bool {
	return a != nil && a.credentials[principal{t, credential}].Delegated
}

// Tier: 1 | Purpose: issue a narrower child grant.
// Model: none.
// Authority: operator-provisioned root task, current parent, child purpose and tenant policy.
// Fallback: reject unknown bindings and any widening, including expiration and depth.
func (a *Authority) Issue(t Tenant, credential string, req IssueRequest, now time.Time) (Grant, error) {
	if a == nil || !req.Scope.Valid() || req.TTL < 1 || req.TTL > delegation.MaxTTL {
		return Grant{}, ErrDenied
	}
	parent, ok := a.credentials[principal{t, credential}]
	child := a.agents[principal{t, req.Child}]
	task := a.tasks[taskKey{t, req.Task}]
	if !ok || !child.Delegated || task.Task == "" || !req.Scope.Within(task.Scope) ||
		!req.Scope.Within(a.policies[t]) || !req.Scope.Within(parent.Purpose) || !req.Scope.Within(child.Purpose) || req.MaxDepth > task.MaxDepth {
		return Grant{}, ErrDenied
	}
	c := delegation.Claims{Tenant: t, Scope: req.Scope, Task: req.Task, Parent: parent.ID, Child: req.Child, Depth: 1, MaxDepth: req.MaxDepth, Issued: now.Unix(), Expires: now.Unix() + int64(req.TTL)}
	if req.ParentToken != "" {
		p, err := delegation.Verify(a.public(), req.ParentToken, Binding{t, req.Task, parent.ID}, now)
		if err != nil || !parent.Delegated || !req.Scope.Within(p.Scope) || c.Expires > p.Expires || c.MaxDepth > p.MaxDepth {
			return Grant{}, ErrDenied
		}
		c.Depth = p.Depth + 1
	} else if parent.ID != task.Agent || parent.Delegated {
		return Grant{}, ErrDenied
	}
	if !c.Valid(now.Unix()) {
		return Grant{}, ErrDenied
	}
	token, err := sign(a.key, c)
	if err != nil {
		return Grant{}, err
	}
	return Grant{token, c.Expires, c.Depth}, nil
}

func (a *Authority) public() ed25519.PublicKey { return a.key.Public().(ed25519.PublicKey) }

func (a *Authority) Check(t Tenant, credential, task, token, operation, resource string, now time.Time) delegation.Decision {
	if a == nil || !a.Required(t, credential) {
		return delegation.Decision{Status: "denied"}
	}
	if token == "" {
		return delegation.Decision{Status: "delegation_unverified"}
	}
	child := a.credentials[principal{t, credential}]
	s := Scope{[]string{operation}, []string{resource}}
	if !s.Within(child.Purpose) || !s.Within(a.policies[t]) || !s.Within(a.tasks[taskKey{t, task}].Scope) {
		return delegation.Decision{Status: "denied"}
	}
	return delegation.Check(a.public(), token, Binding{t, task, child.ID}, operation, resource, now)
}

func (a *Authority) AgentID(t Tenant, credential string) string {
	if a == nil {
		return ""
	}
	return a.credentials[principal{t, credential}].ID
}

func decodeConfig(raw []byte, cfg *Configuration) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(cfg) != nil || d.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func sign(key ed25519.PrivateKey, c delegation.Claims) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return "", ErrDenied
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "zasp-task-delegation.v1+jwt"); err != nil {
		return "", ErrDenied
	}
	token, err := jws.Sign(raw, jws.WithKey(jwa.EdDSA(), key, jws.WithProtectedHeaders(headers)))
	if err != nil || len(token) > 16384 {
		return "", ErrDenied
	}
	return string(token), nil
}
