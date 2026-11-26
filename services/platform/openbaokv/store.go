// Package openbaokv stores connector credentials as bytes within one workload root.
package openbaokv

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
)

const Provider = "openbao"

type Config struct {
	Provider string
	Client   openbaoclient.Config
	Mount    string
}

func FromEnvironment(getenv func(string) string) Config {
	config := Config{Provider: getenv("ZASP_CONNECTOR_SECRETS_PROVIDER"), Mount: getenv("ZASP_OPENBAO_KV_MOUNT")}
	if config.Provider == Provider {
		config.Client = openbaoclient.FromEnvironment(getenv)
	}
	return config
}

func (c Config) Valid() bool {
	switch c.Provider {
	case "", "aws-secrets-manager":
		return c.Mount == "" && c.Client == (openbaoclient.Config{})
	case Provider:
		return c.Client.Valid() && openbaoclient.ValidPath(c.Mount) && !strings.Contains(c.Mount, "/")
	default:
		return false
	}
}

type Store struct {
	client *openbaoclient.Client
	mount  string
	root   string
}

func New(c Config, root string, timeout time.Duration) (*Store, error) {
	if c.Provider != Provider || !c.Valid() || !openbaoclient.ValidPath(root) {
		return nil, errors.New("invalid OpenBao connector secret configuration")
	}
	client, err := openbaoclient.New(c.Client, timeout)
	if err != nil {
		return nil, err
	}
	return &Store{client: client, mount: c.Mount, root: root}, nil
}

func (s *Store) CloseIdleConnections() { s.client.CloseIdleConnections() }

// Ready verifies the dedicated mount permanently discards older data on each
// CAS update. Workload tokens must not have per-key metadata write permissions.
func (s *Store) Ready(ctx context.Context) error {
	var result struct {
		Data struct {
			MaxVersions int `json:"max_versions"`
		}
	}
	if err := s.client.Do(ctx, http.MethodGet, s.mount+"/config", nil, &result); err != nil {
		return err
	}
	if result.Data.MaxVersions != 1 {
		return errors.New("OpenBao connector KV mount must use max_versions=1")
	}
	return nil
}

type record struct {
	Value   []byte `json:"value,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}
type writeOptions struct {
	CAS int `json:"cas"`
}

func (s *Store) path(name string) (string, error) {
	if !strings.HasPrefix(name, s.root+"/") || !openbaoclient.ValidPath(name) {
		return "", openbaoclient.ErrUnavailable
	}
	return s.mount + "/data/" + name, nil
}

func (s *Store) get(ctx context.Context, path string) (record, int, error) {
	var result struct {
		Data struct {
			Data     record
			Metadata struct{ Version int }
		}
	}
	if err := s.client.Do(ctx, http.MethodGet, path, nil, &result); err != nil {
		return record{}, 0, err
	}
	r, version := result.Data.Data, result.Data.Metadata.Version
	if version < 1 || len(r.Value) > 32<<10 || r.Deleted != (len(r.Value) == 0) {
		return record{}, 0, openbaoclient.ErrUnavailable
	}
	return r, version, nil
}

func (s *Store) put(ctx context.Context, path string, cas int, data record) error {
	input := struct {
		Data    record       `json:"data"`
		Options writeOptions `json:"options"`
	}{data, writeOptions{cas}}
	var result struct{ Data struct{ Version int } }
	if err := s.client.Do(ctx, http.MethodPost, path, input, &result); err != nil {
		return err
	}
	if result.Data.Version != cas+1 {
		return openbaoclient.ErrUnavailable
	}
	return nil
}

func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	path, err := s.path(name)
	if err != nil || len(value) == 0 || len(value) > 32<<10 {
		return openbaoclient.ErrUnavailable
	}
	// OAuth grant IDs are single-use, including after consumption.
	if strings.HasPrefix(name, s.root+"/oauth/") {
		return s.put(ctx, path, 0, record{Value: value})
	}
	previous, version, err := s.get(ctx, path)
	defer clear(previous.Value)
	if errors.Is(err, openbaoclient.ErrNotFound) {
		return s.put(ctx, path, 0, record{Value: value})
	}
	if err != nil {
		return err
	}
	if !previous.Deleted {
		return openbaoclient.ErrVersionConflict
	}
	return s.put(ctx, path, version, record{Value: value})
}

func (s *Store) Read(ctx context.Context, name string) ([]byte, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	r, _, err := s.get(ctx, path)
	if err != nil {
		return nil, err
	}
	if r.Deleted {
		return nil, openbaoclient.ErrNotFound
	}
	return r.Value, nil
}

func (s *Store) Delete(ctx context.Context, name string) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	r, version, err := s.get(ctx, path)
	defer clear(r.Value)
	if err != nil {
		return err
	}
	if r.Deleted {
		return openbaoclient.ErrNotFound
	}
	// CAS makes duplicate consumers race for one update. With max_versions=1
	// this atomically removes the secret bytes and preserves the used grant ID.
	return s.put(ctx, path, version, record{Deleted: true})
}
