package opensearchdriver

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SchemaObserver exposes only existing immutable schema reads over a borrowed client.
// It deliberately has no Close: transport ownership remains with the caller.
type SchemaObserver interface{ Ready(context.Context) error }
type schemaObserver struct{ ready func(context.Context) error }

func (o *schemaObserver) Ready(ctx context.Context) error {
	if o == nil || o.ready == nil || ctx == nil || ctx.Err() != nil {
		return runtimeindex.ErrConfiguration
	}
	return o.ready(ctx)
}

// NewSchemaObserver reuses the canonical mapping and marker checks without
// exposing initialization, document mutation or an alternate network transport.
func NewSchemaObserver(index string, config Config, credentials aws.CredentialsProvider, signer HTTPSigner, client HTTPDoer, clock func() time.Time) (SchemaObserver, error) {
	if config.AllowTestLoopback {
		return nil, runtimeindex.ErrConfiguration
	}
	markerID := schemaMarkerID
	switch index {
	case indexName:
	case sessionIndexName:
		markerID = sessionSchemaMarkerID
	case "zasp-runtime-sessions-v2":
		markerID = "_zasp_session_schema_v2"
	default:
		return nil, runtimeindex.ErrConfiguration
	}

	endpoint, e := validateConfig(config, credentials, signer, clock)
	if e != nil || nilInterface(client) {
		return nil, runtimeindex.ErrConfiguration
	}
	guard := schemaReadClient{client: client, endpoint: *endpoint, paths: map[string]bool{"/" + index + "/_mapping": true, "/" + index + "/_doc/" + markerID: true}}
	driver, e := newWithClient(config, credentials, signer, guard, clock)
	if e != nil {
		return nil, e
	}
	if index != indexName {
		session := &SessionIndex{transport: driver, sandboxV2: index == "zasp-runtime-sessions-v2"}
		return &schemaObserver{ready: session.Ready}, nil
	}

	return &schemaObserver{ready: driver.Ready}, nil
}

// This check runs after signing, immediately before the borrowed client. A signer
// cannot redirect this capability or introduce a write method/body/query.
type schemaReadClient struct {
	client   HTTPDoer
	endpoint url.URL
	paths    map[string]bool
}

func (c schemaReadClient) Do(r *http.Request) (*http.Response, error) {
	if r == nil || r.Context().Err() != nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Scheme != c.endpoint.Scheme || r.URL.Host != c.endpoint.Host || r.Host != "" && r.Host != c.endpoint.Host || r.URL.User != nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || !c.paths[r.URL.Path] || r.Body != nil && r.Body != http.NoBody || r.ContentLength != 0 || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		return nil, runtimeindex.ErrConfiguration
	}
	return c.client.Do(r)
}
