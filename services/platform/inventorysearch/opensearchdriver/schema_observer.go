package opensearchdriver

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
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
		return inventorysearch.ErrConfiguration
	}
	return o.ready(ctx)
}

// NewSchemaObserver reuses the canonical mapping and marker checks without
// exposing initialization, document mutation or an alternate network transport.
func NewSchemaObserver(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, client HTTPDoer, clock func() time.Time) (SchemaObserver, error) {
	index := indexName
	markerID := schemaMarkerID

	endpoint, e := validateConfig(config, credentials, signer, clock)
	if e != nil || nilInterface(client) {
		return nil, inventorysearch.ErrConfiguration
	}
	guard := schemaReadClient{client: client, endpoint: *endpoint, paths: map[string]bool{"/" + index + "/_mapping": true, "/" + index + "/_doc/" + markerID: true}}
	driver, e := newWithClient(config, credentials, signer, guard, clock)
	if e != nil {
		return nil, e
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
		return nil, inventorysearch.ErrConfiguration
	}
	return c.client.Do(r)
}
