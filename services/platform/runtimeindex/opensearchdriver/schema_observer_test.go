package opensearchdriver

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type schemaEscapeSigner struct{ host bool }

func (s schemaEscapeSigner) SignHTTP(_ context.Context, _ aws.Credentials, r *http.Request, _ string, _ string, _ string, _ time.Time, _ ...func(*v4.SignerOptions)) error {
	if s.host {
		r.URL.Host = "vpc-foreign.us-west-2.es.amazonaws.com"
	} else {
		r.Method = http.MethodPost
	}
	return nil
}
func TestSchemaObserverReusesImmutableRuntimeReadsAndBorrowedAuthority(t *testing.T) {
	for _, mode := range []string{"raw", "session-v1", "session-v2", "denied", "mapping drift", "marker drift", "signer host escape", "signer method escape", "canceled", "wildcard"} {
		t.Run(mode, func(t *testing.T) {
			index, markerID, schema, marker := indexName, schemaMarkerID, indexSchemaJSON, expectedSchemaMarker()
			if mode == "session-v1" || mode == "session-v2" {
				s := &SessionIndex{sandboxV2: mode == "session-v2"}
				index, markerID, schema, marker = s.indexName(), s.markerID(), s.schemaJSON(), s.expectedMarker()
			}
			config := Config{Endpoint: "https://vpc-runtime.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 65536, MaximumResponseBytes: 65536}
			calls := 0
			client := httpDoerFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "vpc-runtime.us-west-2.es.amazonaws.com" || r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Body != nil && r.Body != http.NoBody || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Fatal("observer escaped borrowed signed GET authority")
				}
				if mode == "denied" {
					return jsonResponse(403, `{"message":"provider detail must not escape"}`), nil
				}
				switch r.URL.Path {
				case "/" + index + "/_mapping":
					if mode == "mapping drift" {
						return jsonResponse(200, `{"`+index+`":{"mappings":{"dynamic":true}}}`), nil
					}
					return jsonResponse(200, `{"`+index+`":`+schema+`}`), nil
				case "/" + index + "/_doc/" + markerID:
					if mode == "marker drift" {
						marker.SchemaVersion = 99
					}
					b, _ := json.Marshal(marker)
					return jsonResponse(200, `{"_index":"`+index+`","_id":"`+markerID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(b)+`}`), nil
				default:
					t.Fatal("unexpected route")
					return nil, nil
				}
			})
			credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "observer", SecretAccessKey: "controlled-fixture-only"}, nil
			})
			var signer HTTPSigner = v4.NewSigner()
			if mode == "signer host escape" || mode == "signer method escape" {
				signer = schemaEscapeSigner{host: mode == "signer host escape"}
			}
			if mode == "wildcard" {
				index = "*"
			}
			observer, e := NewSchemaObserver(index, config, credentials, signer, client, func() time.Time { return time.Now().UTC() })
			if mode == "wildcard" {
				if e == nil || observer != nil || calls != 0 {
					t.Fatal("wildcard reached observer")
				}
				return
			}
			if e != nil || observer == nil {
				t.Fatal("explicit immutable observer refused")
			}
			if reflect.TypeOf(observer).NumMethod() != 1 {
				t.Fatal("observer exposed mutation or borrowed transport ownership")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			e = observer.Ready(ctx)
			if mode == "raw" || mode == "session-v1" || mode == "session-v2" {
				if e != nil || calls != 2 {
					t.Fatal("exact existing schema/marker reads were not reused")
				}
			} else if e == nil {
				t.Fatal("unobserved or drifted schema passed")
			}
			if strings.Contains(mode, "escape") || mode == "canceled" {
				if calls != 0 {
					t.Fatal("forbidden request reached borrowed client")
				}
			}
			if e != nil && strings.Contains(e.Error(), "provider detail") {
				t.Fatal("provider response leaked")
			}
		})
	}
}
