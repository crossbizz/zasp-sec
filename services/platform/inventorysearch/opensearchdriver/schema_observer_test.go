package opensearchdriver

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestSchemaObserverReusesImmutableInventoryReadsAndBorrowedAuthority(t *testing.T) {
	for _, mode := range []string{"exact", "denied", "mapping drift", "marker drift"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client := doerFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "search-zasp-abc.us-west-2.es.amazonaws.com" || r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Body != nil && r.Body != http.NoBody || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Fatal("inventory observer exceeded signed GET authority")
				}
				if mode == "denied" {
					return httpResponse(403, `{"message":"private provider detail"}`), nil
				}
				if r.URL.Path == "/"+indexName+"/_mapping" {
					if mode == "mapping drift" {
						return httpResponse(200, `{"zasp-inventory-v1":{"mappings":{"dynamic":true}}}`), nil
					}
					return httpResponse(200, `{"`+indexName+`":`+indexSchemaJSON+`}`), nil
				}
				if r.URL.Path != "/"+indexName+"/_doc/"+schemaMarkerID {
					t.Fatal("foreign observer route")
				}
				marker := expectedSchemaMarker()
				if mode == "marker drift" {
					marker.SchemaVersion = 99
				}
				b, _ := json.Marshal(marker)
				return httpResponse(200, `{"_index":"`+indexName+`","_id":"`+schemaMarkerID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(b)+`}`), nil
			})
			observer, e := NewSchemaObserver(validConfig(), &credentialProvider{}, v4.NewSigner(), client, fixedClock)
			if e != nil || observer == nil {
				t.Fatal("explicit immutable inventory observer refused")
			}
			if reflect.TypeOf(observer).NumMethod() != 1 {
				t.Fatal("inventory observer exposed mutation or Close")
			}
			e = observer.Ready(context.Background())
			if mode == "exact" {
				if e != nil || calls != 2 {
					t.Fatal("existing inventory schema/marker verification not reused")
				}
			} else if e == nil {
				t.Fatal("drift or unavailable schema passed")
			}
			if e != nil && strings.Contains(e.Error(), "private provider") {
				t.Fatal("provider detail leaked")
			}
		})
	}
}
