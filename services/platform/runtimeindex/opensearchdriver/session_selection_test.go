package opensearchdriver

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConfiguredSessionIndexUsesOnlySelectedProviderPath(t *testing.T) {
	for _, name := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", "zasp-runtime-sessions-v3", " zasp-runtime-sessions-v2", "arbitrary"} {
		t.Run(name, func(t *testing.T) {
			requests := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.URL.Path
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"missing"}`))
			}))
			defer server.Close()
			config := Config{Endpoint: server.URL, Region: "us-west-2", RequestTimeout: time.Second, MaximumRequestBytes: 1 << 20, MaximumResponseBytes: 1 << 20, AllowTestLoopback: true}
			credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
			})
			index, err := NewConfiguredSessionIndex(name, config, credentials, signerStub{}, func() time.Time { return time.Now().UTC() })
			valid := name == "" || name == "zasp-runtime-sessions-v1" || name == "zasp-runtime-sessions-v2"
			if !valid {
				if err == nil || index != nil {
					t.Fatal("unknown index accepted", name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer index.Close()
			if err := index.Ready(context.Background()); err != runtimeindex.ErrRejected {
				t.Fatal("missing selected schema was accepted", err)
			}
			want := name
			if want == "" {
				want = "zasp-runtime-sessions-v1"
			}
			select {
			case path := <-requests:
				if path != "/"+want+"/_mapping" {
					t.Fatal("wrong provider index", path, want)
				}
			default:
				t.Fatal("selected index wasn't checked")
			}
			select {
			case path := <-requests:
				t.Fatal("unexpected fallback request", path)
			default:
			}
		})
	}
}
