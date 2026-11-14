package saasdiscovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

func decodeItem(t *testing.T, document string) saasdiscovery.Item {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	var item saasdiscovery.Item
	if err := decoder.Decode(&item); err != nil {
		t.Fatal(err)
	}
	return item
}

func TestItemHelpersReadNestedMembersWithoutPanicking(t *testing.T) {
	t.Parallel()
	item := decodeItem(t, `{"id":42,"name":"Agent","enabled":true,"owner":{"team":{"name":"Platform"},"tags":["a"]},"nothing":null,
		"members":[{"id":"m1"},"skip me",7,{"id":"m2"},null],"scalar":"text"}`)

	if got := item.Text("id"); got != "42" {
		t.Errorf("Text(id) = %q, want the number as text", got)
	}
	if got := item.Text("owner", "team", "name"); got != "Platform" {
		t.Errorf("Text(owner.team.name) = %q", got)
	}
	for _, path := range [][]string{{"missing"}, {"enabled"}, {"owner"}, {"name", "deeper"}, {"owner", "tags"}} {
		if got := item.Text(path...); got != "" {
			t.Errorf("Text(%v) = %q, want empty", path, got)
		}
	}
	if !item.Bool("enabled") || item.Bool("name") || item.Bool("missing") {
		t.Error("Bool did not read only a boolean member")
	}
	if !item.Has("owner", "team") || item.Has("nothing") || item.Has("missing") || item.Has("scalar", "x") {
		t.Error("Has did not report only present, non-null members")
	}

	team := item.Object("owner", "team")
	if team == nil || team.Text("name") != "Platform" {
		t.Fatalf("Object(owner.team) = %#v", team)
	}
	for _, path := range [][]string{{"missing"}, {"scalar"}, {"members"}, {"nothing"}} {
		if got := item.Object(path...); got != nil {
			t.Errorf("Object(%v) = %#v, want nil", path, got)
		}
	}
	// A nil Item is still safe to read from.
	if item.Object("missing").Text("anything") != "" || item.Object("missing").Has("x") {
		t.Error("reading from a missing object was not empty")
	}

	members := item.Objects("members")
	if len(members) != 2 || members[0].Text("id") != "m1" || members[1].Text("id") != "m2" {
		t.Fatalf("Objects(members) = %#v, want only the two objects", members)
	}
	for _, path := range [][]string{{"missing"}, {"owner"}, {"scalar"}, {"nothing"}} {
		if got := item.Objects(path...); got == nil || len(got) != 0 {
			t.Errorf("Objects(%v) = %#v, want an empty, non-nil list", path, got)
		}
	}
}

func TestValidConnectionReferenceAcceptsOnlyANangoConnectionUUIDv4(t *testing.T) {
	t.Parallel()
	if !saasdiscovery.ValidConnectionReference(saastest.ConnectionReference) {
		t.Fatalf("stand-in connection reference %q refused", saastest.ConnectionReference)
	}
	for _, value := range []string{
		"",
		"ref:nango/connection/",
		"ref:nango/connection/11111111-1111-1111-8111-111111111111", // not version 4
		"ref:nango/connection/11111111-1111-4111-7111-111111111111", // wrong variant
		"ref:nango/connection/11111111-1111-4111-8111-11111111111A", // upper case
		"ref:nango/connection/11111111-1111-4111-8111-111111111111\n",
		" ref:nango/connection/11111111-1111-4111-8111-111111111111",
		"ref:nango/other/11111111-1111-4111-8111-111111111111",
		"11111111-1111-4111-8111-111111111111",
		"secret-token-value",
	} {
		if saasdiscovery.ValidConnectionReference(value) {
			t.Errorf("ValidConnectionReference(%q) = true", value)
		}
	}
}

func TestNewCollectionAPIRefusesAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()
	registry, _ := acmeRegistry(t)
	standIn := saastest.NewNango(t, registry, acmeRoutes())
	for name, config := range map[string]saasdiscovery.CollectionAPIConfig{
		"no registry":    {Proxy: standIn.Proxy()},
		"empty registry": {Registry: &saasdiscovery.Registry{}, Proxy: standIn.Proxy()},
		"no proxy":       {Registry: registry},
		"zero clock":     {Registry: registry, Proxy: standIn.Proxy(), Clock: func() time.Time { return time.Time{} }},
		"non-UTC clock":  {Registry: registry, Proxy: standIn.Proxy(), Clock: func() time.Time { return time.Now().In(time.FixedZone("x", 3600)) }},
	} {
		if api, err := saasdiscovery.NewCollectionAPI(config); !errors.Is(err, saasdiscovery.ErrInvalid) || api != nil {
			t.Errorf("%s: NewCollectionAPI = %v, %v; want ErrInvalid", name, api, err)
		}
	}
	if _, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: standIn.Proxy()}); err != nil {
		t.Fatalf("default clock refused: %v", err)
	}
}

func TestCheckCollectionReadinessMakesNoProviderCall(t *testing.T) {
	t.Parallel()
	registry, _ := acmeRegistry(t)
	standIn := saastest.NewNango(t, registry, acmeRoutes())
	api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: standIn.Proxy()})
	if err != nil {
		t.Fatal(err)
	}
	readiness := api.(*saasdiscovery.SaaSCollectionAPI)
	if err := readiness.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("ready collector reported %v", err)
	}
	if calls := standIn.Calls(); len(calls) != 0 {
		t.Fatalf("readiness check made provider calls: %v", calls)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readiness.CheckCollectionReadiness(cancelled); !errors.Is(err, saasdiscovery.ErrProvider) {
		t.Fatalf("cancelled readiness = %v, want ErrProvider", err)
	}
	//lint:ignore SA1012 a nil context is the refused input under test.
	if err := readiness.CheckCollectionReadiness(nil); !errors.Is(err, saasdiscovery.ErrProvider) { //nolint:staticcheck
		t.Fatalf("nil context readiness = %v, want ErrProvider", err)
	}
	var unset *saasdiscovery.SaaSCollectionAPI
	if err := unset.CheckCollectionReadiness(context.Background()); !errors.Is(err, saasdiscovery.ErrProvider) {
		t.Fatalf("nil collector readiness = %v, want ErrProvider", err)
	}
	if err := (&saasdiscovery.SaaSCollectionAPI{}).CheckCollectionReadiness(context.Background()); !errors.Is(err, saasdiscovery.ErrProvider) {
		t.Fatalf("zero collector readiness = %v, want ErrProvider", err)
	}
}

func TestFetchCollectionPageRefusesACredentialThatIsNotAConnectionReference(t *testing.T) {
	t.Parallel()
	registry, _ := acmeRegistry(t)
	standIn := saastest.NewNango(t, registry, acmeRoutes())
	api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: standIn.Proxy()})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", "raw-provider-token", saastest.ConnectionReference + "x"} {
		page, err := api.FetchCollectionPage(context.Background(), []byte(credential), saasdiscovery.CollectionPageRequest{})
		if !errors.Is(err, saasdiscovery.ErrInvalid) || !reflect.DeepEqual(page, saasdiscovery.CollectionPage{}) {
			t.Errorf("credential %q: page=%v err=%v; want ErrInvalid", credential, page, err)
		}
	}
	if calls := standIn.Calls(); len(calls) != 0 {
		t.Fatalf("refused credentials reached the provider: %v", calls)
	}
}
