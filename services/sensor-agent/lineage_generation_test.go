package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type lineageGenerationPublishFixture struct {
	spool   *lineageSpool
	after   func()
	created *lineageSpoolGeneration
	context context.Context
}

func (publisher *lineageGenerationPublishFixture) Create(ctx context.Context, source sensoradapter.LineageSource) (*lineageSpoolGeneration, error) {
	publisher.context = ctx
	generation, err := publisher.spool.Create(ctx, source)
	publisher.created = generation
	if publisher.after != nil {
		publisher.after()
	}
	return generation, err
}

func TestLineageGenerationCancellationAfterManifestPreservesAbandonedHistory(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	endpoint, _ := lineageGenerationFixture(t, nil)
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	publisher := &lineageGenerationPublishFixture{spool: spool, after: cancel}
	generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, publisher)
	if generation != nil || err != errLineageGeneration || publisher.created == nil {
		t.Fatal("post-publication cancellation admitted")
	}
	if !publisher.created.closed || spool.active != nil || spool.closed {
		t.Fatal("owned/borrowed cleanup incorrect")
	}
	name := "generation-" + publisher.created.source.GenerationID
	root, err := spool.root.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.ReadFile("manifest.json"); err != nil {
		t.Fatal("published history removed")
	}
	if _, err := root.Lstat("closed.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed startup sealed history")
	}
	if _, err := spool.Create(context.Background(), publisher.created.source); err == nil {
		t.Fatal("failed startup history reused")
	}
	endpoint.mu.Lock()
	closed := endpoint.closed
	endpoint.mu.Unlock()
	if !closed {
		t.Fatal("post-publication cancellation leaked endpoint")
	}
}

func TestLineageGenerationSpoolFailureClosesSubscription(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	endpoint, fixture := lineageGenerationFixture(t, nil)
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	spool.Close()
	generation, err := startLineageGeneration(context.Background(), "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
	if generation != nil || err != errLineageGeneration || fixture.versions.Load() != 1 || api.nodeCalls != 4 {
		t.Fatal("failure didn't reach post-check publication")
	}
	endpoint.mu.Lock()
	closed := endpoint.closed
	endpoint.mu.Unlock()
	if !closed {
		t.Fatal("publication failure leaked endpoint")
	}
	if _, err := boot.Read(); err != nil {
		t.Fatal("failure closed borrowed reader")
	}
}

func TestLineageGenerationRetryUsesNewSourceAndCloseUnblocksReceive(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var previous sensoradapter.LineageSource
	for attempt := 0; attempt < 2; attempt++ {
		endpoint, _ := lineageGenerationFixture(t, nil)
		generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
		if err != nil {
			t.Fatal(err)
		}
		if generation.Source().GenerationID == previous.GenerationID {
			t.Fatal("generation identity reused")
		}
		previous = generation.Source()
		done := make(chan error, 1)
		go func() { _, err := generation.subscription.Next(); done <- err }()
		generation.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed receive succeeded")
			}
		case <-ctx.Done():
			t.Fatal("close didn't release receive")
		}
		if ctx.Err() != nil || spool.closed || spool.active != nil {
			t.Fatal("close revoked caller resources")
		}
		root, err := spool.root.OpenRoot("generation-" + previous.GenerationID)
		if err != nil {
			t.Fatal(err)
		}
		_, manifestErr := root.ReadFile("manifest.json")
		_, sealErr := root.Lstat("closed.json")
		root.Close()
		if manifestErr != nil || !errors.Is(sealErr, os.ErrNotExist) {
			t.Fatal("bare close changed persisted termination")
		}
	}
}

func TestLineageGenerationLifetimeSurvivesStartupDeadline(t *testing.T) {
	t.Parallel()
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	endpoint, fixture := lineageGenerationFixture(t, nil)
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	publisher := &lineageGenerationPublishFixture{spool: spool}
	started := time.Now()
	generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, publisher)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	if publisher.context == nil || publisher.context.Err() != context.Canceled {
		t.Fatal("startup context not retired")
	}
	deadline, ok := generation.subscription.context.Deadline()
	want, _ := ctx.Deadline()
	if !ok || deadline != want {
		t.Fatal("startup deadline attached to stream lifetime")
	}
	timer := time.NewTimer(time.Until(started.Add(16 * time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("caller timed out")
	}
	fixture.events <- lineageProviderFixture("exec")
	if _, err := generation.subscription.Next(); err != nil {
		t.Fatal("startup timer canceled admitted stream")
	}
}

type lineageGenerationServer struct {
	*lineageGRPCFixture
	onVersion func()
}

func (server *lineageGenerationServer) GetVersion(ctx context.Context, request *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	if server.onVersion != nil {
		server.onVersion()
	}
	return server.lineageGRPCFixture.GetVersion(ctx, request)
}

func lineageGenerationFixture(t *testing.T, onVersion func()) (*lineageSocket, *lineageGRPCFixture) {
	t.Helper()
	path, listener := lineageSocketFixture(t)
	server := grpc.NewServer()
	fixture := &lineageGRPCFixture{version: "v1.7.0", events: make(chan *tetragon.GetEventsResponse, 8), requests: make(chan *tetragon.GetEventsRequest, 8), headers: make(chan metadata.MD, 2)}
	tetragon.RegisterFineGuidanceSensorsServer(server, &lineageGenerationServer{lineageGRPCFixture: fixture, onVersion: onVersion})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { endpoint.Close() })
	return endpoint, fixture
}

func TestLineageGenerationBracketsUnixSubscriptionWithActualTLSReads(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	identity := newLineageIdentityAPIFixture()
	var calls, atVersion atomic.Int32
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodGet || request.URL.RawQuery != "timeout=5s" || request.Header.Get("Authorization") != "Bearer synthetic-generation-kubernetes" {
			t.Error("unexpected Kubernetes request")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/nodes/node-a":
			json.NewEncoder(w).Encode(identity.node)
		case "/api/v1/namespaces/kube-system":
			json.NewEncoder(w).Encode(identity.namespace)
		default:
			t.Error("unexpected Kubernetes path")
			w.WriteHeader(404)
		}
	}))
	defer httpServer.Close()
	api, err := newLineageKubernetesAPI(&rest.Config{Host: httpServer.URL, BearerToken: "synthetic-generation-kubernetes", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw})}}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	endpoint, fixture := lineageGenerationFixture(t, func() { atVersion.Store(calls.Load()) })
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	source := generation.Source()
	if source.Profile != "tetragon-local-stream-v2" {
		t.Fatal("default production constructor changed source generation")
	}
	if calls.Load() != 8 || atVersion.Load() != 4 || source.NodeName != "node-a" || source.ClusterUID != string(identity.namespace.UID) || source.NodeUID != string(identity.node.UID) || source.BootID != fixtureHostBootID || source.EnrollmentBinding != strings.Repeat("b", 64) || !validLineageUUID(source.GenerationID) || source.GenerationID[14] != '4' || !strings.ContainsRune("89ab", rune(source.GenerationID[19])) {
		t.Fatalf("unbound generation: %#v, calls %d/%d", source, atVersion.Load(), calls.Load())
	}
	manifest, err := generation.storage.root.ReadFile("manifest.json")
	want, wantErr := lineageManifestBytes(source)
	if err != nil || wantErr != nil || !bytes.Equal(manifest, want) {
		t.Fatal("generation returned before manifest publication")
	}
	source.NodeName = "changed"
	if generation.Source().NodeName != "node-a" {
		t.Fatal("mutable source escaped")
	}
	fixture.events <- lineageProviderFixture("exec")
	line, err := generation.subscription.Next()
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := generation.storage.Append(ctx, [][]byte{line})
	if err != nil {
		t.Fatal(err)
	}
	lines, err := readLineageSpoolChunk(generation.storage.root, chunk.Name, generation.Source(), uint32(os.Getuid()))
	if err != nil || len(lines) != 1 || !bytes.Equal(lines[0], line) {
		t.Fatal("actual subscription record not readable in bound generation")
	}
	if err := generation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := generation.Close(); err != nil {
		t.Fatal("close not idempotent")
	}
	if _, err := generation.subscription.Next(); err == nil {
		t.Fatal("closed generation still readable")
	}
	if _, err := generation.storage.Append(ctx, [][]byte{line}); err == nil {
		t.Fatal("closed generation still writable")
	}
	if _, err := boot.Read(); err != nil {
		t.Fatal("generation closed borrowed boot reader")
	}
}

func TestLineageGenerationRejectsIdentityDriftWithoutManifest(t *testing.T) {
	for _, kind := range []string{"node", "cluster", "boot", "cancel", "api-failure"} {
		t.Run(kind, func(t *testing.T) {
			boot, path := fixtureBootReader(t)
			api := newLineageIdentityAPIFixture()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Mutation happens synchronously inside the third namespace read,
			// after GetVersion has completed, avoiding cross-goroutine test races.
			api.onNamespace = func() {
				if api.namespaceCalls != 3 {
					return
				}
				switch kind {
				case "node":
					api.node.UID = types.UID("ffffffff-ffff-4fff-8fff-ffffffffffff")
				case "cluster":
					api.namespace.UID = types.UID("ffffffff-ffff-4fff-8fff-ffffffffffff")
				case "boot":
					writeSensorFixture(t, path, "ffffffff-ffff-4fff-8fff-ffffffffffff\n", 0o600)
					api.node.Status.NodeInfo.BootID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
				case "cancel":
					cancel()
				case "api-failure":
					api.namespace = nil
				}
			}
			endpoint, fixture := lineageGenerationFixture(t, nil)
			parent := t.TempDir()
			spool, err := newLineageSpool(parent, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
			if err != errLineageGeneration || generation != nil {
				t.Fatal("changed identity admitted")
			}
			if fixture.versions.Load() != 1 {
				t.Fatal("failure didn't occur across subscription")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != ".producer.lock" {
				t.Fatal("failed identity published generation")
			}
			endpoint.mu.Lock()
			closed := endpoint.closed
			endpoint.mu.Unlock()
			if !closed {
				t.Fatal("failed generation leaked endpoint")
			}
		})
	}
}

func TestLineageGenerationInvalidInputsFailBeforeNetwork(t *testing.T) {
	for _, kind := range []string{"binding", "node", "boot", "api", "spool", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			boot, _ := fixtureBootReader(t)
			var api lineageIdentityAPI = newLineageIdentityAPIFixture()
			endpoint, fixture := lineageGenerationFixture(t, nil)
			spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			binding, node := strings.Repeat("b", 64), "node-a"
			switch kind {
			case "binding":
				binding = "credential-secret"
			case "node":
				node = "../node-a"
			case "boot":
				boot = nil
			case "api":
				api = (*lineageKubernetesAPI)(nil)
			case "spool":
				spool = nil
			case "canceled":
				cancel()
			}
			generation, err := startLineageGeneration(ctx, node, binding, api, boot, endpoint, spool)
			if generation != nil || err != errLineageGeneration || fixture.versions.Load() != 0 {
				t.Fatal("invalid startup touched source")
			}
			endpoint.mu.Lock()
			closed := endpoint.closed
			endpoint.mu.Unlock()
			if !closed {
				t.Fatal("invalid startup leaked endpoint")
			}
		})
	}
}
