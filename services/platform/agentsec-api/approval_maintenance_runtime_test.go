package main

import (
	"bytes"
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApprovalMaintenanceRuntimeConfigurationClosed(t *testing.T) {
	base := fixtureRuntimeConfig()
	if !validApprovalMaintenanceRuntimeConfig(base) {
		t.Fatal("original unconfigured path changed")
	}
	base.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "development", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-dev", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/tmp/test-fga-token", Timeout: time.Second, ApprovalMaintenanceProfileChecksum: strings.Repeat("a", 64)}
	base.ApprovalMaintenanceKeyFile = "/var/run/zasp/approval-key"
	base.ApprovalMaintenancePostgresDSN = "postgres://zasp_approval_delivery@db.internal:5432/zasp?sslmode=require"
	if !validApprovalMaintenanceRuntimeConfig(base) {
		t.Fatal("explicit restricted same database profile refused")
	}
	cases := map[string]func(*RuntimeConfig){"missing-key": func(c *RuntimeConfig) { c.ApprovalMaintenanceKeyFile = "" }, "relative-key": func(c *RuntimeConfig) { c.ApprovalMaintenanceKeyFile = "key" }, "unclean-key": func(c *RuntimeConfig) { c.ApprovalMaintenanceKeyFile = "/var/run/zasp/../key" }, "missing-dsn": func(c *RuntimeConfig) { c.ApprovalMaintenancePostgresDSN = "" }, "api-login": func(c *RuntimeConfig) { c.ApprovalMaintenancePostgresDSN = c.SecurityAgentPostgresDSN }, "other-db": func(c *RuntimeConfig) {
		c.ApprovalMaintenancePostgresDSN = strings.Replace(c.ApprovalMaintenancePostgresDSN, "/zasp?", "/other?", 1)
	}, "transport-override": func(c *RuntimeConfig) {
		c.ApprovalMaintenancePostgresDSN = strings.Replace(c.ApprovalMaintenancePostgresDSN, "require", "disable", 1)
	}, "no-pin": func(c *RuntimeConfig) { c.RuntimeServices.ApprovalMaintenanceProfileChecksum = "" }, "disabled": func(c *RuntimeConfig) { c.RuntimeServices.Enabled = false }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if validApprovalMaintenanceRuntimeConfig(c) {
				t.Fatal("partial or mismatched authority accepted")
			}
		})
	}
}
func TestApprovalMaintenanceVerifierKeyAdmission(t *testing.T) {
	seed := bytes.Repeat([]byte{0xa5}, 32)
	makeFile := func(name string, body []byte, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, body, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := makeFile("key", seed, 0400)
	got, err := loadApprovalMaintenanceKey(p)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatal("bounded exact verifier refused")
	}
	clear(got)
	bad := []string{makeFile("short", seed[:31], 0400), makeFile("long", append(append([]byte{}, seed...), 1), 0400), makeFile("writable", seed, 0600), t.TempDir(), "relative-key"}
	symlink := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(p, symlink); err != nil {
		t.Fatal(err)
	}
	bad = append(bad, symlink)
	hardlink := filepath.Join(t.TempDir(), "hardlink")
	if err := os.Link(p, hardlink); err != nil {
		t.Fatal(err)
	}
	bad = append(bad, p, hardlink)
	for _, path := range bad {
		if key, err := loadApprovalMaintenanceKey(path); err == nil || key != nil {
			clear(key)
			t.Fatal("unsafe verifier input admitted")
		}
	}
}
func TestApprovalMaintenanceRuntimeRefusesMissingLiveAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []RuntimeConfig{fixtureRuntimeConfig(), {}} {
		r, closer, err := newRuntimeApprovalMaintenance(ctx, c, nil, nil, nil, "fixture-owner")
		if err == nil || r != nil || closer != nil {
			t.Fatal("unconfigured canceled input fabricated native readiness")
		}
	}
}

type approvalLifecycleFixture struct {
	ready bool
	runs  int
}

func (f *approvalLifecycleFixture) Run(context.Context) error { f.runs++; return nil }
func (f *approvalLifecycleFixture) Ready() bool               { return f.ready }

type approvalCloserFixture struct{ closed int }

func (f *approvalCloserFixture) Close() error { f.closed++; return nil }
func configuredApprovalRuntimeFixture() RuntimeConfig {
	c := fixtureRuntimeConfig()
	c.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "development", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-dev", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/tmp/test-fga-token", Timeout: time.Second, ApprovalMaintenanceProfileChecksum: strings.Repeat("a", 64)}
	c.ApprovalMaintenanceKeyFile = "/var/run/zasp/approval-key"
	c.ApprovalMaintenancePostgresDSN = "postgres://zasp_approval_delivery@db.internal:5432/zasp?sslmode=require"
	return c
}

// These own runtime composition controls assert branch/cleanup behavior, not
// native authority. Real inactive caller refusal has its separate PG test.
func TestApprovalNotificationRuntimeSelectionPreservesBoundaries(t *testing.T) {
	for _, configured := range []bool{false, true} {
		c := fixtureRuntimeConfig()
		if configured {
			c = configuredApprovalRuntimeFixture()
		}
		native := &approvalLifecycleFixture{ready: true}
		legacy := &approvalLifecycleFixture{ready: true}
		nativeCalls, legacyCalls := 0, 0
		r, closer, err := selectApprovalNotificationLifecycle(c, func() (approvalNotificationLifecycle, io.Closer, error) { nativeCalls++; return native, nil, nil }, func() (approvalNotificationLifecycle, io.Closer, error) { legacyCalls++; return legacy, nil, nil })
		if err != nil || closer != nil {
			t.Fatal("valid selection refused")
		}
		if err := r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if configured && (nativeCalls != 1 || legacyCalls != 0 || native.runs != 1 || legacy.runs != 0) || !configured && (nativeCalls != 0 || legacyCalls != 1 || native.runs != 0 || legacy.runs != 1) {
			t.Fatal("old claims selected in native path or original path changed")
		}
		metadataCalls := 0
		if err := approvalNotificationLifecycleReady(context.Background(), func(context.Context) error { metadataCalls++; return nil }, r); err != nil || metadataCalls != 1 {
			t.Fatal("original metadata omitted")
		}
		if err := approvalNotificationLifecycleReady(context.Background(), func(context.Context) error { metadataCalls++; return errRuntimeUnavailable }, r); err == nil || metadataCalls != 2 {
			t.Fatal("original metadata refusal bypassed")
		}
	}
}
func TestApprovalNotificationNativeFailureNeverFallsBack(t *testing.T) {
	c := configuredApprovalRuntimeFixture()
	legacyCalls := 0
	closer := &approvalCloserFixture{}
	r, owned, err := selectApprovalNotificationLifecycle(c, func() (approvalNotificationLifecycle, io.Closer, error) { return nil, closer, errRuntimeUnavailable }, func() (approvalNotificationLifecycle, io.Closer, error) {
		legacyCalls++
		return &approvalLifecycleFixture{ready: true}, nil, nil
	})
	if err == nil || r != nil || owned != nil || legacyCalls != 0 || closer.closed != 1 {
		t.Fatal("inactive native failure fell back or leaked resources")
	}
	c.ApprovalMaintenanceKeyFile = ""
	calls := 0
	factory := func() (approvalNotificationLifecycle, io.Closer, error) {
		calls++
		return &approvalLifecycleFixture{ready: true}, nil, nil
	}
	if r, owned, err := selectApprovalNotificationLifecycle(c, factory, factory); err == nil || r != nil || owned != nil || calls != 0 {
		t.Fatal("partial profile reached either constructor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metadata := 0
	if approvalNotificationLifecycleReady(ctx, func(context.Context) error { metadata++; return nil }, &approvalLifecycleFixture{ready: true}) == nil || metadata != 0 {
		t.Fatal("canceled readiness read metadata")
	}
	if approvalNotificationLifecycleReady(context.Background(), func(context.Context) error { return nil }, &approvalLifecycleFixture{}) == nil {
		t.Fatal("native worker not ready bypassed")
	}
}
