package apiserver

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestDisposablePostgresCleanupOutcomes(t *testing.T) {
	// These real, short-lived commands isolate discarded stop/Wait results;
	// the two PostgreSQL parents supply the actual server-shutdown coverage.
	for _, tc := range []struct {
		name, server, stop string
		wantStop, wantWait bool
	}{
		{"normal exit", "exit 0", "exit 0", false, false},
		{"failed stop requires fallback kill", "exec sleep 30", "exit 9", true, true},
		{"failed server exit", "exit 7", "exit 0", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("/bin/sh", "-c", tc.server)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			err := stopDisposablePostgres(command, exec.Command("/bin/sh", "-c", tc.stop))
			if command.ProcessState == nil {
				t.Fatal("owned server was not reaped")
			}
			if tc.wantStop || tc.wantWait {
				if err == nil {
					t.Fatal("failed PostgreSQL cleanup was accepted as normal exit")
				}
				if tc.wantStop && !strings.Contains(err.Error(), "pg_ctl=exit status 9") {
					t.Fatal("stop failure missing from cleanup result", err)
				}
				if tc.wantWait && strings.Contains(err.Error(), "wait=<nil>") {
					t.Fatal("failed server Wait missing from cleanup result", err)
				}
			} else if err != nil || !command.ProcessState.Success() {
				t.Fatal("normal stop and server exit rejected", err)
			}
		})
	}
}

func TestDisposablePostgresCleanupObservationIsAvailableOnlyAfterNormalJoin(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	observation, err := stopDisposablePostgresObserved(command, exec.Command("/bin/sh", "-c", "exit 0"), "")
	if err != nil || observation.Available || observation.EndpointChecked || observation.SurvivingResourcesChecked {
		t.Fatal("empty endpoint exposed structured cleanup evidence", observation, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	command = exec.Command("/bin/sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	observation, err = stopDisposablePostgresObserved(command, exec.Command("/bin/sh", "-c", "exit 0"), endpoint)
	if err != nil || !observation.Available || !observation.PGCtlStopped || !observation.CommandWaitJoined || !observation.NormalExit || !observation.EndpointChecked || observation.EndpointSHA256 == "" || !observation.SurvivingResourcesChecked || observation.SurvivingResources != 0 {
		t.Fatal("normal joined endpoint cleanup observation refused", observation, err)
	}
	failed := exec.Command("/bin/sh", "-c", "exit 7")
	if err := failed.Start(); err != nil {
		t.Fatal(err)
	}
	observation, err = stopDisposablePostgresObserved(failed, exec.Command("/bin/sh", "-c", "exit 0"), "")
	if err == nil || observation.Available {
		t.Fatal("failed server exit exposed cleanup evidence", observation, err)
	}
}

func TestDisposablePostgresCleanupObservationRegistrationIsTestScoped(t *testing.T) {
	var key *testing.T
	t.Run("scope", func(t *testing.T) {
		key = t
		registerDisposablePostgresCleanupObservation(t, &disposablePostgresCleanupObservation{})
		if _, ok := disposablePostgresCleanupObservers.Load(t); !ok {
			t.Fatal("test-scoped cleanup observer missing")
		}
	})
	if _, ok := disposablePostgresCleanupObservers.Load(key); ok {
		t.Fatal("stale cleanup observer survived test cleanup")
	}
}
