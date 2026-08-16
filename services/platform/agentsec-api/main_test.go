package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

var testHTTPClient = &http.Client{Timeout: 250 * time.Millisecond}

func TestRunPrintsExactBuildVersion(t *testing.T) {
	t.Parallel()

	for _, version := range []string{
		"dev",
		"0.1.0-test.1",
		"A_b+c.d-9",
		strings.Repeat("a", 64),
	} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			if err := run(&output, version); err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if got, want := output.String(), "agentsec-api build "+version+"\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestRunRejectsInvalidBuildVersionWithoutOutput(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		".1.0.0",
		"-dev",
		" dev",
		"dev ",
		"dev build",
		"dev\nnext",
		"dev\rnext",
		"dev/path",
		"dévelop",
		"dev\x00next",
		strings.Repeat("a", 65),
	}
	for _, version := range invalid {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			if err := run(&output, version); !errors.Is(err, errInvalidBuildVersion) {
				t.Fatalf("run() error = %v, want errInvalidBuildVersion", err)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
}

func TestRunReturnsWriterFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("write failed")
	if err := run(errorWriter{err: want}, "dev"); !errors.Is(err, want) {
		t.Fatalf("run() error = %v, want %v", err, want)
	}
}

func TestRunRejectsNilWriter(t *testing.T) {
	t.Parallel()

	if err := run(nil, "dev"); !errors.Is(err, errOutputUnavailable) {
		t.Fatalf("run() error = %v, want errOutputUnavailable", err)
	}
}

func TestDefaultBuildVersion(t *testing.T) {
	t.Parallel()

	if buildVersion != "dev" {
		t.Fatalf("buildVersion = %q, want dev", buildVersion)
	}
}

func TestServeProcessExposesExactHealthEndpoints(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	listeners := make(chan net.Listener, 1)
	listen := func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != healthListenAddress {
			t.Fatalf("listen = (%q, %q), want (tcp, %s)", network, address, healthListenAddress)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listeners <- listener
		}
		return listener, err
	}
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { result <- serveProcess(ctx, &output, "1.2.3-test", listen) }()
	listener := <-listeners
	baseURL := "http://" + listener.Addr().String()
	waitForReady(t, baseURL)
	assertEndpoint(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertEndpoint(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertEndpoint(t, baseURL+"/version", http.StatusOK, "{\"service\":\"agentsec-api\",\"version\":\"1.2.3-test\"}\n")
	assertContains(t, baseURL+"/metrics", "agentsec_build_info{service=\"agentsec-api\",version=\"1.2.3-test\"} 1\n")
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveProcess() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveProcess() did not terminate")
	}
	if got, want := output.String(), "agentsec-api build 1.2.3-test\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestServeProcessFailsBeforeOrClosesListener(t *testing.T) {
	t.Parallel()

	t.Run("invalid before listen", func(t *testing.T) {
		calls := 0
		listen := func(string, string) (net.Listener, error) {
			calls++
			return &commandListener{}, nil
		}
		var output bytes.Buffer
		if err := serveProcess(context.Background(), &output, " bad", listen); !errors.Is(err, errInvalidBuildVersion) {
			t.Fatalf("serveProcess() error = %v, want errInvalidBuildVersion", err)
		}
		if calls != 0 || output.Len() != 0 {
			t.Fatalf("calls/output = (%d, %q), want zero", calls, output.String())
		}
	})

	t.Run("canceled before listen", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		listen := func(string, string) (net.Listener, error) {
			calls++
			return &commandListener{}, nil
		}
		var output bytes.Buffer
		if err := serveProcess(ctx, &output, "dev", listen); err != nil {
			t.Fatalf("serveProcess() error = %v", err)
		}
		if calls != 0 || output.Len() != 0 {
			t.Fatalf("calls/output = (%d, %q), want zero", calls, output.String())
		}
	})

	t.Run("listen failure", func(t *testing.T) {
		want := errors.New("listen failed")
		listen := func(string, string) (net.Listener, error) { return nil, want }
		var output bytes.Buffer
		if err := serveProcess(context.Background(), &output, "dev", listen); !errors.Is(err, want) {
			t.Fatalf("serveProcess() error = %v, want %v", err, want)
		}
		if output.Len() != 0 {
			t.Fatalf("output = %q, want empty", output.String())
		}
	})

	t.Run("listen failure closes returned candidate", func(t *testing.T) {
		listener := &commandListener{}
		want := errors.New("listen failed")
		listen := func(string, string) (net.Listener, error) { return listener, want }
		if err := serveProcess(context.Background(), &bytes.Buffer{}, "dev", listen); !errors.Is(err, want) {
			t.Fatalf("serveProcess() error = %v, want %v", err, want)
		}
		if listener.closes != 1 {
			t.Fatalf("listener closes = %d, want 1", listener.closes)
		}
	})

	t.Run("cleanup failure wins listen failure", func(t *testing.T) {
		listener := &commandListener{closeErr: errors.New("close failed")}
		listen := func(string, string) (net.Listener, error) { return listener, errors.New("listen failed") }
		if err := serveProcess(context.Background(), &bytes.Buffer{}, "dev", listen); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("serveProcess() error = %v, want errRuntimeUnavailable", err)
		}
	})

	t.Run("writer failure closes listener", func(t *testing.T) {
		listener := &commandListener{}
		listen := func(string, string) (net.Listener, error) { return listener, nil }
		want := errors.New("write failed")
		if err := serveProcess(context.Background(), errorWriter{err: want}, "dev", listen); !errors.Is(err, want) {
			t.Fatalf("serveProcess() error = %v, want %v", err, want)
		}
		if listener.closes != 1 {
			t.Fatalf("listener closes = %d, want 1", listener.closes)
		}
	})

	t.Run("writer panic closes listener", func(t *testing.T) {
		listener := &commandListener{}
		listen := func(string, string) (net.Listener, error) { return listener, nil }
		if err := serveProcess(context.Background(), panicWriter{}, "dev", listen); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("serveProcess() error = %v, want errRuntimeUnavailable", err)
		}
		if listener.closes != 1 {
			t.Fatalf("listener closes = %d, want 1", listener.closes)
		}
	})
}

func waitForReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := testHTTPClient.Get(baseURL + "/readyz") // #nosec G107 -- owned numeric-loopback test listener.
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("health server did not become ready")
}

func assertEndpoint(t *testing.T, target string, status int, body string) {
	t.Helper()
	response, err := testHTTPClient.Get(target) // #nosec G107 -- owned numeric-loopback test listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	if response.StatusCode != status || string(value) != body {
		t.Fatalf("GET %s = (%d, %q), want (%d, %q)", target, response.StatusCode, value, status, body)
	}
}

func assertContains(t *testing.T, target, fragment string) {
	t.Helper()
	response, err := testHTTPClient.Get(target) // #nosec G107 -- owned numeric-loopback test listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(value), fragment) {
		t.Fatalf("GET %s = (%d, %q), want status 200 containing %q", target, response.StatusCode, value, fragment)
	}
}

type errorWriter struct {
	err error
}

type panicWriter struct{}

type commandListener struct {
	closes   int
	closeErr error
}

func (*commandListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (listener *commandListener) Close() error {
	listener.closes++
	return listener.closeErr
}
func (*commandListener) Addr() net.Addr { return commandAddress("127.0.0.1:0") }

type commandAddress string

func (commandAddress) Network() string        { return "tcp" }
func (address commandAddress) String() string { return string(address) }

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func (panicWriter) Write([]byte) (int, error) {
	panic("sensitive writer panic")
}
