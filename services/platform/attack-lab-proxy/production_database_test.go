package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestProxyDatabaseSupportsConcurrentReadinessAndInvocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := connectProxyDatabase(ctx, startProxyPostgres(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	database := proxyPostgresDatabase{connection: connection}
	start := make(chan struct{})
	failures := make(chan error, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			body, err := database.QueryJSON(ctx, "SELECT to_jsonb(true) FROM pg_sleep(0.03)")
			if err != nil {
				failures <- err
			} else if string(body) != "true" {
				failures <- fmt.Errorf("invalid result")
			}
		}()
	}
	close(start)
	group.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("concurrent query: %v", err)
	}
	if connection.Config().MaxConns != 8 {
		t.Fatal("proxy pool is not bounded")
	}
	var release []func()
	defer func() {
		for _, done := range release {
			done()
		}
	}()
	for range 8 {
		acquired, err := connection.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		release = append(release, acquired.Release)
	}
	bounded, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	defer stop()
	if _, err := database.QueryJSON(bounded, "SELECT to_jsonb(true)"); err == nil || bounded.Err() == nil {
		t.Fatalf("pool wait ignored request deadline: %v", err)
	}
}

func TestProductionProxyHandlerBoundsDatabaseWorkAndShutdown(t *testing.T) {
	connection, err := connectProxyDatabase(context.Background(), startProxyPostgres(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for _, mode := range []string{"deadline", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, returned := make(chan struct{}), make(chan error, 1)
			database := proxyPostgresDatabase{connection: connection}
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				close(entered)
				_, err := database.QueryJSON(request.Context(), "SELECT to_jsonb(true) FROM pg_sleep(30)")
				returned <- err
			})
			timeout := 50 * time.Millisecond
			if mode == "shutdown" {
				timeout = 30 * time.Second
			}
			server := newProxyHTTPServer(ctx, runtimeConfig{RequestTimeout: timeout}, handler)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go server.Serve(listener)
			client := &http.Client{Timeout: 2 * time.Second}
			go func() {
				response, err := client.Get("http://" + listener.Addr().String())
				if err == nil {
					response.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("handler did not start")
			}
			if mode == "shutdown" {
				cancel()
			}
			select {
			case err := <-returned:
				if err == nil {
					t.Error("blocked query unexpectedly succeeded")
				}
			case <-time.After(500 * time.Millisecond):
				t.Error("production handler did not cancel database work")
			}
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := server.Shutdown(bounded); err != nil {
				t.Errorf("bounded shutdown: %v", err)
			}
		})
	}
}

func startProxyPostgres(t *testing.T, username string) string {
	t.Helper()
	if username != "zasp_test" && username != "zasp_e2e" {
		t.Fatal("unsupported disposable PostgreSQL owner")
	}
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	pgIsReady, readyErr := exec.LookPath("pg_isready")
	pgCtl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		lookupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if output, err := exec.CommandContext(lookupCtx, "pg_config", "--bindir").Output(); err == nil {
			bin := string(bytes.TrimSpace(output))
			if filepath.IsAbs(bin) {
				initdb, initErr = exec.LookPath(filepath.Join(bin, "initdb"))
				postgres, postgresErr = exec.LookPath(filepath.Join(bin, "postgres"))
				pgIsReady, readyErr = exec.LookPath(filepath.Join(bin, "pg_isready"))
				pgCtl, ctlErr = exec.LookPath(filepath.Join(bin, "pg_ctl"))
			}
		}
	}
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI requires local PostgreSQL acceptance, not a skip")
		}
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username="+username, "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		stop := exec.Command(pgCtl, "-D", data, "-m", "fast", "-w", "stop")
		if err := stop.Run(); err != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		stopped = true
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if exec.Command(pgIsReady, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", username, "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", username, port)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}
