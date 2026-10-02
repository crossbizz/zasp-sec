package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestObserverValidateOnlyCommandDoesNotReadCredentialsOrConnect(t *testing.T) {
	if os.Getenv("ZASP_OBSERVER_VALIDATE_CHILD") == "1" {
		os.Args = []string{"discovery-observe", "--validate-config"}
		main()
		os.Exit(0)
	}
	c := observerRequest().Config
	c.Environment = "production"
	c.TemporalAddress = "temporal.internal:7233"
	c.FGAURL = "https://fga.internal"
	c.TemporalCAFile = "/not-present/ca"
	c.TemporalCertFile = "/not-present/cert"
	c.TemporalKeyFile = "/not-present/key"
	for _, tc := range []struct {
		address, url string
		valid        bool
	}{{"temporal.internal:7233", "https://fga.internal", true}, {"temporal.example.com:7233", "https://fga.internal", false}, {"https://temporal.internal:7233", "https://fga.internal", false}, {"temporal.internal:7233", "https://fga.example.com", false}, {"temporal.internal:07233", "https://fga.internal", false}} {
		c.TemporalAddress = tc.address
		c.FGAURL = tc.url
		data, _ := json.Marshal(map[string]any{"format": "zasp-discovery-config-validation-v1", "config": c})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		binary, _ := os.Executable()
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestObserverValidateOnlyCommandDoesNotReadCredentialsOrConnect$")
		cmd.Env = []string{"ZASP_OBSERVER_VALIDATE_CHILD=1"}
		cmd.Stdin = bytes.NewReader(data)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		cancel()
		if tc.valid {
			if err != nil || stdout.String() != "{\"format\":\"zasp-discovery-config-validation-v1\",\"valid\":true}\n" || stderr.Len() != 0 {
				t.Fatal("valid config did not complete validate-only without external dependencies")
			}
		} else if err == nil || stdout.Len() != 0 || stderr.String() != "discovery observation refused\n" {
			t.Fatal("invalid endpoint config accepted or raw error leaked")
		}
	}
}

func TestObserverInputRejectsUnknownTrailingOversizeAndInvalidAuthority(t *testing.T) {
	valid, _ := json.Marshal(observerRequest())
	for _, data := range [][]byte{
		[]byte(`{"format":"canary-secret","unknown":true}`),
		append(append([]byte{}, valid...), []byte(` {}`)...),
		[]byte(strings.Repeat(" ", 16385)),
		bytes.Replace(valid, []byte(`"kind":"schedule"`), []byte(`"kind":"delete"`), 1),
		bytes.Replace(valid, []byte(`"revision":2`), []byte(`"revision":0`), 1),
	} {
		if _, err := readRequest(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid command input accepted")
		}
	}
	q, err := readRequest(bytes.NewReader(valid))
	if err != nil || q.Ref != observerRequest().Ref {
		t.Fatal("valid bounded command input refused")
	}
}
func TestObserverInputReaderDoesNotConsumeUnboundedStream(t *testing.T) {
	r := &countingInput{}
	if _, err := readRequest(r); err == nil {
		t.Fatal("oversize input accepted")
	}
	if r.n > 16385 {
		t.Fatal("input capture exceeds fixed bound")
	}
}

type countingInput struct{ n int }

func (r *countingInput) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.n += len(p)
	if r.n > 100000 {
		return 0, io.EOF
	}
	return len(p), nil
}
