// Package cliauth pairs one zaspctl process with an explicit browser approval.
package cliauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/browserlink"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var idPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var codePattern = regexp.MustCompile(`^[0-9a-f]{8}$`)
var proofPattern = regexp.MustCompile(`^[0-9]{1,12}\.[A-Za-z0-9_-]{43}$`)
var tokenPattern = regexp.MustCompile(`^zasp_cli_[A-Za-z0-9_-]{43}$`)

var errStore = errors.New("OS credential store unavailable or session expired")
var errLogin = errors.New("login was unavailable or expired")

type grant struct {
	Token       string    `json:"access_token"`
	Type        string    `json:"token_type"`
	Environment string    `json:"environment_id"`
	Expires     time.Time `json:"expires_at"`
	Scope       string    `json:"scope"`
}

func (g grant) valid(env string, now time.Time) bool {
	return g.Type == "Bearer" && g.Scope == "submit_addon_scans" && env == g.Environment &&
		tokenPattern.MatchString(g.Token) && now.Before(g.Expires) && !g.Expires.After(now.Add(16*time.Minute))
}

func Token(apiOrigin, environment string) (string, error) {
	host, ok := browserlink.Origin(apiOrigin)
	if !ok || !idPattern.MatchString(environment) {
		return "", errStore
	}
	data, err := readSecret(host, environment)
	var g grant
	if err != nil || len(data) > 2048 || json.Unmarshal(data, &g) != nil || !g.valid(environment, time.Now()) {
		return "", errStore
	}
	return g.Token, nil
}

type loginFlow struct {
	client  *http.Client
	wait    time.Duration
	present func(string, string)
	save    func(string, string, []byte) error
}

func Login(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("auth login", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	environment := flags.String("environment", "", "Zasp Environment ID")
	noOpen := flags.Bool("no-open", false, "print the URL without opening a browser")
	host, ok := browserlink.Origin(os.Getenv("ZASP_API_URL"))
	if flags.Parse(args) != nil || flags.NArg() != 0 || !ok || !idPattern.MatchString(*environment) {
		fmt.Fprintln(stderr, "Set ZASP_API_URL to the HTTPS deployment origin and supply --environment ID. Use --no-open to open the link manually.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	flow := loginFlow{
		client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		wait:   2 * time.Second,
		present: func(link, code string) {
			fmt.Fprintf(stdout, "Open this link and enter the code from this terminal.\n%s\nCode: %s\n", link, code)
			if !*noOpen {
				browserlink.Open(link)
			}
		},
		save: writeSecret,
	}
	if err := flow.execute(ctx, host, *environment); err != nil {
		if errors.Is(err, errStore) {
			fmt.Fprintln(stderr, "The operating system could not save the session. Unlock or configure your credential store, then sign in again.")
		} else {
			fmt.Fprintln(stderr, "Sign-in could not be completed. Check the Environment, approve the request before it expires and retry.")
		}
		return 3
	}
	fmt.Fprintln(stdout, "Signed in for findings-only submission to", *environment)
	return 0
}

func (flow loginFlow) execute(ctx context.Context, host, env string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return errLogin
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	var start struct {
		ID      string    `json:"request_id"`
		Proof   string    `json:"request_proof"`
		Code    string    `json:"comparison_code"`
		Expires time.Time `json:"expires_at"`
	}
	status, err := flow.post(ctx, host+"/api/v1/cli/auth/start", map[string]string{
		"client_id": "zaspctl", "environment_id": env, "code_challenge_method": "S256", "code_challenge": challenge,
	}, &start)
	if err != nil || status != 200 || !idPattern.MatchString(start.ID) || !proofPattern.MatchString(start.Proof) ||
		!codePattern.MatchString(start.Code) || !time.Now().Before(start.Expires) || start.Expires.After(time.Now().Add(11*time.Minute)) {
		return errLogin
	}
	proofExpiry, _ := strconv.ParseInt(strings.SplitN(start.Proof, ".", 2)[0], 10, 64)
	if start.Expires.Unix() != proofExpiry {
		return errLogin
	}
	fragment := url.Values{"request_id": {start.ID}, "request_proof": {start.Proof}, "environment_id": {env}, "code_challenge": {challenge}}
	flow.present(host+"/cli/authorize#"+fragment.Encode(), start.Code)
	limited, cancel := context.WithDeadline(ctx, start.Expires)
	defer cancel()
	for {
		timer := time.NewTimer(flow.wait)
		select {
		case <-limited.Done():
			timer.Stop()
			return errLogin
		case <-timer.C:
		}
		var g grant
		status, err := flow.post(limited, host+"/api/v1/cli/auth/exchange", map[string]string{
			"client_id": "zaspctl", "environment_id": env, "request_id": start.ID, "code_verifier": verifier,
		}, &g)
		if err != nil {
			return errLogin
		}
		if status == 409 {
			continue
		}
		if status != 200 || !g.valid(env, time.Now()) {
			return errLogin
		}
		body, err := json.Marshal(g)
		if err != nil || flow.save(host, env, body) != nil {
			return errStore
		}
		return nil
	}
}

func (flow loginFlow) post(ctx context.Context, address string, body map[string]string, out any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, errLogin
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(payload))
	if err != nil {
		return 0, errLogin
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := flow.client.Do(req)
	if err != nil {
		return 0, errLogin
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(data) > 8192 || json.Unmarshal(data, out) != nil {
		return 0, errLogin
	}
	return resp.StatusCode, nil
}
