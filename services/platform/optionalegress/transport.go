package optionalegress

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"math/big"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// Resolver returns an owned credential copy for this exact scope/profile. The
// sender clears it after the one request and never returns raw transport errors.
type CredentialResolver interface {
	ResolveOptionalCredential(context.Context, Binding, Profile) ([]byte, error)
}
type SenderConfig struct {
	Resolver  CredentialResolver
	Transport http.RoundTripper
	Now       func() time.Time
}
type OpenRouterSender struct {
	resolver CredentialResolver
	client   *http.Client
	now      func() time.Time
	owned    *http.Transport
	closed   atomic.Bool
}

var amountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})(\.[0-9]{1,18})?([eE][+-]?(0|[1-9][0-9]?))?$`)

func validBearer(v []byte) bool {
	if len(v) < 16 || len(v) > 4096 {
		return false
	}
	for _, b := range v {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func NewOpenRouterSender(c SenderConfig) (*OpenRouterSender, error) {
	if nilValue(c.Resolver) || c.Now == nil {
		return nil, ErrInvalid
	}
	transport := c.Transport
	var ownedTransport *http.Transport
	if nilValue(transport) {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, ErrInvalid
		}
		owned := base.Clone()
		owned.MaxConnsPerHost = 100
		owned.MaxIdleConnsPerHost = 10
		owned.ResponseHeaderTimeout = 30 * time.Second
		transport = owned
		ownedTransport = owned
	}
	return &OpenRouterSender{resolver: c.Resolver, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: c.Now, owned: ownedTransport}, nil
}

// Close rejects new sends and closes only this sender's owned idle transport.
// The API runtime must drain its active requests first. This does not prove a
// remote provider has stopped processing an already admitted request.
func (s *OpenRouterSender) Close() error {
	if s == nil {
		return nil
	}
	s.closed.Store(true)
	if s.owned != nil {
		s.owned.CloseIdleConnections()
	}
	return nil
}

func (s *OpenRouterSender) Send(ctx context.Context, p *Prepared, claim Claim) (out SendOutcome) {
	out = SendOutcome{State: Unknown, FailureCode: "provider_contract"}
	defer func() {
		if recover() != nil {
			out = SendOutcome{State: Unknown, FailureCode: "provider_contract"}
		}
	}()
	if s == nil || s.closed.Load() || s.client == nil || ctx == nil || ctx.Err() != nil || p == nil || claim.Binding != p.binding || !noncePattern.MatchString(claim.Nonce) || !validBinding(claim.Binding, claim.Intent) {
		return out
	}
	deadline, ok := canonicalTime(p.binding.Deadline)
	if !ok || !deadline.After(s.now()) || !p.consumed.CompareAndSwap(false, true) {
		return out
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	token, e := s.resolver.ResolveOptionalCredential(bounded, p.binding, p.profile)
	if e != nil {
		clear(token)
		out.FailureCode = "credential_unavailable"
		return out
	}
	defer clear(token)
	if !validBearer(token) || subtle.ConstantTimeCompare([]byte(digest(token)), []byte(p.binding.CredentialDigest)) != 1 || bounded.Err() != nil {
		out.FailureCode = "credential_unavailable"
		return out
	}
	request, e := http.NewRequestWithContext(bounded, http.MethodPost, openRouterEndpoint, bytes.NewReader(p.body))
	if e != nil {
		return out
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("X-Zasp-Data-Policy", p.profile.PolicyVersion)
	request.Header.Set("X-OpenRouter-Metadata", "enabled")
	response, e := s.client.Do(request)
	if e != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		out.FailureCode = "provider_transport"
		return out
	}
	if response.Body == nil {
		return out
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	closeErr := response.Body.Close()
	if e != nil || closeErr != nil || bounded.Err() != nil {
		out.FailureCode = "provider_transport"
		return out
	}
	if len(body) > maximumResponseBytes || len(body) == 0 {
		return out
	}
	out.ResultDigest = digest(body)
	if response.StatusCode != http.StatusOK {
		out.FailureCode = "provider_status"
		return out
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return out
	}
	result, usage, e := parseResponse(body, p)
	if e != nil {
		return out
	}
	out.State = Complete
	out.FailureCode = ""
	out.Result = result
	out.Usage = usage
	return out
}

func validText(s string) bool {
	if len(s) < 1 || len(s) > 2048 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

// uniqueJSON rejects duplicate keys at every depth before normal decoding can
// collapse them. Only bounded JSON is accepted; no raw errors escape this package.
func uniqueJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maximumResponseBytes || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		v, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				seen[s] = true
				if !value(depth + 1) {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim(']')
		}
		return false
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func parseResponse(raw []byte, p *Prepared) (*TransientExplanation, *Usage, error) {
	if !uniqueJSON(raw) {
		return nil, nil, ErrUnavailable
	}
	var response struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Object   string `json:"object"`
		Metadata struct {
			Attempts []struct {
				Model    string `json:"model"`
				Provider string `json:"provider"`
				Status   int    `json:"status"`
			} `json:"attempts"`
		} `json:"openrouter_metadata"`
		Choices []struct {
			Index        int    `json:"index"`
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role      string            `json:"role"`
				Content   string            `json:"content"`
				Refusal   json.RawMessage   `json:"refusal"`
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Input  json.Number `json:"prompt_tokens"`
			Output json.Number `json:"completion_tokens"`
			Total  json.Number `json:"total_tokens"`
			Cost   json.Number `json:"cost"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &response) != nil || !wordPattern.MatchString(response.ID) || (response.Provider != "" && response.Provider != p.profile.Backend) || response.Model != p.profile.Model || response.Object != "chat.completion" || len(response.Choices) != 1 {
		return nil, nil, ErrUnavailable
	}
	// The documented ChatResult has no mandatory top-level provider. Routing
	// metadata is explicitly requested and supplies the actual provider/model
	// attempt. Missing or foreign routing evidence is uncertainty, not a match.
	if len(response.Metadata.Attempts) != 1 {
		return nil, nil, ErrUnavailable
	}
	attempt := response.Metadata.Attempts[0]
	if attempt.Provider != p.profile.Backend || attempt.Model != p.profile.Model || attempt.Status != http.StatusOK {
		return nil, nil, ErrUnavailable
	}
	c := response.Choices[0]
	if c.Index != 0 || c.FinishReason != "stop" || c.Message.Role != "assistant" || len(c.Message.Content) > 8192 || len(c.Message.ToolCalls) != 0 || (len(c.Message.Refusal) != 0 && string(c.Message.Refusal) != "null") {
		return nil, nil, ErrUnavailable
	}
	content := []byte(c.Message.Content)
	if !uniqueJSON(content) {
		return nil, nil, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(content, &fields) != nil || len(fields) != 2 || fields["explanation"] == nil || fields["recommendation"] == nil {
		return nil, nil, ErrUnavailable
	}
	var result TransientExplanation
	if json.Unmarshal(content, &result) != nil || !validText(result.Explanation) || !validText(result.Recommendation) {
		return nil, nil, ErrUnavailable
	}
	input, e1 := response.Usage.Input.Int64()
	output, e2 := response.Usage.Output.Int64()
	total, e3 := response.Usage.Total.Int64()
	if e1 != nil || e2 != nil || e3 != nil || input < 0 || input > p.binding.InputTokenBound || output < 0 || output > p.binding.OutputTokenCap || total != input+output {
		return nil, nil, ErrUnavailable
	}
	cost, e := nanoCost(response.Usage.Cost)
	if e != nil {
		return nil, nil, e
	}
	usage := &Usage{InputTokens: input, OutputTokens: output, CostNanoCredits: cost}
	rateBound, e := priceCeiling(input, output, p.profile.PromptPriceNanoCreditsPerMillion, p.profile.CompletionPriceNanoCreditsPerMillion)
	if e != nil || cost > rateBound || !validUsage(usage, p.binding) {
		return nil, nil, ErrUnavailable
	}
	return &result, usage, nil
}
func nanoCost(number json.Number) (int64, error) {
	s := number.String()
	if len(s) < 1 || len(s) > 64 || !amountPattern.MatchString(s) {
		return 0, ErrUnavailable
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 {
		return 0, ErrUnavailable
	}
	r.Mul(r, new(big.Rat).SetInt64(1000000000))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(r.Num(), r.Denom(), remainder)
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, ErrUnavailable
	}
	return quotient.Int64(), nil
}
