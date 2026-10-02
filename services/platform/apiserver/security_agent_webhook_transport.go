package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

// DeliverSecurityAgentResponse signs immutable prepared bytes. It does not load
// evidence, select a destination, resolve secrets, or retry an ambiguous send.
func (webhook *findingTicketWebhook) DeliverSecurityAgentResponse(ctx context.Context, destination, deliveryID, digest string, payload, secret []byte) (securityagent.ResponseWebhookReceipt, error) {
	failed := securityagent.ResponseWebhookReceipt{Outcome: "failed", ErrorCode: "invalid_request"}
	uncertain := securityagent.ResponseWebhookReceipt{Outcome: "uncertain", ErrorCode: "delivery_uncertain"}
	parsed, parseErr := url.Parse(destination)
	decoded, digestErr := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	actual := sha256.Sum256(payload)
	if webhook == nil || webhook.client == nil || ctx == nil || ctx.Err() != nil || parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || len(payload) < 2 || len(payload) > 16<<10 || !validProductID(deliveryID) || !findingTicketDigestPattern.MatchString(digest) || digestErr != nil || subtle.ConstantTimeCompare(decoded, actual[:]) != 1 || len(secret) < 32 || len(secret) > 4096 {
		return failed, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, webhook.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, destination, bytes.NewReader(payload))
	if err != nil {
		return failed, ErrRepositoryOperation
	}
	if request.URL.Path == "" {
		request.URL.Path = "/"
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "zasp-security-agent-webhook/1")
	request.Header.Set("X-Zasp-Event", "security_agent.response")
	request.Header.Set("X-Zasp-Delivery-ID", deliveryID)
	request.Header.Set("X-Zasp-Payload-Digest", digest)
	request.Header.Set("X-Zasp-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	// Keep the pinned transport and timeout. Return the first redirect response
	// without following it, so a definitive 3xx is failed, not uncertain.
	client := *webhook.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil || response == nil || bounded.Err() != nil {
		closeFindingTicketResponse(response)
		return uncertain, ErrRepositoryUnavailable
	}
	defer closeFindingTicketResponse(response)
	rejected := securityagent.ResponseWebhookReceipt{Outcome: "failed", ErrorCode: "response_rejected"}
	if response.StatusCode != http.StatusNoContent {
		return rejected, nil
	}
	if response.Body == nil {
		return uncertain, ErrRepositoryUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || bounded.Err() != nil {
		return uncertain, ErrRepositoryUnavailable
	}
	if len(body) != 0 {
		return rejected, nil
	}
	return securityagent.ResponseWebhookReceipt{Outcome: "acknowledged"}, nil
}
