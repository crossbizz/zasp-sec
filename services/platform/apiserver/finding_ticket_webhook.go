package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type findingTicketWebhook struct {
	client  *http.Client
	timeout time.Duration
}

type findingTicketLookup func(context.Context, string) ([]net.IPAddr, error)
type findingTicketTransportFactory func(string, string, time.Duration) http.RoundTripper

type findingTicketPinnedRoundTripper struct {
	networks []*net.IPNet
	timeout  time.Duration
	lookup   findingTicketLookup
	factory  findingTicketTransportFactory
}

func NewProductionFindingTicketWebhook(allowedCIDRs []string, timeout time.Duration) (FindingTicketWebhook, error) {
	return newProductionFindingTicketWebhook(allowedCIDRs, timeout, net.DefaultResolver.LookupIPAddr, productionFindingTicketTransport)
}

func newProductionFindingTicketWebhook(allowedCIDRs []string, timeout time.Duration, lookup findingTicketLookup, factory findingTicketTransportFactory) (*findingTicketWebhook, error) {
	networks, valid := parseFindingTicketCIDRs(allowedCIDRs)
	if !valid || timeout < 100*time.Millisecond || timeout > 10*time.Second || lookup == nil || factory == nil {
		return nil, ErrRepositoryConfiguration
	}
	client := &http.Client{Transport: &findingTicketPinnedRoundTripper{networks: networks, timeout: timeout, lookup: lookup, factory: factory}}
	return newFindingTicketWebhook(client, timeout)
}

func newFindingTicketWebhook(client *http.Client, timeout time.Duration) (*findingTicketWebhook, error) {
	if client == nil || client.Transport == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	bounded := *client
	bounded.Timeout = timeout
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRepositoryUnavailable }
	return &findingTicketWebhook{client: &bounded, timeout: timeout}, nil
}

func (webhook *findingTicketWebhook) DeliverFindingTicket(ctx context.Context, destination, payload, digest, deliveryID string, secret []byte) (string, error) {
	parsed, parseErr := url.Parse(destination)
	decodedDigest, digestErr := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	actualDigest := sha256.Sum256([]byte(payload))
	if webhook == nil || webhook.client == nil || ctx == nil || ctx.Err() != nil || parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(payload) < 2 || len(payload) > 16<<10 || !validProductID(deliveryID) || !findingTicketDigestPattern.MatchString(digest) || digestErr != nil || len(decodedDigest) != sha256.Size || subtle.ConstantTimeCompare(decodedDigest, actualDigest[:]) != 1 || len(secret) < 32 || len(secret) > 4096 {
		return "", ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, webhook.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, destination, bytes.NewBufferString(payload))
	if err != nil {
		return "", ErrRepositoryUnavailable
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "zasp-finding-ticket-webhook/1")
	request.Header.Set("X-Zasp-Delivery-ID", deliveryID)
	request.Header.Set("X-Zasp-Payload-Digest", digest)
	request.Header.Set("X-Zasp-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := webhook.client.Do(request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeFindingTicketResponse(response)
		return "", ErrRepositoryUnavailable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if readErr != nil || len(body) > 4096 || response.StatusCode != http.StatusCreated || response.Header.Get("Content-Type") != "application/json" {
		return "", ErrRepositoryUnavailable
	}
	var ticket FindingTicket
	if decodeStrictRisk(body, &ticket) != nil || !findingTicketProviderIDPattern.MatchString(ticket.TicketID) {
		return "", ErrRepositoryUnavailable
	}
	return ticket.TicketID, nil
}

func closeFindingTicketResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func (roundTripper *findingTicketPinnedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper == nil || request == nil || request.Context() == nil || request.Context().Err() != nil || !validFindingTicketDestination(request.URL.String()) {
		return nil, ErrRepositoryUnavailable
	}
	host := strings.ToLower(request.URL.Hostname())
	addresses, err := roundTripper.lookup(request.Context(), host)
	if err != nil || len(addresses) < 1 || len(addresses) > 32 {
		return nil, ErrRepositoryUnavailable
	}
	unique := make(map[string]struct{}, len(addresses))
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		if !validFindingTicketIP(ip) || !findingTicketIPAllowed(ip, roundTripper.networks) {
			return nil, ErrRepositoryUnavailable
		}
		value := ip.String()
		if _, duplicate := unique[value]; duplicate {
			continue
		}
		unique[value] = struct{}{}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, ErrRepositoryUnavailable
	}
	sort.Strings(values)
	transport := roundTripper.factory(host, values[0], roundTripper.timeout)
	if transport == nil {
		return nil, ErrRepositoryUnavailable
	}
	return transport.RoundTrip(request)
}

func parseFindingTicketCIDRs(values []string) ([]*net.IPNet, bool) {
	if len(values) < 1 || len(values) > 64 {
		return nil, false
	}
	result := make([]*net.IPNet, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value || !ip.Equal(network.IP) || !validFindingTicketIP(ip) {
			return nil, false
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones < 16 || bits == 128 && ones < 32 || bits != 32 && bits != 128 {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		for _, existing := range result {
			if existing.Contains(network.IP) || network.Contains(existing.IP) {
				return nil, false
			}
		}
		seen[value] = struct{}{}
		result = append(result, network)
	}
	return result, true
}

func findingTicketIPAllowed(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func validFindingTicketIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func productionFindingTicketTransport(host, pinnedIP string, timeout time.Duration) http.RoundTripper {
	if !findingTicketHostnamePattern.MatchString(host) || !validFindingTicketIP(net.ParseIP(pinnedIP)) || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedHost, port, err := net.SplitHostPort(address)
		if err != nil || strings.ToLower(requestedHost) != host || port != "443" {
			return nil, ErrRepositoryUnavailable
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(pinnedIP, "443"))
	}
	return transport
}

var _ FindingTicketWebhook = (*findingTicketWebhook)(nil)
