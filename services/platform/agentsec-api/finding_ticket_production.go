package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

var findingTicketSecretReferencePattern = regexp.MustCompile(`^secret_ref_([A-Za-z0-9][A-Za-z0-9._/-]{0,115})$`)

type findingTicketSecretResolver struct {
	driver  *connectorSecretsDriver
	root    string
	timeout time.Duration
}

func newFindingTicketSecretResolver(driver *connectorSecretsDriver, connectorSecretPrefix string, timeout time.Duration) (*findingTicketSecretResolver, error) {
	if driver == nil || driver.client == nil || !connectorPrefixPattern.MatchString(connectorSecretPrefix) || !strings.HasSuffix(connectorSecretPrefix, "/oauth") || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &findingTicketSecretResolver{driver: driver, root: strings.TrimSuffix(connectorSecretPrefix, "/oauth") + "/webhook", timeout: timeout}, nil
}

func (resolver *findingTicketSecretResolver) ResolveFindingTicketSecret(ctx context.Context, reference string) ([]byte, error) {
	if resolver == nil || resolver.driver == nil || ctx == nil || ctx.Err() != nil || strings.Contains(reference, "..") || strings.Contains(reference, "//") {
		return nil, errRuntimeUnavailable
	}
	match := findingTicketSecretReferencePattern.FindStringSubmatch(reference)
	if len(match) != 2 {
		return nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	value, err := resolver.driver.Read(bounded, resolver.root+"/"+match[1])
	if err != nil || len(value) < 32 || len(value) > 4096 {
		clear(value)
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

func newFindingTicketDeliveryID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errRuntimeUnavailable
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return "pid_" + encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func newFindingTicketLeaseToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errRuntimeUnavailable
	}
	return hex.EncodeToString(value), nil
}
