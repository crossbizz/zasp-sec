package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Deployment-owned service identities. Neither tenant input nor environment
// variables can replace destinations, paths, ports, or the readiness contract.
var attackLabWorkflowServices = [...]string{
	"http://agentsec-security-agent:8081/readyz",
	"http://agentsec-attack-lab-outbox:8081/readyz",
	"http://agentsec-attack-lab-controller:8081/readyz",
	"http://agentsec-attack-lab-proxy:8081/readyz",
	"http://security-agent-attack-lab-reconciler:8081/readyz",
}

func newAttackLabWorkflowReadiness(transport http.RoundTripper) func(context.Context) bool {
	return newSecurityAgentWorkflowReadiness(transport, attackLabWorkflowServices[:])
}

func newSecurityAgentWorkflowReadiness(transport http.RoundTripper, endpoints []string) func(context.Context) bool {
	endpoints = append([]string(nil), endpoints...)
	if transport == nil {
		transport = &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
			DisableKeepAlives:      true,
			MaxConnsPerHost:        1,
			ResponseHeaderTimeout:  time.Second,
			MaxResponseHeaderBytes: 4096,
		}
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	type flight struct {
		done  chan struct{}
		ready bool
	}
	var mu sync.Mutex
	var active *flight
	return func(ctx context.Context) bool {
		if ctx == nil || ctx.Err() != nil {
			return false
		}
		mu.Lock()
		if current := active; current != nil {
			mu.Unlock()
			select {
			case <-current.done:
				return current.ready && ctx.Err() == nil
			case <-ctx.Done():
				return false
			}
		}
		current := &flight{done: make(chan struct{})}
		active = current
		mu.Unlock()
		// The owner performs all work synchronously; callers only share this
		// bounded flight. No background goroutine or positive cache survives it.
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		ready := true
		for _, endpoint := range endpoints {
			request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
			if err != nil {
				ready = false
				break
			}
			response, err := client.Do(request)
			if err != nil {
				ready = false
				break
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 65))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json; charset=utf-8" || string(body) != "{\"status\":\"ready\"}\n" || probeCtx.Err() != nil {
				ready = false
				break
			}
		}
		mu.Lock()
		current.ready = ready
		active = nil
		close(current.done)
		mu.Unlock()
		return ready
	}
}
