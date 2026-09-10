package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func runAPILoadHTTPCommand(output io.Writer, input io.Reader, arguments []string) error {
	var scenario apiLoadScenario
	if decodeAPILoad(input, &scenario) != nil || !scenario.valid() {
		return errResilienceRejected
	}
	flags := flag.NewFlagSet("api-load run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", "", "")
	credential := flags.String("credential-file", "", "")
	ca := flags.String("ca-bundle-file", "", "")
	seen := map[string]bool{}
	for i := 2; i < len(arguments); i += 2 {
		if i+1 >= len(arguments) || !strings.HasPrefix(arguments[i], "--") || seen[arguments[i]] {
			return errInvalidArguments
		}
		seen[arguments[i]] = true
	}
	if flags.Parse(arguments[2:]) != nil || flags.NArg() != 0 {
		return errInvalidArguments
	}
	client, err := NewRecoveryClient(RecoveryClientConfig{Endpoint: *endpoint, CredentialFile: *credential, CABundleFile: *ca, Timeout: time.Duration(scenario.RequestTimeoutMS) * time.Millisecond})
	if err != nil {
		return errResilienceRejected
	}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	measurement, err := measureAPILoad(ctx, scenario, client)
	if err != nil {
		return err
	}
	if err = encodeJSON(output, measurement); err != nil {
		return err
	}
	_, err = evaluateAPILoadMeasurement(measurement)
	return err
}

func measureAPILoad(parent context.Context, scenario apiLoadScenario, client *recoveryClient) (apiLoadMeasurement, error) {
	if parent == nil || parent.Err() != nil || !scenario.valid() || client == nil || client.client == nil {
		return apiLoadMeasurement{}, errResilienceRejected
	}
	credential, err := readRecoveryCredential(client.config.CredentialFile)
	if err != nil {
		return apiLoadMeasurement{}, errResilienceRejected
	}
	defer clear(credential)
	started := time.Now()
	budget := time.Duration(scenario.DurationSeconds)*time.Second + time.Duration(scenario.RequestTimeoutMS)*time.Millisecond
	if budget > 300*time.Second {
		budget = 300 * time.Second
	}
	ctx, cancel := context.WithDeadline(parent, started.Add(budget))
	defer cancel()
	count := scenario.DurationSeconds * scenario.RequestsPerSecond
	measurement := apiLoadMeasurement{Scenario: scenario, StartedAt: started.UTC().Format(time.RFC3339Nano), Samples: make([]apiLoadSample, count)}
	for i := range measurement.Samples {
		measurement.Samples[i] = apiLoadSample{Index: i, Outcome: "cancelled"}
	}
	slots := make(chan struct{}, scenario.Concurrency)
	var pending sync.WaitGroup
	interval := time.Second / time.Duration(scenario.RequestsPerSecond)
	for i := 0; i < count; i++ {
		due := started.Add(time.Duration(i) * time.Second / time.Duration(scenario.RequestsPerSecond))
		if wait := time.Until(due); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
		}
		if ctx.Err() != nil {
			break
		}
		// No catch-up burst and no unbounded producer queue. Client misses are
		// retained at their planned index and fail the gate, never omitted.
		if time.Since(due) >= interval {
			measurement.Samples[i].Outcome = "scheduler_late"
			continue
		}
		select {
		case slots <- struct{}{}:
			pending.Add(1)
			go func(index int, scheduled time.Time) {
				defer pending.Done()
				defer func() { <-slots }()
				measurement.Samples[index] = executeAPILoadRead(ctx, client, credential, index, scheduled)
			}(i, due)
		default:
			measurement.Samples[i].Outcome = "capacity"
		}
	}
	pending.Wait()
	measurement.ElapsedNS = int64(time.Since(started))
	measurement.Interrupted = parent.Err() != nil
	return measurement, nil
}

func executeAPILoadRead(ctx context.Context, client *recoveryClient, credential []byte, index int, scheduled time.Time) (result apiLoadSample) {
	result = apiLoadSample{Index: index, Outcome: "transport"}
	defer func() { result.LatencyNS = int64(time.Since(scheduled)) }()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.config.Endpoint+apiLoadPaths[index%len(apiLoadPaths)], nil)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+string(credential))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "agentsecctl/api-load-v1")
	response, err := client.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	result.Status = response.StatusCode
	if response.StatusCode != 200 {
		result.Outcome = "http"
		return
	}
	result.Outcome = "invalid_response"
	const maximumBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
	defer clear(body)
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(body) > maximumBody || mediaErr != nil || media != "application/json" || response.Header.Get("Cache-Control") != "no-store" {
		return
	}
	var page struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo *struct {
			HasMore    *bool           `json:"has_more"`
			NextCursor json.RawMessage `json:"next_cursor"`
		} `json:"page_info"`
	}
	if decodeAPILoad(bytes.NewReader(body), &page) != nil || page.Items == nil || len(page.Items) > 50 || page.PageInfo == nil || page.PageInfo.HasMore == nil {
		return
	}
	for _, item := range page.Items {
		if !validAPILoadRecord(index%4, item) {
			return
		}
	}
	if *page.PageInfo.HasMore {
		var cursor string
		if json.Unmarshal(page.PageInfo.NextCursor, &cursor) != nil || cursor == "" || len(cursor) > 8192 {
			return
		}
	} else if string(page.PageInfo.NextCursor) != "null" {
		return
	}
	result.Outcome = "ok"
	return
}

// Validate canonical identity and route-specific record fields. Full response
// schemas remain the product contract tests' responsibility; a JSON envelope
// containing scalars, nulls or unrelated records cannot count as a success.
func validAPILoadRecord(endpoint int, raw json.RawMessage) bool {
	var item map[string]json.RawMessage
	if json.Unmarshal(raw, &item) != nil || item == nil {
		return false
	}
	text := func(key string) string {
		var value string
		if json.Unmarshal(item[key], &value) != nil {
			return ""
		}
		return value
	}
	bounded := func(value string, maximum int) bool {
		return len(value) > 0 && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
	}
	if !validRecoveryProductID(text("id")) {
		return false
	}
	if endpoint == 2 {
		return bounded(text("name"), 128) && bounded(text("connector_key"), 63) && contains([]string{"configured", "pending_authorization", "active", "degraded", "revoking"}, text("status"))
	}
	var version int64
	if json.Unmarshal(item["version"], &version) != nil || version < 1 {
		return false
	}
	if endpoint == 0 || endpoint == 3 {
		kind := "agent"
		if endpoint == 3 {
			kind = "tool"
		}
		return text("kind") == kind && bounded(text("name"), 256) && validRecoveryProductID(text("evidence_id"))
	}
	if endpoint == 1 {
		var evidence []string
		if json.Unmarshal(item["evidence_ids"], &evidence) != nil || len(evidence) < 1 || len(evidence) > 64 {
			return false
		}
		for _, id := range evidence {
			if !validRecoveryProductID(id) {
				return false
			}
		}
		return bounded(text("title"), 256) && contains([]string{"posture", "prowler"}, text("source")) && contains([]string{"critical", "high", "medium", "low"}, text("severity")) && contains([]string{"open", "under_review", "resolved", "accepted"}, text("status"))
	}
	return false
}
