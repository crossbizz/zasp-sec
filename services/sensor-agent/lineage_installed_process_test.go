package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// This test-only subprocess entry composes sensor code with the apiserver's
// actual TLS/PostgreSQL fixture. No test mode is added to the production binary.
// Configuration contains paths and source identity, never token contents.
type installedLineageProcessConfig struct {
	Action     string                      `json:"action"`
	Endpoint   string                      `json:"endpoint"`
	CAPath     string                      `json:"ca_path"`
	TokenPath  string                      `json:"token_path"`
	SpoolPath  string                      `json:"spool_path"`
	CursorPath string                      `json:"cursor_path"`
	AckPath    string                      `json:"ack_path"`
	ResultPath string                      `json:"result_path"`
	Stamp      string                      `json:"stamp"`
	Source     sensoradapter.LineageSource `json:"source"`
}

type installedLineageProcessResult struct {
	Outcome    string                      `json:"outcome"`
	Result     sensoradapter.StreamResult  `json:"result"`
	Progress   sensoradapter.ChunkProgress `json:"progress"`
	Durable    bool                        `json:"durable"`
	TokenReads int                         `json:"token_reads"`
	Requests   int                         `json:"requests"`
}

func TestInstalledLineageConsumerProcess(t *testing.T) {
	path := os.Getenv("ZASP_LINEAGE_CONSUMER_FIXTURE")
	if path == "" {
		t.Skip("invoked by actual apiserver/PostgreSQL composition")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 {
		t.Fatal("invalid fixture configuration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read fixture configuration")
	}
	var config installedLineageProcessConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("decode fixture configuration")
	}
	for _, path := range []string{config.CAPath, config.TokenPath, config.SpoolPath, config.CursorPath, config.AckPath, config.ResultPath} {
		if !validAbsolute(path) {
			t.Fatal("invalid fixture path")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := installedLineageProcessResult{Outcome: "rejected"}
	defer func() {
		raw, err := json.Marshal(result)
		if err != nil || os.WriteFile(config.ResultPath, raw, 0600) != nil {
			t.Error("write fixture result")
		}
	}()
	if config.Action == "initialize" || config.Action == "initialize-interrupted" || config.Action == "initialize-single" {
		if initializeInstalledLineageFixture(ctx, config) == nil {
			result.Outcome = "initialized"
		}
		return
	}
	if config.Action == "recover-interrupted" {
		spool, err := newLineageSpool(config.SpoolPath, uint32(os.Getuid()))
		if err != nil {
			return
		}
		defer spool.Close()
		if done, err := spool.SealInterrupted(ctx, config.Source); err == nil && done {
			result.Outcome = "source-recovered"
		}
		return
	}
	if config.Action == "reserve-incomplete" || config.Action == "discard-unpublished" {
		spool, err := newLineageSpool(config.SpoolPath, uint32(os.Getuid()))
		if err != nil {
			return
		}
		defer spool.Close()
		if config.Action == "discard-unpublished" {
			if done, err := spool.DiscardUnpublished(ctx, config.Source.GenerationID); err == nil && done {
				result.Outcome = "reservation-discarded"
			}
		} else {
			base, cancel := context.WithCancel(ctx)
			defer cancel()
			interrupted := &lineageReservationContext{Context: base, spool: config.SpoolPath, id: config.Source.GenerationID, stage: "manifest", action: cancel}
			generation, err := spool.Create(interrupted, config.Source)
			if generation != nil {
				generation.Close()
			}
			if err != nil && generation == nil && interrupted.fired {
				result.Outcome = "reservation-left"
			}
		}
		return
	}
	if config.Action == "retire-checkpoint" || config.Action == "retire-acknowledgment" || config.Action == "forget-retirement" || config.Action == "retire-slot" || config.Action == "release-slot" {
		// No source reader, token, CA or HTTP client is opened after reclamation.
		completion, err := newLineageCompletionReader(config.SpoolPath, uint32(os.Getuid()))
		if err != nil {
			return
		}
		defer completion.Close()
		store, err := newLineageAcknowledgments(config.AckPath)
		if err != nil {
			return
		}
		defer store.Close()
		request := lineageReclaimRequest{Source: config.Source, Destination: config.Endpoint + "/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}
		if config.Action == "forget-retirement" {
			if complete, err := store.ForgetRetirement(ctx, completion, request); err == nil && complete {
				result.Outcome = "retirement-forgotten"
			}
			return
		}
		tokenParent, err := os.OpenRoot(filepath.Dir(config.TokenPath))
		if err != nil {
			return
		}
		defer tokenParent.Close()
		if config.Action == "retire-slot" || config.Action == "release-slot" {
			slots, err := newLineageConsumerSlots(filepath.Dir(config.CursorPath), lineageSlotConfig{EnrollmentBinding: config.Source.EnrollmentBinding, Destination: request.Destination, Producer: completion, Acknowledgments: store, ProtectedInputs: []sensoradapter.PinnedInput{{Parent: tokenParent, Name: filepath.Base(config.TokenPath)}}})
			if err != nil {
				return
			}
			defer slots.Close()
			progress, err := slots.ReconcileConsumer(ctx, nil, 100)
			if err != nil {
				return
			}
			result.Result.ProducerDroppedTotal = progress.ProducerDroppedTotal
			result.Result.CoverageUnknown = progress.CoverageUnknown
			if config.Action == "retire-slot" {
				if progress.Retired == 1 && progress.Released == 0 {
					result.Outcome = "slot-retired"
				}
			} else {
				if progress.Released == 1 {
					result.Outcome = "slot-released"
				} else if installedLineageConsumerIdle(progress) {
					result.Outcome = "slot-idle"
				}
			}
			return
		}
		retire := store.RetireCheckpoint
		outcome := "checkpoint-retired"
		if config.Action == "retire-acknowledgment" {
			retire = store.RetireAcknowledgment
			outcome = "ack-retired"
		}
		complete, err := retire(ctx, completion, request, config.CursorPath, 100, []sensoradapter.PinnedInput{{Parent: tokenParent, Name: filepath.Base(config.TokenPath)}})
		if err == nil && complete {
			result.Outcome = outcome
		}
		return
	}
	if config.Action == "verify-acknowledgment" || config.Action == "verify-daemon-acknowledgment" || config.Action == "reclaim-acknowledged" || config.Action == "collect-completion" || config.Action == "reconcile-producer" {
		// Producer-only path: don't open a token, CA, client or consumer cursor.
		spool, err := newLineageSpool(config.SpoolPath, uint32(os.Getuid()))
		if err != nil {
			return
		}
		defer spool.Close()
		receipts, err := newLineageReceiptReader(config.AckPath, uint32(os.Geteuid()))
		if config.Action == "verify-daemon-acknowledgment" {
			if receipts != nil {
				receipts.Close()
			}
			receipts, err = newProductionLineageReceiptReader(config.AckPath, 65532)
		}
		if config.Action == "reclaim-acknowledged" {
			if receipts != nil {
				defer receipts.Close()
			}
			complete, err := spool.ReclaimAcknowledged(ctx, receipts, lineageReclaimRequest{Source: config.Source, Destination: config.Endpoint + "/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())})
			if err == nil && complete {
				result.Outcome = "source-reclaimed"
			}
			return
		}
		if err != nil {
			return
		}
		defer receipts.Close()
		if config.Action == "reconcile-producer" {
			if _, err := spool.ReconcileProducer(ctx, receipts, lineageProducerConfig{EnrollmentBinding: config.Source.EnrollmentBinding, Destination: config.Endpoint + "/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}); err == nil {
				result.Outcome = "producer-reconciled"
			}
			return
		}
		if config.Action == "collect-completion" {
			if complete, err := spool.CollectCompletion(ctx, receipts, lineageReclaimRequest{Source: config.Source, Destination: config.Endpoint + "/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}); err == nil && complete {
				result.Outcome = "completion-collected"
			}
			return
		}
		ack, found, err := spool.VerifyAcknowledgment(ctx, receipts, config.Source, config.Endpoint+"/internal/v1/runtime/events")
		if err == nil && found {
			result.Outcome = "receipt-verified"
			result.Progress = ack.Consumption.Progress
		}
		return
	}
	if config.Action != "process" && config.Action != "process-lost-response" && config.Action != "acknowledge" && config.Action != "reconcile-consumer" {
		return
	}
	reader, err := newLineageSpoolReader(filepath.Join(config.SpoolPath, "generation-"+config.Source.GenerationID), config.Source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		return
	}
	defer reader.Close()
	if reader.Source() != config.Source {
		return
	}
	protectedParent, err := os.OpenRoot(filepath.Dir(config.TokenPath))
	if err != nil {
		return
	}
	defer protectedParent.Close()
	store, err := newLineageAcknowledgments(config.AckPath)
	if err != nil {
		return
	}
	defer store.Close()
	producer, err := newLineageCompletionReader(config.SpoolPath, uint32(os.Getuid()))
	if err != nil {
		return
	}
	defer producer.Close()
	slots, err := newLineageConsumerSlots(filepath.Dir(config.CursorPath), lineageSlotConfig{EnrollmentBinding: config.Source.EnrollmentBinding, Destination: config.Endpoint + "/internal/v1/runtime/events", Producer: producer, Acknowledgments: store, ProtectedInputs: []sensoradapter.PinnedInput{{Parent: protectedParent, Name: filepath.Base(config.TokenPath)}}})
	if err != nil {
		return
	}
	defer slots.Close()
	assignment, err := slots.Reserve(ctx, reader)
	if err != nil {
		return
	}
	if cursor, err := slots.CursorPath(assignment); err != nil || cursor != config.CursorPath {
		return
	}
	token, err := newTokenReader(config.TokenPath)
	if err != nil {
		return
	}
	defer token.Close()
	ca, err := os.ReadFile(config.CAPath)
	if err != nil {
		t.Fatal("read fixture CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("decode fixture CA")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: config.Endpoint, EnrollmentBinding: config.Source.EnrollmentBinding, Now: time.Now,
		Token: func() ([]byte, error) { result.TokenReads++; return token.Read() },
		Do: func(request *http.Request) (*http.Response, error) {
			result.Requests++
			response, err := httpClient.Do(request)
			if err != nil {
				return nil, err
			}
			if config.Action == "process-lost-response" && response.StatusCode == http.StatusAccepted {
				_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16385))
				response.Body.Close()
				if readErr != nil {
					return nil, readErr
				}
				return nil, errors.New("fixture response lost after actual acceptance")
			}
			return response, nil
		},
	})
	if err != nil {
		return
	}
	if config.Action == "reconcile-consumer" {
		progress, err := slots.ReconcileConsumer(ctx, client, 100)
		if err != nil {
			return
		}
		result.Result = sensoradapter.StreamResult{Read: progress.Read, Submitted: progress.Submitted, Dropped: uint64(progress.Read - progress.Submitted)}
	}
	consumer, err := newAssignedLineageChunkConsumer(reader, client, config.CursorPath, 100, []sensoradapter.PinnedInput{{Parent: token.root, Name: token.name}}, store, assignment)
	if err != nil {
		return
	}
	defer consumer.Close()
	if config.Action == "reconcile-consumer" {
		result.Outcome = "ok"
		result.Progress, result.Durable, _ = consumer.Committed()
		return
	}
	if config.Action == "acknowledge" {
		if consumer.Acknowledge(ctx) == nil {
			result.Outcome = "acknowledged"
		}
		result.Progress, result.Durable, _ = consumer.Committed()
		return
	}
	result.Result, err = consumer.ProcessAvailable(ctx)
	switch {
	case err == nil:
		result.Outcome = "ok"
	case errors.Is(err, sensoradapter.ErrClientRetryable):
		result.Outcome = "retryable"
	case errors.Is(err, sensoradapter.ErrClientDenied):
		result.Outcome = "denied"
	case errors.Is(err, sensoradapter.ErrEnvelopeExpired):
		result.Outcome = "expired"
	default:
		result.Outcome = "rejected"
	}
	result.Progress, result.Durable, _ = consumer.Committed()
}

// Cumulative coverage isn't activity. Keep it in the child result even when a
// restarted consumer performs no new work during an idempotent release retry.
func installedLineageConsumerIdle(progress lineageConsumerProgress) bool {
	progress.ProducerDroppedTotal, progress.CoverageUnknown = 0, false
	return progress == (lineageConsumerProgress{})
}

func TestInstalledLineageIdleDoesNotEraseCoverage(t *testing.T) {
	for _, dropped := range []uint64{0, 7} {
		for _, unknown := range []bool{false, true} {
			progress := lineageConsumerProgress{ProducerDroppedTotal: dropped, CoverageUnknown: unknown}
			if !installedLineageConsumerIdle(progress) || progress.ProducerDroppedTotal != dropped || progress.CoverageUnknown != unknown {
				t.Fatal("idle classification changed retained coverage")
			}
			for _, active := range []lineageConsumerProgress{{SourcesProcessed: 1}, {Acknowledged: 1}, {Retired: 1}, {Released: 1}, {Waiting: 1}, {Read: 1}, {Submitted: 1}} {
				active.ProducerDroppedTotal, active.CoverageUnknown = dropped, unknown
				if installedLineageConsumerIdle(active) {
					t.Fatal("activity classified as idle")
				}
			}
		}
	}
}

func initializeInstalledLineageFixture(ctx context.Context, config installedLineageProcessConfig) error {
	stamp, err := time.Parse(time.RFC3339Nano, config.Stamp)
	if err != nil {
		return errLineageSpool
	}
	spool, err := newLineageSpool(config.SpoolPath, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer spool.Close()
	// Create is exclusive. Initialization cannot adopt or rewrite old history.
	generation, err := spool.Create(ctx, config.Source)
	if err != nil {
		return err
	}
	defer generation.Close()
	records := 3
	if config.Action == "initialize-single" {
		records = 1
	}
	for index := 0; index < records; index++ {
		kind := "file"
		if index == 0 {
			kind = "exec"
		}
		event := lineageProviderFixture(kind)
		if config.Action == "initialize-single" && config.Source.Profile == "tetragon-local-stream-v2" {
			event = lineageCgroupProviderFixture(^uint64(0))
		}
		event.NodeName, event.Time = config.Source.NodeName, timestamppb.New(stamp)
		if event.GetProcessExec() != nil {
			event.GetProcessExec().Process.StartTime = timestamppb.New(stamp)
		} else if index == 0 {
			event.GetProcessKprobe().Process.StartTime = timestamppb.New(stamp)
		} else {
			started := stamp
			if index == 2 {
				started = started.Add(-time.Second)
			}
			event.GetProcessKprobe().Process = &tetragon.Process{Pid: wrapperspb.UInt32(42), StartTime: timestamppb.New(started)}
		}
		line, err := sanitizeLineageEvent(event)
		if err != nil {
			return err
		}
		if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
			return err
		}
	}
	if config.Action == "initialize-interrupted" {
		return os.WriteFile(filepath.Join(generation.root.Name(), ".pending"), []byte(`{"version":"tetragon-`), 0600)
	}
	return generation.Seal(ctx, "shutdown", 0, 0)
}
