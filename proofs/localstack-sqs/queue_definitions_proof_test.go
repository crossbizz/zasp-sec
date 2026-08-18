package main

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/queuedefinition"
)

func TestRunQueueDefinitionsProofCreatesReadsAndCleansExactSix(t *testing.T) {
	t.Parallel()

	fake := newQueueDefinitionsFake()
	result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
	if err != nil {
		t.Fatalf("RunQueueDefinitionsProof error = %v", err)
	}
	if result != (QueueDefinitionsProofResult{
		Queues: 3, DLQs: 3, Schemas: 3,
		Retention: true, Redrive: true, Cleanup: true, Audit: true,
	}) {
		t.Fatalf("result = %#v", result)
	}
	if names := fake.queueNames(); len(names) != 0 {
		t.Fatalf("queues remain = %v", names)
	}
	assertQueueDefinitionCreateState(t, fake)

	events := fake.eventSnapshot()
	lastDLQCreate, firstSourceCreate := -1, len(events)
	lastSourceDelete, firstDLQDelete := -1, len(events)
	for index, event := range events {
		switch {
		case strings.HasPrefix(event, "create:") && strings.HasSuffix(event, "-dlq"):
			lastDLQCreate = index
		case strings.HasPrefix(event, "create:agentsec-") && !strings.HasSuffix(event, "-dlq") && index < firstSourceCreate:
			firstSourceCreate = index
		case strings.HasPrefix(event, "delete-queue:agentsec-") && !strings.HasSuffix(event, "-dlq"):
			lastSourceDelete = index
		case strings.HasPrefix(event, "delete-queue:") && strings.HasSuffix(event, "-dlq") && index < firstDLQDelete:
			firstDLQDelete = index
		}
	}
	if lastDLQCreate < 0 || firstSourceCreate <= lastDLQCreate || lastSourceDelete < 0 || firstDLQDelete <= lastSourceDelete {
		t.Fatalf("lifecycle order = %v", events)
	}
}

func TestRunQueueDefinitionsProofReconcilesAmbiguousAndDelayedCreates(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"ambiguous-applied", "malformed-applied"} {
		t.Run(mode, func(t *testing.T) {
			fake := newQueueDefinitionsFake()
			fake.createModes["agentsec-runtime-events-dlq"] = mode
			fake.hiddenAfterCreate["agentsec-runtime-events-dlq"] = 3
			result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
			if err != nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
				t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
			}
			if fake.createCalls["agentsec-runtime-events-dlq"] != 1 {
				t.Fatalf("create attempts = %d", fake.createCalls["agentsec-runtime-events-dlq"])
			}
		})
	}

	t.Run("transient read", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-runtime-events-dlq"] = "ambiguous-applied"
		fake.listErrors["agentsec-runtime-events-dlq"] = 2
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if err != nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})

	t.Run("ambiguous unapplied", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-background-dlq"] = "ambiguous-unapplied"
		options := queueDefinitionsOptions(fake)
		options.CleanupTimeout = 20 * time.Millisecond
		result, err := RunQueueDefinitionsProof(context.Background(), options)
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
		if fake.createCalls["agentsec-background-dlq"] != 1 {
			t.Fatalf("create attempts = %d", fake.createCalls["agentsec-background-dlq"])
		}
	})

	t.Run("panic unapplied", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-background-dlq"] = "panic-unapplied"
		options := queueDefinitionsOptions(fake)
		options.CleanupTimeout = 20 * time.Millisecond
		result, err := RunQueueDefinitionsProof(context.Background(), options)
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})
}

func TestRunQueueDefinitionsProofNeverAdoptsDefinitiveCreateRejection(t *testing.T) {
	t.Parallel()

	fake := newQueueDefinitionsFake()
	fake.createModes["agentsec-background-dlq"] = "definitive"
	result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
	if !errors.Is(err, errProvider) {
		t.Fatalf("RunQueueDefinitionsProof error = %v", err)
	}
	if !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
		t.Fatalf("result = %#v; queues = %v", result, fake.queueNames())
	}
	if fake.listAfterDefinitive {
		t.Fatal("definitive create rejection entered exact-name reconciliation")
	}
}

func TestRunQueueDefinitionsProofReconcilesOnlyAmbiguousPolicyMutation(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"ambiguous-applied", "panic-applied"} {
		t.Run(mode, func(t *testing.T) {
			fake := newQueueDefinitionsFake()
			fake.setModes["agentsec-tests-dlq"] = mode
			result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
			if err != nil || !result.Redrive || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
				t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
			}
			if fake.setCalls["agentsec-tests-dlq"] != 1 {
				t.Fatalf("set attempts = %d", fake.setCalls["agentsec-tests-dlq"])
			}
		})
	}

	t.Run("definitive", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.setModes["agentsec-tests-dlq"] = "definitive"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})

	t.Run("ambiguous unapplied retains cleanup authority", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.setModes["agentsec-tests-dlq"] = "ambiguous-unapplied"
		options := queueDefinitionsOptions(fake)
		options.CleanupTimeout = 20 * time.Millisecond
		result, err := RunQueueDefinitionsProof(context.Background(), options)
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})
}

func TestRunQueueDefinitionsProofReconcilesAmbiguousDeleteAndRejectsDefinitiveDelete(t *testing.T) {
	t.Parallel()

	t.Run("ambiguous applied", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.deleteModes["agentsec-runtime-events"] = "ambiguous-applied"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if err != nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
		if fake.deleteCalls["agentsec-runtime-events"] != 1 {
			t.Fatalf("delete attempts = %d", fake.deleteCalls["agentsec-runtime-events"])
		}
	})

	t.Run("panic applied", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.deleteModes["agentsec-runtime-events"] = "panic-applied"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if err != nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})

	t.Run("definitive continues", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.deleteModes["agentsec-runtime-events"] = "definitive"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
		}
		names := fake.queueNames()
		if !reflect.DeepEqual(names, []string{"agentsec-runtime-events"}) {
			t.Fatalf("later cleanup did not continue: %v", names)
		}
	})

	t.Run("ambiguous unapplied does not starve later cleanup", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.deleteModes["agentsec-background"] = "ambiguous-unapplied"
		options := queueDefinitionsOptions(fake)
		options.CleanupTimeout = 20 * time.Millisecond
		result, err := RunQueueDefinitionsProof(context.Background(), options)
		if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
		}
		if names := fake.queueNames(); !reflect.DeepEqual(names, []string{"agentsec-background"}) {
			t.Fatalf("later cleanup was starved: %v", names)
		}
	})

	t.Run("delete panic does not stop later cleanup", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.deleteModes["agentsec-background"] = "panic"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
		}
		if names := fake.queueNames(); !reflect.DeepEqual(names, []string{"agentsec-background"}) {
			t.Fatalf("later cleanup stopped after panic: %v", names)
		}
	})
}

func TestRunQueueDefinitionsProofForeignReplacementFailsClosedAndContinues(t *testing.T) {
	t.Parallel()

	fake := newQueueDefinitionsFake()
	fake.mutateAtFinalInventory = "agentsec-background"
	result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
	if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
		t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
	}
	if names := fake.queueNames(); !reflect.DeepEqual(names, []string{"agentsec-background"}) {
		t.Fatalf("foreign replacement was deleted or later cleanup stopped: %v", names)
	}
}

func TestRunQueueDefinitionsProofRejectsHostileInventoryShapes(t *testing.T) {
	t.Parallel()

	for _, mutation := range []string{"tag", "arn", "attribute", "url", "duplicate", "extra"} {
		t.Run(mutation, func(t *testing.T) {
			fake := newQueueDefinitionsFake()
			fake.inventoryMutation = mutation
			fake.mutateAtFinalInventory = "agentsec-background"
			result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
			if !errors.Is(err, errCleanup) {
				t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
			}
			names := fake.queueNames()
			if mutation == "extra" {
				if !reflect.DeepEqual(names, []string{"zasp-m1-33-foreign"}) {
					t.Fatalf("foreign extra was mutated: %v", names)
				}
				return
			}
			if !reflect.DeepEqual(names, []string{"agentsec-background"}) {
				t.Fatalf("hostile replacement was deleted or later cleanup stopped: %v", names)
			}
		})
	}
}

func TestRunQueueDefinitionsProofUsesIndependentCleanupAfterCancellationAndPanic(t *testing.T) {
	t.Parallel()

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-background-dlq"] = "ambiguous-applied"
		fake.hiddenAfterCreate["agentsec-background-dlq"] = 2
		fake.cancelAfterCreate = cancel
		result, err := RunQueueDefinitionsProof(ctx, queueDefinitionsOptions(fake))
		if err == nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})

	t.Run("panic after apply", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-background-dlq"] = "panic-applied"
		fake.hiddenAfterCreate["agentsec-background-dlq"] = 2
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if err != nil || !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v; queues=%v", result, err, fake.queueNames())
		}
	})

	t.Run("rearm panic continues later cleanup", func(t *testing.T) {
		fake := newQueueDefinitionsFake()
		fake.createModes["agentsec-background"] = "panic-applied"
		fake.panicRearmName = "agentsec-background"
		result, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
		if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
			t.Fatalf("RunQueueDefinitionsProof = %#v, %v", result, err)
		}
		if names := fake.queueNames(); !reflect.DeepEqual(names, []string{"agentsec-background"}) {
			t.Fatalf("later cleanup stopped after rearm panic: %v", names)
		}
	})
}

func TestRunQueueDefinitionsProofRejectsAnyPreexistingQueueWithoutMutation(t *testing.T) {
	t.Parallel()

	fake := newQueueDefinitionsFake()
	fake.addQueue("foreign", nil, map[string]string{"foreign": "true"})
	_, err := RunQueueDefinitionsProof(context.Background(), queueDefinitionsOptions(fake))
	if !errors.Is(err, errOwnership) {
		t.Fatalf("RunQueueDefinitionsProof error = %v", err)
	}
	if names := fake.queueNames(); !reflect.DeepEqual(names, []string{"foreign"}) {
		t.Fatalf("preexisting queue was mutated: %v", names)
	}
	if len(fake.createCalls) != 0 || len(fake.deleteCalls) != 0 {
		t.Fatalf("mutation calls create=%v delete=%v", fake.createCalls, fake.deleteCalls)
	}
}

func TestFormatQueueDefinitionsChildSuccessIsExactAndFixed(t *testing.T) {
	t.Parallel()

	result := QueueDefinitionsProofResult{
		Queues: 3, DLQs: 3, Schemas: 3,
		Retention: true, Redrive: true, Cleanup: true, Audit: true,
	}
	if got := formatQueueDefinitionsChildSuccess(result); got !=
		"LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true." {
		t.Fatalf("success line = %q", got)
	}
}

type queueDefinitionsFake struct {
	*fakeSQS
	muDefinitions          sync.Mutex
	createModes            map[string]string
	setModes               map[string]string
	deleteModes            map[string]string
	hiddenAfterCreate      map[string]int
	createCalls            map[string]int
	setCalls               map[string]int
	deleteCalls            map[string]int
	createdAttributes      map[string]map[string]string
	createdTags            map[string]map[string]string
	setAttributes          map[string]map[string]string
	listErrors             map[string]int
	definitiveRejectedName string
	listAfterDefinitive    bool
	queueUniverseReads     int
	mutateAtFinalInventory string
	inventoryMutation      string
	duplicateInventoryName string
	panicRearmName         string
	cancelAfterCreate      context.CancelFunc
}

func newQueueDefinitionsFake() *queueDefinitionsFake {
	return &queueDefinitionsFake{
		fakeSQS:           newFakeSQS(),
		createModes:       make(map[string]string),
		setModes:          make(map[string]string),
		deleteModes:       make(map[string]string),
		hiddenAfterCreate: make(map[string]int),
		createCalls:       make(map[string]int),
		setCalls:          make(map[string]int),
		deleteCalls:       make(map[string]int),
		createdAttributes: make(map[string]map[string]string),
		createdTags:       make(map[string]map[string]string),
		setAttributes:     make(map[string]map[string]string),
		listErrors:        make(map[string]int),
	}
}

func (fake *queueDefinitionsFake) ListQueues(ctx context.Context, prefix string) ([]string, error) {
	fake.muDefinitions.Lock()
	if fake.definitiveRejectedName != "" && prefix == fake.definitiveRejectedName {
		fake.listAfterDefinitive = true
	}
	if fake.panicRearmName != "" && prefix == fake.panicRearmName {
		fake.muDefinitions.Unlock()
		panic("provider detail must not escape")
	}
	if fake.listErrors[prefix] > 0 {
		fake.listErrors[prefix]--
		fake.muDefinitions.Unlock()
		return nil, errors.New("provider detail must not escape")
	}
	if prefix == "" {
		fake.queueUniverseReads++
		if fake.queueUniverseReads == 2 && fake.mutateAtFinalInventory != "" {
			fake.fakeSQS.mu.Lock()
			switch fake.inventoryMutation {
			case "arn":
				fake.queues[fake.mutateAtFinalInventory].arn = "arn:aws:sqs:us-east-1:000000000000:foreign"
			case "attribute":
				fake.queues[fake.mutateAtFinalInventory].attributes["VisibilityTimeout"] = "999"
			case "url":
				fake.queues[fake.mutateAtFinalInventory].url = "http://127.0.0.1:49153/000000000000/" + fake.mutateAtFinalInventory
			case "duplicate":
				fake.duplicateInventoryName = fake.mutateAtFinalInventory
			case "extra":
				fake.fakeSQS.addQueueLocked("zasp-m1-33-foreign", nil, map[string]string{"foreign": "true"})
			default:
				fake.queues[fake.mutateAtFinalInventory].tags["zasp-proof-marker"] = "fedcba9876543210"
			}
			fake.fakeSQS.mu.Unlock()
		}
	}
	if fake.hiddenAfterCreate[prefix] > 0 {
		fake.hiddenAfterCreate[prefix]--
		fake.muDefinitions.Unlock()
		return nil, nil
	}
	fake.muDefinitions.Unlock()
	urls, err := fake.fakeSQS.ListQueues(ctx, prefix)
	if err == nil && fake.duplicateInventoryName != "" &&
		(prefix == "" || prefix == fake.duplicateInventoryName) {
		for _, queueURL := range urls {
			if queueNameFromURL(queueURL) == fake.duplicateInventoryName {
				urls = append(urls, queueURL)
				break
			}
		}
	}
	return urls, err
}

func (fake *queueDefinitionsFake) CreateQueue(ctx context.Context, name string, attributes, tags map[string]string) (string, error) {
	fake.muDefinitions.Lock()
	fake.createCalls[name]++
	mode := fake.createModes[name]
	if mode == "definitive" {
		fake.definitiveRejectedName = name
		fake.muDefinitions.Unlock()
		return "", definitiveMutationError()
	}
	if mode == "panic-unapplied" {
		fake.muDefinitions.Unlock()
		panic("provider detail must not escape")
	}
	if mode == "ambiguous-unapplied" {
		fake.muDefinitions.Unlock()
		return "", ambiguousMutationError()
	}
	fake.createdAttributes[name] = cloneMap(attributes)
	fake.createdTags[name] = cloneMap(tags)
	fake.muDefinitions.Unlock()
	if ctx.Err() != nil {
		return "", ambiguousMutationError()
	}

	returnedURL, err := fake.fakeSQS.CreateQueue(ctx, name, attributes, tags)
	fake.fakeSQS.mu.Lock()
	if queue := fake.queues[name]; queue != nil {
		queue.url = strings.Replace(queue.url, ":4566/", ":49152/", 1)
		returnedURL = queue.url
	}
	fake.fakeSQS.mu.Unlock()
	if fake.cancelAfterCreate != nil {
		fake.cancelAfterCreate()
		fake.cancelAfterCreate = nil
	}
	switch mode {
	case "ambiguous-applied":
		return "", ambiguousMutationError()
	case "malformed-applied":
		return "", nil
	case "panic-applied":
		panic("provider detail must not escape")
	default:
		return returnedURL, err
	}
}

func (fake *queueDefinitionsFake) SetQueueAttributes(ctx context.Context, queueURL string, attributes map[string]string) error {
	name := queueNameFromURL(queueURL)
	fake.muDefinitions.Lock()
	fake.setCalls[name]++
	mode := fake.setModes[name]
	if mode == "definitive" {
		fake.muDefinitions.Unlock()
		return definitiveMutationError()
	}
	if mode == "ambiguous-unapplied" {
		fake.muDefinitions.Unlock()
		return ambiguousMutationError()
	}
	fake.setAttributes[name] = cloneMap(attributes)
	fake.muDefinitions.Unlock()
	if err := fake.fakeSQS.SetQueueAttributes(ctx, queueURL, attributes); err != nil {
		return err
	}
	if mode == "ambiguous-applied" {
		return ambiguousMutationError()
	}
	if mode == "panic-applied" {
		panic("provider detail must not escape")
	}
	return nil
}

func (fake *queueDefinitionsFake) DeleteQueue(ctx context.Context, queueURL string) error {
	name := queueNameFromURL(queueURL)
	fake.muDefinitions.Lock()
	fake.deleteCalls[name]++
	mode := fake.deleteModes[name]
	fake.muDefinitions.Unlock()
	if mode == "definitive" {
		return definitiveMutationError()
	}
	if mode == "ambiguous-unapplied" {
		return ambiguousMutationError()
	}
	if mode == "panic" {
		panic("provider detail must not escape")
	}
	if ctx.Err() != nil {
		return ambiguousMutationError()
	}
	if err := fake.fakeSQS.DeleteQueue(ctx, queueURL); err != nil {
		return err
	}
	if mode == "ambiguous-applied" {
		return ambiguousMutationError()
	}
	if mode == "panic-applied" {
		panic("provider detail must not escape")
	}
	return nil
}

func queueDefinitionsOptions(client queueDefinitionsProofClient) QueueDefinitionsProofOptions {
	return QueueDefinitionsProofOptions{
		Endpoint:       "http://127.0.0.1:49152",
		Marker:         testMarker,
		Client:         client,
		CleanupTimeout: 100 * time.Millisecond,
		PollInterval:   time.Millisecond,
	}
}

func assertQueueDefinitionCreateState(t *testing.T, fake *queueDefinitionsFake) {
	t.Helper()
	definitions := queuedefinition.Definitions()
	if len(fake.createdAttributes) != 6 || len(fake.createdTags) != 6 || len(fake.setAttributes) != 3 {
		t.Fatalf("snapshots create=%d tags=%d set=%d", len(fake.createdAttributes), len(fake.createdTags), len(fake.setAttributes))
	}
	for _, definition := range definitions {
		settings := definition.Settings()
		dlqAttributes := map[string]string{
			"DelaySeconds":                  "0",
			"MaximumMessageSize":            "262144",
			"MessageRetentionPeriod":        "1209600",
			"ReceiveMessageWaitTimeSeconds": "20",
			"VisibilityTimeout":             "30",
		}
		sourceAttributes := map[string]string{
			"DelaySeconds":                  "0",
			"MaximumMessageSize":            "262144",
			"MessageRetentionPeriod":        "345600",
			"ReceiveMessageWaitTimeSeconds": "20",
			"VisibilityTimeout":             strconv.Itoa(settings.VisibilityTimeoutSeconds),
		}
		if got := fake.createdAttributes[definition.DeadLetterName()]; !reflect.DeepEqual(got, dlqAttributes) {
			t.Fatalf("DLQ attributes %s = %#v", definition.DeadLetterName(), got)
		}
		actualSourceAttributes := cloneMap(fake.createdAttributes[definition.Name()])
		redrive := actualSourceAttributes[redrivePolicyAttribute]
		delete(actualSourceAttributes, redrivePolicyAttribute)
		if !reflect.DeepEqual(actualSourceAttributes, sourceAttributes) {
			t.Fatalf("source attributes %s = %#v", definition.Name(), actualSourceAttributes)
		}
		wantRedrive := "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:" + definition.DeadLetterName() + "\",\"maxReceiveCount\":\"5\"}"
		if redrive != wantRedrive {
			t.Fatalf("source redrive %s = %q", definition.Name(), redrive)
		}
		wantDLQTags := expectedQueueDefinitionTags(definition, "dlq")
		wantSourceTags := expectedQueueDefinitionTags(definition, "source")
		if !reflect.DeepEqual(fake.createdTags[definition.DeadLetterName()], wantDLQTags) ||
			!reflect.DeepEqual(fake.createdTags[definition.Name()], wantSourceTags) {
			t.Fatalf("tags for %s pair do not match", definition.Name())
		}
		wantAllow := "{\"redrivePermission\":\"byQueue\",\"sourceQueueArns\":[\"arn:aws:sqs:us-east-1:000000000000:" + definition.Name() + "\"]}"
		if got := fake.setAttributes[definition.DeadLetterName()][redriveAllowPolicyAttribute]; got != wantAllow {
			t.Fatalf("DLQ allow policy %s = %q", definition.DeadLetterName(), got)
		}
	}
}

func expectedQueueDefinitionTags(definition queuedefinition.Definition, role string) map[string]string {
	pair := definition.DeadLetterName()
	if role == "dlq" {
		pair = definition.Name()
	}
	return map[string]string{
		"zasp-proof":        "m1-33",
		"zasp-proof-marker": testMarker,
		"zasp-proof-role":   role,
		"zasp-queue-kind":   string(definition.Kind()),
		"zasp-schema-id":    definition.SchemaID(),
		"zasp-paired-queue": pair,
	}
}
