package main

import "testing"

func TestQueueDefinitionsMainContractIsExact(t *testing.T) {
	result := QueueDefinitionsProofResult{
		Queues: 3, DLQs: 3, Schemas: 3,
		Retention: true, Redrive: true, Cleanup: true, Audit: true,
	}
	if queueDefinitionsChildSuccess !=
		"LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true." {
		t.Fatalf("queueDefinitionsChildSuccess = %q", queueDefinitionsChildSuccess)
	}
	if formatQueueDefinitionsChildSuccess(result) != queueDefinitionsChildSuccess {
		t.Fatal("formatted queue definitions success does not match main contract")
	}
	var entrypoint func() = runQueueDefinitionsProofMain
	if entrypoint == nil {
		t.Fatal("queue definitions entrypoint is nil")
	}
}
