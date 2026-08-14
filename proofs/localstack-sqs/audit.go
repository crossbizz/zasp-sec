package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

func runAuditMain() {
	if len(os.Args) != 2 || os.Args[1] != "audit" {
		failMain("configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := newSDKQueueClient(ctx, os.Getenv("AWS_ENDPOINT_URL"))
	if err != nil {
		failMain("configuration")
	}
	urls, err := client.ListQueues(ctx, queuePrefix)
	if err != nil || len(urls) != 0 {
		failMain("operation")
	}
	fmt.Println("LocalStack SQS audit passed: proof_queues=0.")
}
