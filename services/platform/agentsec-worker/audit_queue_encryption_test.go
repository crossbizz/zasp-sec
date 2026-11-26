package main

import "testing"

func TestAuditQueueEncryptionRejectsDrift(t *testing.T) {
	const arn = "arn:aws:sqs:us-east-1:123456789012:agentsec-audit-exports"
	const key = "arn:aws:kms:us-east-1:123456789012:key/145d67a6-e462-4944-a3ba-0f68bcc17737"
	for _, test := range []struct {
		name       string
		mode       string
		queue      string
		attributes map[string]string
		want       bool
	}{
		{"sqs", "provider-managed", arn, map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "true"}, true},
		{"kms", "aws-kms", arn, map[string]string{"QueueArn": arn, "KmsMasterKeyId": key}, true},
		{"kms-flag-false", "aws-kms", arn, map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "false", "KmsMasterKeyId": key}, true},
		{"wrong-mode", "unknown", arn, map[string]string{"QueueArn": arn, "KmsMasterKeyId": key}, false},
		{"missing-mode", "", arn, map[string]string{"QueueArn": arn, "KmsMasterKeyId": key}, false},
		{"missing-metadata", "provider-managed", arn, nil, false},
		{"unencrypted", "provider-managed", arn, map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "false"}, false},
		{"both-modes", "provider-managed", arn, map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "true", "KmsMasterKeyId": key}, false},
		{"both-modes-kms", "aws-kms", arn, map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "true", "KmsMasterKeyId": key}, false},
		{"dlq-crossed", "provider-managed", arn + "-dlq", map[string]string{"QueueArn": arn, "SqsManagedSseEnabled": "true"}, false},
		{"bad-key", "aws-kms", arn, map[string]string{"QueueArn": arn, "KmsMasterKeyId": "alias/aws/sqs"}, false},
		{"bad-queue", "aws-kms", "bad", map[string]string{"QueueArn": "bad", "KmsMasterKeyId": key}, false},
		{"cross-account", "aws-kms", arn, map[string]string{"QueueArn": arn, "KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789011:key/145d67a6-e462-4944-a3ba-0f68bcc17737"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := auditQueueEncryptionMatches(test.mode, test.queue, test.attributes); got != test.want {
				t.Fatalf("queue encryption match = %t, want %t", got, test.want)
			}
		})
	}
	for mode, want := range map[string]bool{"": true, "aws-kms": true, "provider-managed": true, "none": false, " provider-managed": false} {
		if got := validAuditQueueEncryption(mode); got != want {
			t.Errorf("valid mode %q = %t, want %t", mode, got, want)
		}
	}
}
