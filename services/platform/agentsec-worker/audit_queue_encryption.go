package main

import (
	"regexp"
	"strings"
)

func validAuditQueueEncryption(mode string) bool {
	return mode == "" || mode == "aws-kms" || mode == "provider-managed"
}

var auditQueueKMSKeyID = regexp.MustCompile(`^key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

// Terraform configures key ARNs when using KMS. Queue metadata must identify
// a key in the same region and AWS account as the expected queue.
func auditQueueEncryptionMatches(mode, queueARN string, attributes map[string]string) bool {
	if attributes["QueueArn"] != queueARN {
		return false
	}
	key, hasKey := attributes["KmsMasterKeyId"]
	managed, hasManaged := attributes["SqsManagedSseEnabled"]
	switch mode {
	case "provider-managed":
		return managed == "true" && !hasKey
	case "aws-kms":
		if hasManaged && managed != "false" {
			return false
		}
		parts := strings.Split(queueARN, ":")
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "sqs" {
			return false
		}
		prefix := "arn:aws:kms:" + parts[3] + ":" + parts[4] + ":"
		id, ok := strings.CutPrefix(key, prefix)
		return ok && auditQueueKMSKeyID.MatchString(id)
	default:
		return false
	}
}
