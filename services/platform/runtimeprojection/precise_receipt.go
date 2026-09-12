package runtimeprojection

import (
	"crypto/sha256"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// EncodePreciseReceipt serializes only the precise projection V3 contract.
func EncodePreciseReceipt(receipt Receipt) ([]byte, [sha256.Size]byte, domain.EvidenceRef, error) {
	return encodeReceiptProfile(receipt, true)
}

// DecodePreciseReceipt accepts only canonical precise projection V3 receipts.
func DecodePreciseReceipt(body []byte) (Receipt, error) { return decodeReceiptProfile(body, true) }
