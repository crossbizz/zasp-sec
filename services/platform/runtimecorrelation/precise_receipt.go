package runtimecorrelation

import (
	"crypto/sha256"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// EncodePreciseReceipt encodes only the precise V4 correlation contract.
func EncodePreciseReceipt(receipt Receipt) ([]byte, [sha256.Size]byte, domain.EvidenceRef, error) {
	return encodeReceiptProfile(receipt, true)
}

// DecodePreciseReceipt accepts only canonical precise V4 receipts.
func DecodePreciseReceipt(body []byte) (Receipt, error) {
	return decodeReceiptProfile(body, true)
}
