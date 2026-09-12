package sessionsearch

// BuildPreciseDocuments requires a committed V3 receipt and its exact V2 archive.
// It does not opt legacy consumers into the precise contract.
func BuildPreciseDocuments(binding ReceiptBinding, receiptBody, archiveBody []byte) ([]Document, error) {
	return buildDocuments(binding, receiptBody, archiveBody, true)
}
