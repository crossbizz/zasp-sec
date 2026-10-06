package apiserver

// Sole packet-derived trust-anchor companion. Excluded explicitly from the
// Node source roster to avoid a source/provenance/packet hash cycle; its bytes
// MUST remain in the full consumed Go closure and external root-owned envelope.
// Empty anchors refuse every native opt-in until final independent review.
const (
	orderedCurrentNative379V2PacketSHA256              = ""
	orderedCurrentNative379V2ModuleSHA256              = ""
	orderedCurrentNative379V2ManifestSHA256            = ""
	orderedCurrentNative379V2CollectorSHA256           = ""
	orderedCurrentNative379V2SourceInventorySHA256     = ""
	orderedCurrentNative379V2GeneratedIdentitiesSHA256 = ""
	orderedCurrentNative379V2SourceFactDeltaSHA256     = ""
)
