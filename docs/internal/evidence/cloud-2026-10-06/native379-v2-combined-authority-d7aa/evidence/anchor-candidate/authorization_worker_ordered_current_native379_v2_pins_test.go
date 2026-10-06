package apiserver

// Sole packet-derived trust-anchor companion. Excluded explicitly from the
// Node source roster to avoid a source/provenance/packet hash cycle; its bytes
// MUST remain in the full consumed Go closure and external root-owned envelope.
// Empty anchors refuse every native opt-in until final independent review.
const (
	orderedCurrentNative379V2PacketSHA256              = "d7aaea0657e9bdb8e512a3c0a332e3cf91296a50e6c967233829ec95f45a01ce"
	orderedCurrentNative379V2ModuleSHA256              = "4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74"
	orderedCurrentNative379V2ManifestSHA256            = "4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9"
	orderedCurrentNative379V2CollectorSHA256           = "97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f"
	orderedCurrentNative379V2SourceInventorySHA256     = "d3f6fac0d38478208fe1feff2f521a8b132b373aa8516771c62005a762a11ea4"
	orderedCurrentNative379V2GeneratedIdentitiesSHA256 = "9d1053e9310e27128404e45c2eeedce1dc6b42eaff004ecf0e0760c903b59f99"
	orderedCurrentNative379V2SourceFactDeltaSHA256     = "90325bea8205ec4e3f8eaa1de3c1fb0d814981cc6fbfd91e3c3e4ad3e6a9cdab"
)
