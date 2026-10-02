package apiserver

// This file is the sole trust-anchor companion. Root binds its bytes outside
// packet manifests, so manifest pins can bind the other three producer files
// without a self-referential hash cycle. Empty pins keep capture closed until
// root accepts a complete immutable packet for that variant.
type consolidatedReferencePacketPins struct {
	Variant, SessionUser, ManifestSHA256, ContractSHA256 string
}

const consolidatedReferenceVariantAManifestSHA256 = ""
const consolidatedReferenceVariantAContractSHA256 = ""
const consolidatedReferenceVariantBManifestSHA256 = ""
const consolidatedReferenceVariantBContractSHA256 = ""

func consolidatedReferenceVariantAPins() consolidatedReferencePacketPins {
	return consolidatedReferencePacketPins{Variant: "A", SessionUser: "zasp_test", ManifestSHA256: consolidatedReferenceVariantAManifestSHA256, ContractSHA256: consolidatedReferenceVariantAContractSHA256}
}

func consolidatedReferenceVariantBPins() consolidatedReferencePacketPins {
	return consolidatedReferencePacketPins{Variant: "B", SessionUser: "zasp_e2e", ManifestSHA256: consolidatedReferenceVariantBManifestSHA256, ContractSHA256: consolidatedReferenceVariantBContractSHA256}
}
