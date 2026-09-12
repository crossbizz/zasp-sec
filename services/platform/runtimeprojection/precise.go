package runtimeprojection

// ProjectPrecise consumes V4 correlation results bound by the caller to an
// authenticated predecessor receipt and its V2 archive.
func ProjectPrecise(input Batch) (ProjectedBatch, error) {
	return projectProfile(input, true, true)
}
