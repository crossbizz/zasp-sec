package apiserver

import "testing"

// Consumes the complete pinned 23-file packet through the actual adapter loader,
// catching manifest representation mismatches that three-file pin tests miss.
func TestPrivateReferenceFullLoader(t *testing.T) {
	input, err := loadPrivateReferenceInputs(privateReferenceFrozen)
	if err != nil || len(input.Paths) != 24 || len(input.DDL) == 0 || len(input.Query) == 0 || input.Contract.Shape.MaxRows != 39 {
		t.Fatal("actual fixed packet loader refused", err)
	}
}
