package providercollection

import (
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"strings"
	"testing"
)

func TestProductEffectArtifactIdentityAndPriorCheckpoint(t *testing.T) {
	request := testRequest(t, collection.ProviderAWS)
	request.Attempt = 0
	request.EffectID = strings.Repeat("a", 64)
	first, err := collectionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := collectionRequestDigest(request)
	if first != replay {
		t.Fatal("replay artifact identity changed")
	}
	request.EffectID = strings.Repeat("b", 64)
	next, _ := collectionRequestDigest(request)
	if first == next {
		t.Fatal("new safe retry reused artifact identity")
	}
	seed := collection.ResumeSeed{EffectID: strings.Repeat("a", 64), Cursor: collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "next"}, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion}
	document := manifestDocument{Version: manifestSchemaVersion, RequestDigest: strings.Repeat("c", 64), Provider: request.Provider, Subject: manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}, IntegrationID: request.IntegrationID.String(), ConnectionID: request.ConnectionID.String(), JobID: request.JobID.String(), EffectID: seed.EffectID, CollectorVersion: request.CollectorVersion, CursorProvider: seed.Cursor.Provider, CursorVersion: seed.Cursor.Version, CursorValue: seed.Cursor.Value, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Objects: []manifestDescriptor{{}}}
	if !validResumeManifest(document, request, seed) {
		t.Fatal("SQL-bound prior product effect cannot resume")
	}
	document.EffectID = request.EffectID
	if validResumeManifest(document, request, seed) {
		t.Fatal("unrecorded producing effect accepted")
	}
	document.EffectID = seed.EffectID
	document.Attempt = 1
	if validResumeManifest(document, request, seed) {
		t.Fatal("mixed legacy/product manifest accepted")
	}
}
