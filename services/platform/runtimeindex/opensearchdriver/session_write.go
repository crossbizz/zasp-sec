package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type SessionWriteResult struct {
	Scope         domain.Scope
	BatchID       domain.ProductID
	Generation    int64
	ReceiptDigest [sha256.Size]byte
	DocumentIDs   []string
}

type sessionMultiGetResponse struct {
	Documents []struct {
		Index       string          `json:"_index"`
		ID          string          `json:"_id"`
		Version     int64           `json:"_version"`
		Sequence    *int64          `json:"_seq_no"`
		PrimaryTerm int64           `json:"_primary_term"`
		Found       bool            `json:"found"`
		Source      json.RawMessage `json:"_source"`
	} `json:"docs"`
}

// Apply issues one immutable create request, then checks every exact document
// and explicitly refreshes the index. A lost acknowledgement is reconciled from
// state without blindly reissuing writes. Nothing is marked searchable until
// both readback and refresh succeed. The caller must hold committed PG authority.
func (index *SessionIndex) Apply(ctx context.Context, binding sessionsearch.ReceiptBinding, receiptBody, archiveBody []byte) (SessionWriteResult, error) {
	return index.applyProfile(ctx, binding, receiptBody, archiveBody, false)
}

func (index *SessionIndex) applyProfile(ctx context.Context, binding sessionsearch.ReceiptBinding, receiptBody, archiveBody []byte, precise bool) (SessionWriteResult, error) {
	build := sessionsearch.BuildDocuments
	if precise {
		if index == nil || !index.sandboxV2 {
			return SessionWriteResult{}, runtimeindex.ErrRejected
		}
		build = sessionsearch.BuildPreciseDocuments
	}
	documents, err := build(binding, receiptBody, archiveBody)
	if err != nil {
		return SessionWriteResult{}, runtimeindex.ErrRejected
	}
	if index == nil || index.transport == nil {
		return SessionWriteResult{}, runtimeindex.ErrConfiguration
	}
	if !index.sandboxV2 {
		receipt, err := runtimeprojection.DecodeReceipt(receiptBody)
		if err != nil || receipt.ImplementationVersion != "runtime-projection-v1" {
			return SessionWriteResult{}, runtimeindex.ErrRejected
		}
	}
	var body bytes.Buffer
	ids := make([]string, len(documents))
	for i, document := range documents {
		var action bulkAction
		action.Create.Index, action.Create.ID = index.indexName(), document.DocumentID
		encodedAction, err := json.Marshal(action)
		if err != nil {
			return SessionWriteResult{}, runtimeindex.ErrRejected
		}
		encodedDocument, err := json.Marshal(document)
		if err != nil || body.Len()+len(encodedAction)+len(encodedDocument)+2 > index.transport.config.MaximumRequestBytes {
			return SessionWriteResult{}, runtimeindex.ErrRejected
		}
		body.Write(encodedAction)
		body.WriteByte('\n')
		body.Write(encodedDocument)
		body.WriteByte('\n')
		ids[i] = document.DocumentID
	}
	if err := index.Ready(ctx); err != nil {
		return SessionWriteResult{}, err
	}
	path := "/" + index.indexName() + "/_bulk?refresh=wait_for&timeout=" + strconv.Itoa(int(index.transport.config.RequestTimeout/time.Second)) + "s"
	result, writeErr := index.transport.request(ctx, http.MethodPost, path, "application/x-ndjson", body.Bytes(), true)
	if writeErr == nil && result.status != http.StatusOK {
		if err := classifyStatus(result.status, true); err == runtimeindex.ErrDenied || err == runtimeindex.ErrRejected {
			return SessionWriteResult{}, err
		}
	}
	// Bulk ACKs and per-item errors are not completion evidence. Reconcile even
	// partial responses and transport failures using exact immutable source bytes.
	if err := index.exactDocuments(ctx, documents, ids); err != nil {
		return SessionWriteResult{}, err
	}
	result, err = index.transport.request(ctx, http.MethodPost, "/"+index.indexName()+"/_refresh", "", nil, false)
	if err != nil {
		return SessionWriteResult{}, err
	}
	if result.status != http.StatusOK {
		return SessionWriteResult{}, sessionReadStatus(result.status)
	}
	var refreshed struct {
		Shards *struct {
			Total      int  `json:"total"`
			Successful int  `json:"successful"`
			Failed     *int `json:"failed"`
		} `json:"_shards"`
	}
	if decodeSessionResponse(result.body, &refreshed) != nil || refreshed.Shards == nil || refreshed.Shards.Failed == nil || refreshed.Shards.Total < 1 {
		return SessionWriteResult{}, runtimeindex.ErrDrift
	}
	if *refreshed.Shards.Failed != 0 || refreshed.Shards.Successful != refreshed.Shards.Total {
		return SessionWriteResult{}, runtimeindex.ErrRetryable
	}
	return SessionWriteResult{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ReceiptDigest: binding.ReceiptDigest, DocumentIDs: ids}, nil
}

func (index *SessionIndex) exactDocuments(ctx context.Context, expected []sessionsearch.Document, ids []string) error {
	body, err := json.Marshal(struct {
		IDs []string `json:"ids"`
	}{IDs: ids})
	if err != nil {
		return runtimeindex.ErrRejected
	}
	result, err := index.transport.request(ctx, http.MethodPost, "/"+index.indexName()+"/_mget?realtime=true", "application/json", body, false)
	if err != nil {
		return err
	}
	if result.status != http.StatusOK {
		return sessionReadStatus(result.status)
	}
	var response sessionMultiGetResponse
	if decodeSessionResponse(result.body, &response) != nil || len(response.Documents) != len(expected) {
		return runtimeindex.ErrDrift
	}
	for i, document := range response.Documents {
		if document.Index != index.indexName() || document.ID != expected[i].DocumentID {
			return runtimeindex.ErrDrift
		}
		if !document.Found {
			return runtimeindex.ErrUnknownOutcome
		}
		var source sessionsearch.Document
		canonical, marshalErr := json.Marshal(expected[i])
		if document.Version != 1 || document.Sequence == nil || *document.Sequence < 0 || document.PrimaryTerm < 1 || marshalErr != nil || decodeSessionResponse(document.Source, &source) != nil || source != expected[i] || !equalCanonicalJSON(document.Source, canonical) {
			return runtimeindex.ErrDrift
		}
	}
	return nil
}
