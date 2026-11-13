package apiserver

import (
	"context"
	"net/http"
)

// complianceReadSurface mounts only the checked compliance source reads. It
// owns no export repository and no artifact reader, so a deployment without
// export storage still serves controls and evidence through the same
// authorized statement instead of the unported administration fallback.
type complianceReadSurface struct{ handler *complianceHTTPHandler }

func complianceReadOperation(operation string) bool {
	return stringIn(operation, "listComplianceControls", "listComplianceEvidence", "getComplianceEvidence")
}

func (s *complianceReadSurface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, routed := RoutedOperationFromRequest(r)
	if s == nil || s.handler == nil || s.handler.source == nil || r == nil || !routed || r.Method != http.MethodGet || !complianceReadOperation(route.OperationID) {
		writeComplianceError(w, r, ErrRepositoryNotFound)
		return
	}
	s.handler.ServeHTTP(w, r)
}

func (s *complianceReadSurface) Ready(ctx context.Context) error {
	if s == nil || s.handler == nil {
		return ErrRepositoryUnavailable
	}
	return s.handler.source.Ready(ctx)
}

// NewComplianceReadHandler is the storage-free compliance surface for current
// authorization. Legacy deployments keep their existing administration reads.
func NewComplianceReadHandler(ctx context.Context, db JSONDatabase, cursorSigningKey []byte) (ComplianceProductionHandler, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(db) || !currentAuthorizationRequired(db) || !validAuditExportCursorKey(cursorSigningKey) {
		return nil, ErrRepositoryConfiguration
	}
	source, err := NewComplianceRepository(db)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &complianceReadSurface{&complianceHTTPHandler{source: source, signingKey: append([]byte(nil), cursorSigningKey...)}}, nil
}
