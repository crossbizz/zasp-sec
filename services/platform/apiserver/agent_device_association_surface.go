package apiserver

import (
	"crypto/rand"
	"net/http"
)

func isAgentDeviceAssociationOperation(op string) bool {
	return stringIn(op, "createAgentDeviceIntent", "activateAgentDeviceAssociation", "revokeAgentDeviceAssociation", "listAgentDeviceAssociations")
}
func newAgentDeviceAssociationNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return nil, ErrRepositoryUnavailable
	}
	return b, nil
}

type agentDeviceAssociationSurface struct{ fallback, associations http.Handler }

func (s *agentDeviceAssociationSurface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op, ok := RoutedOperationFromRequest(r)
	if ok && isAgentDeviceAssociationOperation(op.OperationID) {
		s.associations.ServeHTTP(w, r)
		return
	}
	s.fallback.ServeHTTP(w, r)
}
