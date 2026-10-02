package apiserver

import (
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

// Infrastructure contention cannot tell a caller its evidence version changed.
func TestComplianceConflictClassification(t *testing.T) {
	for _, tc := range []struct {
		code, message string
		changed       bool
	}{
		{"40001", "compliance source_changed", true},
		{"40001", "serialization failure", false},
		{"40P01", "deadlock detected", false},
		{"23505", "duplicate key", false},
	} {
		err := complianceRepositoryError(classifyPostgresError(&pgconn.PgError{Code: tc.code, Message: tc.message}))
		if errors.Is(err, ErrComplianceSourceChanged) != tc.changed {
			t.Errorf("%s/%s: %v", tc.code, tc.message, err)
		}
	}
}
