package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// EnrollmentBinding identifies one scoped enrollment independently of token
// generations. It is a public comparison constraint, never authentication or
// tenant authority. Consumers must compare it with authenticated server scope
// and sensor identity; a matching caller-supplied hash grants no permission.
func EnrollmentBinding(scope domain.Scope, sensorID domain.ProductID) (string, error) {
	if scope.Validate() != nil || sensorID.IsZero() {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte("zasp.sensor-enrollment.v1\x00" + strings.Join([]string{
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID.String(),
	}, "\x00")))
	return hex.EncodeToString(digest[:]), nil
}
