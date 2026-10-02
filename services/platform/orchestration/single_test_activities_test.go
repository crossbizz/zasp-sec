package orchestration

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

func TestSingleTestCleanupActivityErrorContract(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		kind      string
		permanent bool
	}{
		{"proved", nil, "", false},
		{"pending", ErrCleanupPending, "CleanupPending", true},
		{"unavailable", errors.New("controlled transport failure"), "ProductUnavailable", false},
		{"deadline", context.DeadlineExceeded, "ProductUnavailable", false},
		{"authority", ErrConflict, "ProductRefused", true},
		{"invalid", ErrInvalid, "ProductRefused", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestActivityEnvironment()
			product := &singleTestProductFixture{cleanup: test.err}
			a := &SingleTestActivities{Product: product}
			env.RegisterActivity(a.Cleanup)
			_, err := env.ExecuteActivity(a.Cleanup, CleanupRequest{Start: request(), Reason: "terminal"})
			if test.err == nil {
				require.NoError(t, err)
			} else {
				var application *temporal.ApplicationError
				require.ErrorAs(t, err, &application)
				require.Equal(t, test.kind, application.Type())
				require.Equal(t, test.permanent, application.NonRetryable())
			}
			require.Equal(t, []string{"cleanup"}, product.operations)
		})
	}
}
