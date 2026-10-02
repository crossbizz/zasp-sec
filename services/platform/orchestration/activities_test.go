package orchestration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/temporal"
)

// Closing resources before a running provider/compensation joins would break
// this test. An expired drain keeps the caller responsible for those resources.
func TestActivitiesDrainRetainsActiveCompensation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	product := &blockingCleanupProduct{workflowProductFixture: workflowProductFixture{}, entered: entered, release: release}
	activities := &Activities{Product: product}
	done := make(chan error, 1)
	go func() {
		done <- activities.Cleanup(context.Background(), CleanupRequest{Start: request(), Reason: "workflow_cancelled"})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, activities.Close(ctx), context.DeadlineExceeded)
	require.Error(t, activities.Plan(context.Background(), request()), "closing runtime accepted fresh work")
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, activities.Close(context.Background()))
}

type blockingCleanupProduct struct {
	workflowProductFixture
	entered, release chan struct{}
}

func (p *blockingCleanupProduct) Cleanup(context.Context, CleanupRequest) error {
	close(p.entered)
	<-p.release
	return nil
}

func TestActivityErrorsDoNotLeakProviderDetails(t *testing.T) {
	for _, err := range []error{errors.New("Bearer secret-token provider-response-body"), ErrInvalid, ErrConflict} {
		result := activityError(err)
		require.False(t, strings.Contains(result.Error(), "secret-token"))
		require.False(t, strings.Contains(result.Error(), "provider-response-body"))
		var app *temporal.ApplicationError
		require.ErrorAs(t, result, &app)
		require.Equal(t, err == ErrInvalid || err == ErrConflict, app.NonRetryable())
	}
}
