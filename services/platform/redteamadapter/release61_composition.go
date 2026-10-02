package redteamadapter

import (
	"context"
	"time"
)

// Release61 explicitly selects the dormant ordered journal. It neither installs
// an HTTP handler nor changes the historical/default journal's authority.
func (j *PostgresInvocationJournal) Release61(ctx context.Context) (*PostgresInvocationJournal, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAdapter
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ordered, err := j.ordered()
	if err != nil || ordered.Ready(bounded) != nil {
		return nil, ErrAdapter
	}
	return ordered, nil
}
