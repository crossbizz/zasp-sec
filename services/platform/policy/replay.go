package policy

import (
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// ReplayWindow bounds the deterministic evaluation to indexed events for one agent.
// From is inclusive and To is exclusive, so adjacent windows never double count.
type ReplayWindow struct {
	AgentID string    `json:"agent_id"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
}

func (w ReplayWindow) Valid() bool {
	_, err := domain.ParseProductID(w.AgentID)
	return err == nil && !w.From.IsZero() && w.From.Before(w.To) && w.To.Sub(w.From) <= 30*24*time.Hour && w.From.Nanosecond()%1_000_000 == 0 && w.To.Nanosecond()%1_000_000 == 0
}
