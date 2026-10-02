package redteamadapter

import "github.com/zasp-ai/zasp-sec/services/platform/authorization"

// This discriminator is constructor-owned. Neither a request nor a failed
// query can select another journal family.
type workerJournalFamily uint8

const (
	workerJournalNone workerJournalFamily = iota
	workerJournalSingle74
	workerJournalOrdered68
)

func NewWorkerOrderedTestPostgresJournal(database JSONDatabase, checksum, fingerprint string, forward, compensation *authorization.WorkerExecutor) (*TemporalPostgresJournal, error) {
	if forward == nil || compensation == nil {
		return nil, ErrAdapter
	}
	j, err := NewTemporalPostgresJournal(database, checksum, fingerprint)
	if err != nil {
		return nil, err
	}
	j.forward, j.compensation, j.workerFamily = forward, compensation, workerJournalOrdered68
	return j, nil
}

// Both families use signed journals. The retained selector reads only the
// persisted native owner; invocation failure never selects the other family.
func NewWorkerTestEffectRouter(database JSONDatabase, single, ordered *TemporalPostgresJournal) (*TestEffectRouter, error) {
	if nilJSONDatabase(database) || single == nil || ordered == nil || single.workerFamily != workerJournalSingle74 || ordered.workerFamily != workerJournalOrdered68 || single.forward == nil || single.compensation == nil || ordered.forward == nil || ordered.compensation == nil {
		return nil, ErrAdapter
	}
	return &TestEffectRouter{database: database, single: single, ordered: ordered}, nil
}

func (j *TemporalPostgresJournal) workerOperation(op string) (authorization.WorkerOperation, error) {
	if j == nil || j.forward == nil || j.compensation == nil {
		return "", ErrAdapter
	}
	switch j.workerFamily {
	case workerJournalSingle74:
		switch op {
		case "resolve":
			return "test74.adapter.resolve", nil
		case "start":
			return "test74.adapter.start", nil
		case "complete":
			return "test74.adapter.complete", nil
		}
	case workerJournalOrdered68:
		switch op {
		case "resolve":
			return "ordered68.adapter.resolve", nil
		case "start":
			return "ordered68.adapter.start", nil
		case "complete":
			return "ordered68.adapter.complete", nil
		}
	}
	return "", ErrAdapter
}
