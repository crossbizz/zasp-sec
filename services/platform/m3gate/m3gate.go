package m3gate

import "errors"

var ErrGate = errors.New("M3 gate evidence rejected")

type Evidence struct {
	ConnectorAssets            int
	SensorSupported            bool
	OTLPEvents                 int
	TetragonEvents             int
	BatchIDStable              bool
	ArchiveIndexLinked         bool
	ReplayIdempotent           bool
	DLQMessages                int
	LastKnownInventoryRetained bool
	Freshness                  string
}

type Report struct {
	Status string
	Checks int
}

func Evaluate(value Evidence) (Report, error) {
	connector := value.ConnectorAssets > 0 && value.ConnectorAssets <= 100_000
	sensor := value.SensorSupported
	ingest := value.OTLPEvents > 0 && value.OTLPEvents <= 10_000 && value.TetragonEvents >= 3 && value.TetragonEvents <= 10_000
	durable := value.BatchIDStable && value.ArchiveIndexLinked && value.ReplayIdempotent && value.DLQMessages == 0
	freshness := value.LastKnownInventoryRetained && value.Freshness == "stale"
	if !connector || !sensor || !ingest || !durable || !freshness {
		return Report{}, ErrGate
	}
	return Report{Status: "PASS", Checks: 5}, nil
}
