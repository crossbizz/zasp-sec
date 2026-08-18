package m4gate

import "errors"

var ErrGate = errors.New("M4 gate rejected")

type Fixture struct {
	Inventory, Capability, Posture, AttackPath, ExposureUX bool
}

type Report struct {
	Status string
	Checks int
}

func Evaluate(value Fixture) (Report, error) {
	if !value.Inventory || !value.Capability || !value.Posture || !value.AttackPath || !value.ExposureUX {
		return Report{}, ErrGate
	}
	return Report{Status: "PASS", Checks: 5}, nil
}
