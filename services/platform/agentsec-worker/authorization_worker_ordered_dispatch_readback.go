package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type orderedDispatchReadbackExecutor interface {
	ExecuteOrderedTestDispatchReadback(context.Context, authorization.WorkerDecision) (json.RawMessage, error)
}

func (d *workerOrderedTestDatabase) DispatchOrderedTestLinked(ctx context.Context, raw json.RawMessage, verify func(json.RawMessage) error) (json.RawMessage, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || verify == nil || nilWorkerDependency(d.forward) || nilWorkerDependency(d.compensation) {
		return nil, authorization.ErrInvalid
	}
	op, captured, err := d.route(`SELECT zasp_temporal68.linked($1::jsonb)`, raw)
	if err != nil || captured || op != "ordered68.linked.dispatch" {
		return nil, authorization.ErrInvalid
	}
	reader, ok := d.forward.(orderedDispatchReadbackExecutor)
	if !ok {
		return nil, authorization.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	decision, err := d.forward.Authorize(bounded, op, append(json.RawMessage(nil), raw...))
	if err != nil {
		return nil, err
	}
	prior, err := reader.ExecuteOrderedTestDispatchReadback(bounded, decision)
	if err != nil {
		return nil, err
	}
	// A panic also unwinds before Execute. No callback or decision is retained.
	if err = verify(prior); err != nil {
		return nil, err
	}
	if bounded.Err() != nil {
		return nil, authorization.ErrUnavailable
	}
	return d.forward.Execute(bounded, decision)
}

var _ apiserver.OrderedTestLinkedDispatcher = (*workerOrderedTestDatabase)(nil)
