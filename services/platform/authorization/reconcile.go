package authorization

import (
	"context"
	fga "github.com/openfga/go-sdk/client"
)

type ProjectionSession interface {
	Snapshot(context.Context) (ProjectionSnapshot, error)
	Stage(context.Context, Revision, []fga.ClientTupleKey) error
	Acknowledge(context.Context, Revision, []fga.ClientTupleKey) error
}
type ProjectionRepository interface {
	WithOrganization(context.Context, string, func(ProjectionSession) error) error
}
type TupleWriter interface {
	Replace(context.Context, Revision, []fga.ClientTupleKey, []fga.ClientTupleKey) error
}
type ProjectionReceipt struct {
	Revision   Revision
	TupleCount int
	Applied    bool
}

func Reconcile(ctx context.Context, repository ProjectionRepository, writer TupleWriter, organizationID, storeID, modelID string) (ProjectionReceipt, error) {
	if ctx == nil || repository == nil || writer == nil {
		return ProjectionReceipt{}, ErrInvalid
	}
	var receipt ProjectionReceipt
	err := repository.WithOrganization(ctx, organizationID, func(session ProjectionSession) error {
		snapshot, err := session.Snapshot(ctx)
		if err != nil {
			return err
		}
		revision := snapshot.Revision
		if revision.validate() != nil || revision.OrganizationID != organizationID || revision.StoreID != storeID || revision.ModelID != modelID {
			return ErrPending
		}
		receipt.Revision = revision
		if revision.Desired == revision.Applied {
			receipt.Applied = true
			return nil
		}
		desired, err := Project(snapshot)
		if err != nil {
			return err
		}
		receipt.TupleCount = len(desired)
		// Stage the union of possibly-written tuple keys before service calls.
		// Partial delivery can then be cleaned up after a process crash.
		if err := session.Stage(ctx, revision, desired); err != nil {
			return err
		}
		if err := writer.Replace(ctx, revision, snapshot.Known, desired); err != nil {
			return err
		}
		if err := session.Acknowledge(ctx, revision, desired); err != nil {
			return err
		}
		receipt.Applied = true
		receipt.Revision.Applied = revision.Desired
		return nil
	})
	return receipt, err
}
