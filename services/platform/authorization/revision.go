package authorization

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"regexp"
)

var ErrPending = errors.New("authorization projection pending")
var ErrConflict = errors.New("authorization revision conflict; retry from Check")
var ErrBusy = errors.New("authorization projection already running")

type Revision struct {
	OrganizationID string `json:"organization_id"`
	Desired        int64  `json:"desired"`
	Applied        int64  `json:"applied"`
	Generation     int64  `json:"generation"`
	StoreID        string `json:"store_id"`
	ModelID        string `json:"model_id"`
}
type RevisionReader interface {
	Revision(context.Context, string) (Revision, error)
}
type CheckedDecision struct {
	Decision Decision
	Revision Revision
	Request  CheckRequest
}

func CheckRevision(ctx context.Context, reader RevisionReader, checker Checker, request CheckRequest, storeID, modelID string) (CheckedDecision, error) {
	if ctx == nil || reader == nil || checker == nil {
		return CheckedDecision{}, ErrInvalid
	}
	if _, err := Map(request); err != nil {
		return CheckedDecision{}, ErrInvalid
	}
	revision, err := reader.Revision(ctx, request.OrganizationID)
	if err != nil {
		return CheckedDecision{}, ErrUnavailable
	}
	if revision.validate() != nil || revision.OrganizationID != request.OrganizationID || revision.StoreID != storeID || revision.ModelID != modelID || revision.Desired != revision.Applied {
		return CheckedDecision{}, ErrPending
	}
	decision, err := checker.Check(ctx, request)
	if err != nil {
		return CheckedDecision{}, err
	}
	if decision.ModelID != revision.ModelID {
		return CheckedDecision{}, ErrConflict
	}
	current, err := reader.Revision(ctx, request.OrganizationID)
	if err != nil {
		return CheckedDecision{}, ErrUnavailable
	}
	if current != revision {
		return CheckedDecision{}, ErrConflict
	}
	return CheckedDecision{Decision: decision, Revision: revision, Request: request}, nil
}

var projectionULID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func (r Revision) validate() error {
	if _, err := domain.ParseProductID(r.OrganizationID); err != nil || r.Desired < 1 || r.Applied < 0 || r.Applied > r.Desired || r.Generation < 1 || !projectionULID.MatchString(r.StoreID) || !projectionULID.MatchString(r.ModelID) {
		return ErrInvalid
	}
	return nil
}
