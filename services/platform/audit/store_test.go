package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductAuditServiceRedactsAppendsAndQueriesWithoutMutationMethods(t *testing.T) {
	now := time.Date(2026, 8, 18, 14, 0, 0, 0, time.UTC)
	sequence := 900
	service, err := NewProductService(NewEventStore(), func() (domain.ProductID, error) {
		sequence++
		return auditFixtureID(t, sequence), nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := domain.NewScope(auditFixtureID(t, 910), auditFixtureID(t, 911), auditFixtureID(t, 912))
	event, err := service.Record(context.Background(), scope, ProductEventInput{
		Actor: auditFixtureID(t, 913), Action: "api_token.create", Target: auditFixtureID(t, 914), Outcome: OutcomeSucceeded,
		Metadata: map[string]string{"token": "zasp_pat_secret", "source": "identity_admin"},
	})
	if err != nil || event.Metadata()["token"] != "[REDACTED]" {
		t.Fatalf("Record() = %#v, %v", event, err)
	}
	values, err := service.Query(context.Background(), scope.OrganizationID(), 50, 0)
	if err != nil || len(values) != 1 || values[0].ID() != event.ID() || values[0].Metadata()["source"] != "identity_admin" {
		t.Fatalf("Query() = %#v, %v", values, err)
	}
	export, err := service.CreateExport(context.Background(), scope.OrganizationID(), event.Actor())
	if err != nil || export.EventCount() != 1 || export.Status() != "ready" {
		t.Fatalf("CreateExport() = %#v, %v", export, err)
	}
	loaded, err := service.GetExport(context.Background(), scope.OrganizationID(), export.ID())
	if err != nil || loaded != export {
		t.Fatalf("GetExport() = %#v, %v", loaded, err)
	}
}

func TestProductAuditExportCountsEveryAppendOnlyEvent(t *testing.T) {
	sequence := 2000
	service, err := NewProductService(NewEventStore(), func() (domain.ProductID, error) {
		sequence++
		return auditFixtureID(t, sequence), nil
	}, func() time.Time { return time.Date(2026, 8, 18, 15, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := domain.NewScope(auditFixtureID(t, 2100), auditFixtureID(t, 2101), auditFixtureID(t, 2102))
	for index := 0; index < 101; index++ {
		if _, err := service.Record(context.Background(), scope, ProductEventInput{
			Actor: auditFixtureID(t, 2103), Action: "api_token.create", Target: auditFixtureID(t, 2104),
			Outcome: OutcomeSucceeded, Metadata: map[string]string{"sequence": fmt.Sprint(index)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	export, err := service.CreateExport(context.Background(), scope.OrganizationID(), auditFixtureID(t, 2103))
	if err != nil || export.EventCount() != 101 {
		t.Fatalf("CreateExport() count = %d, %v", export.EventCount(), err)
	}
}

func auditFixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
