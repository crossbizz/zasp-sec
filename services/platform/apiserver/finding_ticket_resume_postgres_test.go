package apiserver

import "testing"

func TestV3FindingTicketResumeOnInstalledBaseline(t *testing.T) {
	b := startInstalledV2Baseline(t)
	owner := b.member("security_admin", "view")
	peer := b.member("security_admin", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	finding, delivery := b.id(), b.id()
	const key = "finding-ticket-before-upgrade"
	b.seed(func() {
		b.exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Evidence review','high','open')`, b.o, b.w, b.e, finding)
		b.exec(`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, b.o, b.w, b.e, finding, b.id())
		b.exec(`INSERT INTO zasp_finding_ticket_deliveries(organization_id,workspace_id,environment_id,delivery_id,principal_id,finding_id,expected_version,idempotency_key,correlation_id,payload,payload_digest,destination_url,secret_reference,state) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,'{}',decode(repeat('ab',32),'hex'),'https://example.invalid/tickets','secret_ref_review_test','retryable')`, b.o, b.w, b.e, delivery, owner.identity.PrincipalID.String(), finding, key, b.id())
	})
	read := func(actor installedPrincipal, ticket, pending string) {
		t.Helper()
		ctx, err := b.checked(actor, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": finding}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := repo.GetRiskFinding(ctx, b.scope, finding)
		if err != nil || value.CurrentTicketID != ticket || value.PendingTicketKey != pending {
			t.Fatalf("ticket %q, pending %q, error %v", value.CurrentTicketID, value.PendingTicketKey, err)
		}
	}
	read(owner, "", key)
	read(peer, "", "")
	b.seed(func() {
		b.exec(`UPDATE zasp_finding_ticket_deliveries SET state='completed',ticket_id='CASE-42',completed_at=now() WHERE delivery_id=$1`, delivery)
	})
	read(owner, "CASE-42", "")
	read(peer, "", "")
	b.seed(func() { b.exec(`UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, finding) })
	read(owner, "", "")
}
