package migrations

import (
	"context"
	"testing"
)

// These exercise the actual installer admission frame, not database internals.
// Existing native original-owner/RLS acceptance remains separately mandatory.
func bindingInstaller(r *Runner, profile string) func(context.Context) error {
	switch profile {
	case "approval":
		return r.UpProductionApprovalMaintenanceProfile
	case "connector":
		return r.UpProductionConnectorMaintenance
	case "activation":
		return r.UpProductionApprovalActivationProfile
	case "settlement":
		return r.UpProductionApprovalSettlementAuditProfile
	case "optional-normal":
		return r.UpProductionOptionalEgressProfile
	case "optional-audit":
		return r.UpProductionOptionalEgressAuditProfile
	case "class-normal":
		return r.UpProductionEnvironmentClassProfile
	case "class-audit":
		return r.UpProductionEnvironmentClassAuditProfile
	}
	return nil
}
func TestInstallerBindingRefusalUsesBoundedAuthorityBeforeOwnerDDL(t *testing.T) {
	for _, profile := range []string{"approval", "connector", "activation", "settlement", "optional-normal", "optional-audit", "class-normal", "class-audit"} {
		t.Run(profile, func(t *testing.T) {
			tx := newMaintenanceRoleTransaction("none")
			tx.denyBinding = true
			r, err := NewRunner(maintenanceRoleDatabase{tx})
			if err != nil {
				t.Fatal(err)
			}
			err = bindingInstaller(r, profile)(context.Background())
			if err == nil || tx.committed || !tx.rolledBack || tx.ownerDDL != 0 {
				t.Fatal("unregistered binding passed admission, mutated owner DDL, or committed")
			}
			if tx.bindingReads == 0 || tx.outsideBindingReads != 0 {
				t.Fatal("binding admission queried protected relation outside existing authority role")
			}
		})
	}
}
func TestEnvironmentClassBindingAdmissionExistingProfile(t *testing.T) {
	for _, profile := range []string{"class-normal", "class-audit"} {
		for _, incoming := range []string{"none", "registered_source_login"} {
			t.Run(profile+"/"+incoming, func(t *testing.T) {
				tx := newMaintenanceRoleTransaction(incoming)
				tx.profilePresent = true
				r, err := NewRunner(maintenanceRoleDatabase{tx})
				if err != nil {
					t.Fatal(err)
				}
				err = bindingInstaller(r, profile)(context.Background())
				if err != nil || !tx.committed || tx.rolledBack || tx.ownerDDL != 0 || tx.bindingReads == 0 || tx.outsideBindingReads != 0 || tx.restores == 0 {
					t.Fatalf("registered original owner could not revalidate exact existing class profile: %v", err)
				}
			})
		}
	}
}
