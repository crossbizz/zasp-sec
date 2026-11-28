package apiserver

import (
	"context"
	"encoding/json"
)

const (
	memberLifecycleReadSQL  = `SELECT zasp_authorization80.member_lifecycle_read($1,$2,$3,$4,$5,$6,$7,$8)`
	memberLifecycleWriteSQL = `SELECT zasp_authorization80.member_lifecycle_write($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`
)

// MemberDirectory resolves organization members and delivers their sign-in invitations.
type MemberDirectory interface {
	DeliverMemberInvitation(context.Context, string, string, bool, func(string, bool) error) (string, error)
	MemberProfiles(context.Context, string, []string) ([]DirectoryMember, error)
}

// Existing Stytch accounts need different mail depending on their provider
// status. Check for an already-active product membership before sending, and
// recover an uncertain invite delivery without sending a second signup link.
func (p *RepositoryIdentityProvider) DeliverMemberInvitation(ctx context.Context, org, email string, resuming bool, prepareDelivery func(string, bool) error) (string, error) {
	driver := p.memberDirectoryDriver()
	if prepareDelivery == nil {
		return "", ErrRepositoryOperation
	}
	if driver == nil {
		return "", ErrRepositoryUnavailable
	}
	prior, err := driver.lookupDirectoryMember(ctx, org, email)
	if err != nil {
		return "", ErrRepositoryUnavailable
	}
	if prior == nil {
		if err := prepareDelivery("", false); err != nil {
			return "", err
		}
	} else {
		if err := prepareDelivery(prior.Reference, prior.Status == "active"); err != nil {
			return "", err
		}
		if resuming && prior.Status == "invited" {
			return prior.Reference, nil
		}
	}
	delivered, err := driver.sendMemberLink(ctx, org, email, prior != nil && prior.Status == "active")
	if err != nil || prior != nil && prior.Reference != delivered.MemberReference {
		return "", ErrRepositoryUnavailable
	}
	return delivered.MemberReference, nil
}

func (p *RepositoryIdentityProvider) memberDirectoryDriver() *stytchSessionDriver {
	if p == nil {
		return nil
	}
	auth, ok := p.authenticator.(*StytchOAuthAuthenticator)
	if !ok || auth == nil || p.redirectURI == "" {
		return nil
	}
	return &stytchSessionDriver{baseURL: auth.baseURL, client: auth.client, project: auth.project, secret: auth.secret, inviteRedirectURL: p.redirectURI}
}

type memberInvitationWrite struct {
	Phase           string `json:"phase"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	Role            string `json:"role"`
	Key             string `json:"key"`
	MemberReference string `json:"member_reference,omitempty"`
	LoginLink       bool   `json:"login_link,omitempty"`
}

func (r *PostgresRepository) mutateMember(ctx context.Context, identity RequestIdentity, m administrationMutation) (json.RawMessage, error) {
	write := func(body any) (json.RawMessage, error) {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, ErrRepositoryOperation
		}
		return r.preconditionedAdministrationMutation(ctx, memberLifecycleWriteSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), m.Operation, m.ID, data, m.AuditID)
	}
	if m.Operation != "inviteMember" {
		return write(struct {
			Version int64  `json:"version"`
			Name    string `json:"display_name,omitempty"`
		}{m.ExpectedVersion, m.Name})
	}
	if nilInterface(r.memberDirectory) {
		return nil, ErrRepositoryUnavailable
	}
	body := memberInvitationWrite{Phase: "reserve", Email: m.Email, DisplayName: m.Name, Role: m.Role, Key: m.IdempotencyKey}
	payload, err := write(body)
	if err != nil {
		return nil, err
	}
	var reservation struct {
		Organization string `json:"_deliver_to"`
		Resuming     bool   `json:"_resume"`
	}
	if err := json.Unmarshal(payload, &reservation); err != nil {
		return nil, ErrRepositoryUnavailable
	}
	if reservation.Organization == "" {
		return payload, nil
	}
	member, err := r.memberDirectory.DeliverMemberInvitation(ctx, reservation.Organization, m.Email, reservation.Resuming, func(ref string, loginLink bool) error {
		body.LoginLink = loginLink
		body.Phase = "check"
		if ref == "" {
			body.Phase = "send_new"
		}
		body.MemberReference = ref
		_, err := write(body)
		return err
	})
	if err != nil || !validExactStytchReference(member, "member-") {
		body.Phase = "release"
		_, _ = write(body) // A disconnected client can also retry after the lease expires.
		if err != nil {
			return nil, err
		}
		return nil, ErrRepositoryUnavailable
	}
	body.Phase = "complete"
	body.MemberReference = member
	return write(body)
}
