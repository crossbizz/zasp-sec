# Role policy for the OpenFGA cutover

Implementation decision, not permission-model verification or activation.

Use the current production role-to-permission policy as the cutover baseline.
The original PRD names six roles but does not define a complete permission
matrix. Its section6.2 requires Security Admin connector onboarding;11.10
SA-1 requires Security Engineer responder creation;14.2 requires scoped grants
and fresh Stytch revalidation for sensitive changes. The actual SQL policy
and API role metadata support those flows. The isolated identity package is
not wired into production and disagrees with both.

| Role | Baseline product permissions |
| --- | --- |
| organization_admin | investigate_sessions, manage_api_tokens, manage_data_controls, manage_findings, manage_identity, manage_workflows, revoke_sessions, run_tests, view, view_audit, view_compliance |
| security_admin | Same production permission set as organization_admin |
| security_engineer | investigate_sessions, manage_findings, manage_workflows, run_tests, view |
| developer_owner | investigate_sessions, run_tests, view |
| compliance_viewer | view, view_audit, view_compliance |
| read_only_viewer | view |

The reason is compatibility with verified product policy, not trust in a
display label. SQL0025 zasp_effective_scope_permissions and production.go
serverOwnedRoles agree. SQL0019 zasp_identity_admin_authorized explicitly
admits both active administrator roles. Preserve Security Admin identity
administration; removing it based on identity/roles.go would change access.
Do not add Developer/Owner integration mutation from that unused map.
Compliance export remains tied to the applicable audit/compliance permission
and its stronger export-specific checks; an export_evidence alias cannot open
other data or bypass retention/content restrictions.

Operation mapping stays explicit. The manage_workflows bucket currently
covers integration, policy, sensor and Security Agent mutations plus approval
decisions. P5 may assign separate FGA relations to these operations, but each
must retain this baseline's authorized roles and the operation's existing
SQL restrictions. Do not alias the whole bucket to only one domain or grant
all actions when any one relation is allowed. Seven authentication/bootstrap
operations without a route permission are not anonymous access by default;
their credential and bootstrap contracts remain binding.

An organization role is not an implicit grant to every environment.
SQL0019 zasp_identity_admin_effective_scopes requires active membership and
an exact organization/workspace/environment grant, directly or through a
verified group mapping. It combines permissions only within that same scope.
Project these grants, not a new organization-wide inheritance shortcut.
Resource ancestry must remain server-validated with exactly one parent.
Organization membership, resource hierarchy and grant scope are separate
facts. Test sibling-environment and cross-organization denials for admin
roles too.

PATs keep their current user-grant intersection and token restrictions.
Agents/service principals get distinct FGA types and explicit bounded
delegation; they never become synthetic Stytch members or inherit every
permission held by their creator. Task/target binding, current product policy,
approval and budget checks remain executor requirements. Compensation uses
its separate narrow authority.

P5 must verify the complete operation mapping and six-role examples against
the actual model. P6 must project direct and verified group grants; P7 must
keep revocation, revision locking, fresh auth, CSRF and SQL tenant checks.
This decision changes no live permissions and discharges no original task.
If later operation-level acceptance contradicts this baseline, record the
specific requirement and revise the mapping before activation.
