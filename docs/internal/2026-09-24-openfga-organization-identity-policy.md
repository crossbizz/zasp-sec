# Organization identity administration in P7

Implementation decision, not verified activation. Frozen P5/P6 evidence remains
unchanged. This closes a typed-target gap identified during P7 integration.

The original v1.5 plan assigns Stytch Organization membership/coarse roles and
requires SSO, SCIM, member administration and first-admin bootstrap. Product
Workspace/Environment grants remain separate. The accepted role-policy decision
preserves identity administration for both Organization Admin and Security Admin.

Concrete existing authority: SQL0019
`public.zasp_identity_admin_authorized(organization_value,principal_value)`
requires an active matching organization membership with role organization_admin
or security_admin. Its provider-organization and SSO/SCIM mutation functions use
that check. It does not require grants to every environment.

P5's organization object has only member; its environment alias cannot express
the final authority for these organization-wide effects. Checking every current
environment would add an unrelated restriction, create bootstrap/empty-set
ambiguities, and couple identity administration to later environment creation.

P7 will introduce explicit organization administrator source relations and a
narrow organization manage_identity permission, projected from the existing
active product/Stytch-linked membership facts. Member alone is insufficient.
This must not inherit view or mutation permissions into workspaces, environments
or product resources. Current credential/scope validity, fresh Stytch checks,
CSRF, SQL row guards and revocation fencing still apply.

Trace each organization membership/role/SSO/SCIM operation to this policy.
Tokens retain their actual Workspace/Environment scope; group mappings retain
their stored scope. Do not extend unrelated organization permissions without
specific existing policy and requirement evidence.

Required grouped verification: both administrator roles can perform intended
organization identity operations without sibling-environment resource access;
ordinary members and foreign organizations cannot; revocation denies current
decisions; model-generation changes require completed projection. Preserve the
immutable old model packet and use the existing pin/generation migration path.
No production model publication or permission activation is authorized by this
document alone. P7 remains incomplete until actual consumers pass verification.
