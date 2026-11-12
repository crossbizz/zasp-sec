# First Organization bootstrap

A new deployment has no Organization and no member, and sign-in only admits a member who already has a product membership. `zasp-bootstrap` is the operator command that creates the first Organization and invites its first Organization Admin. Nothing else creates a membership: there is no self-signup and no API route for it.

The command ships in the API image at `/app/zasp-bootstrap`, next to `agentsec-migrate`.

## What it does

Given a customer name, email domain and the first administrator's email address, it:

1. Resolves the Stytch Organization for the domain, or creates it. The Organization slug is the domain itself. A new Organization allows invitations only (nobody joins by holding an address in the domain) and is stamped in its trusted metadata as created by this command. An existing Organization is used only if it carries that stamp, the requested name and the requested domain; anything else is refused, never adopted.
2. Resolves the Stytch member for the administrator's address, or sends a Stytch invitation. No password is created. The invitation link returns the administrator to `<public origin>/auth/callback`.
3. In one database transaction, writes the product Organization, a `Default` Workspace, `Production`, `Staging` and `Development` Environments with metadata-only data controls, the administrator's `organization_admin` membership, and that administrator's scopes in all three Environments. `Production` is the default scope.
4. Binds the Organization's permission projection to the deployment's authorization store and model, when both are configured. The projector then applies the permissions; until it has, the administrator sees "Authorization pending".

It prints one JSON object with the product and provider identifiers. It prints no credential.

## Running it

Run it as the migration operator, after the schema and verifier registrations are installed:

```bash
/app/zasp-bootstrap -organization-name "Acme Security" -domain acme.com -admin-email admin@acme.com
```

| Setting | Meaning |
| --- | --- |
| `ZASP_POSTGRES_DSN` | Operator DSN: the `zasp_operator` role that [installed the schema](baseline-schema-install.md). It needs `BYPASSRLS`, because `zasp_data_controls` forces row security. |
| `ZASP_PUBLIC_ORIGIN` | The deployment's HTTPS origin. The invitation returns to its `/auth/callback`. |
| `ZASP_DEPLOYMENT_MODE` | `saas` or `single_tenant`. |
| `ZASP_ORGANIZATION_ID` | Required in `single_tenant` mode and empty in `saas` mode, exactly as for the API. |
| `ZASP_STYTCH_BASE_URL`, `ZASP_STYTCH_PROJECT_ID`, `ZASP_STYTCH_SECRET` | The deployment's Stytch project. |
| `ZASP_OPENFGA_STORE_ID`, `ZASP_OPENFGA_MODEL_ID` | Optional, but set both or neither. When set, the command binds the permission projection. |

In `single_tenant` mode the command provisions only the configured Organization. `-organization-id` may repeat that ID; any other value is refused. Once that Organization is bound to a Stytch Organization, through an earlier run or through `ZASP_STYTCH_ORGANIZATION_ID`, the command resolves only that Stytch Organization and never creates another, so a mistyped domain is refused before anything is written or sent.

In `saas` mode a new Organization receives a generated ID and `-organization-id` is refused.

## Running it again

Every step is idempotent. A second run with the same arguments changes nothing, sends no second invitation, and prints the same identifiers with `organization_created` and `admin_created` set to `false`. A run interrupted after any step is safe to repeat.

Running it with a different administrator address for the same domain adds a second Organization Admin to the same Organization. Default Workspaces and Environments are created only with the Organization. A later run grants the administrator scopes in the Environments that exist and never recreates a default the customer renamed.

The command does not re-send an invitation to a member who already exists. If an invitation expires unused, re-send it from the Stytch dashboard.

## Refusals

A refusal prints one line, `bootstrap refused: stage=<stage>`, and exits with status 1.

| Stage | Cause |
| --- | --- |
| `arguments` | A flag is missing or malformed. Names, domains and addresses must be lower case where the identity model requires it. |
| `configuration` | A setting above is missing or inconsistent with the deployment mode. |
| `database` | The operator database is unreachable. |
| `identity-provider` | Stytch refused, or returned an Organization or member that does not match the request. See the provider prerequisites below. |
| `existing-records` | Product records already exist and disagree with the request. Nothing was written. Examples: the membership was deactivated or its role changed, the provider Organization is already linked to a different product Organization, or the pinned ID belongs to another Organization. |
| `product-records` | The product records could not be written. |
| `authorization-binding` | The permission projection is not installed, refused the store and model, or the Organization is already bound to a different store or model. |

The command never reactivates, moves or promotes an existing membership. Those are identity administration decisions.

## Provider prerequisites

These are settings in the Stytch dashboard for the project. The project API credentials cannot change them.

- **Redirect URLs.** Register `<public origin>/auth/callback?state={}` for Login and Signup, and `<public origin>/auth/callback` for Invite. Without the `state={}` wildcard Stytch rejects sign-in start with `query_params_do_not_match`.
- **Email sending.** Until billing is verified, a Stytch account can send email only to addresses on the account owner's own domain. An invitation to any other address fails with `billing_not_verified_for_email` and the command reports `identity-provider`.
- **An OAuth provider** (Google, Microsoft, GitHub, Slack or HubSpot) enabled for returning members. `ZASP_STYTCH_AUTHORIZE_URL` selects one.

## Signing in afterwards

The invited administrator follows the Stytch invitation. Stytch returns them to `/auth/callback` with an invitation token and no product state. The page asks them to accept, so that a mail scanner opening the link does not spend the single-use token, and then exchanges it for a product session. This is the only exchange the API accepts without the state it issues at sign-in start.

Stytch redeems invitation links and ordinary email sign-in links through the same exchange, so the API cannot tell them apart. The product never sends email sign-in links. Keep the Stytch frontend SDK disabled for the project, or restrict each Organization's allowed authentication methods, if members must not be able to sign in by email link.

Returning members use sign-in start, which redirects to the configured OAuth provider.

## Known limits

- Product-started sign-in is bound to the one Stytch Organization in `ZASP_STYTCH_ORGANIZATION_ID`. In `saas` mode, members of any other Organization can enter through their invitation but have no sign-in start of their own yet.
- Members other than the bootstrapped administrators have no product membership path. Sign-in does not create a membership for a Stytch member who lacks one.
- The stateless invitation exchange is not limited to members with a pending product invitation. Recording and consuming one needs a schema change.
- Corporate SSO sign-in is not accepted by the callback. SSO connections can be configured, but only OAuth and invitation tokens are exchanged.

These are open launch requirements, tracked in `docs/internal/implementation_status_v1.5.md`.
