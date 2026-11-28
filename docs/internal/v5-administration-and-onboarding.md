# V5 administration and onboarding plan

## Member and organization workflows

1. Use the existing built-in roles and OpenFGA authorization checks. Require current organization authority for invitations, removals, role changes, and organization renames. Show the workspace and environment covered by each grant.
2. Let an admin invite a colleague by email, see pending invitations, and distinguish a pending invitation from an active membership. Bind acceptance to the invited identity and organization. Prevent duplicate grants during retries.
3. Give each member a searchable directory entry and access details. Support editing the member profile and role, confirming removal, revoking the departing member’s sessions, and protecting the last organization administrator.
4. Make the organization display name editable. Preserve the verified sign-in domain and underlying tenant ID.
5. Install the schema on both new and existing deployments. Exercise the operator upgrade path against a populated database.

## First login

Use Overview as the entry point for setup. Show what to do when an environment has no inventory, including opening the connector catalog, authorizing a source, running its first sync, and optionally enrolling a runtime sensor. If setup has already begun, direct the admin to the existing connection or enrollment. Give read-only members guidance that matches their permissions. Preserve the operational dashboard for environments with data, and show uncertainty explicitly when a request fails or access is limited.

When Sensors has no enrollments, help the operator choose between Tetragon for Kubernetes and OTLP for application traces. Carry that choice into enrollment, show how to install the collector, and explain how to verify incoming data. Guide read-only members and users who need to reauthenticate.

## Integrations and Kubernetes

Show only Nango-backed sources in the catalog and configured integrations. Use the supported provider configurations in the deployment's Nango environment. Cover a configured provider, an empty catalog, and an unavailable Nango service.

Give the Kubernetes profile a persistent Nango deployment with a private dashboard, a callback through the Zasp origin, and one environment shared by the API and discovery worker. Document how to reach the dashboard, enable providers, and upgrade an existing installation.

## Acceptance and delivery

- Exercise the production API and UI, including invitation acceptance, authorization, stale versions, duplicate requests, removal, organization editing, and member access details.
- Cover empty, partially configured, populated, restricted, and unavailable overview states. Verify that each setup action opens the correct product workflow.
- Run the repository's API contract, Go, type, UI, lint, and build checks and the required pull request CI. Merge `v5` to `main` after verifying the tested revision.
