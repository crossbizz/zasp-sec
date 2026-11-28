# Deployment administrator console

Open `/deployment-admin` at the installation's HTTPS product origin and enter its deployment password. This credential grants access to the Nango and OpenSearch operator records for that installation. Organization administrators continue to manage members and roles through the product's organization settings.

The console stores two access records. Each can contain an API URL, dashboard URL, operator account or email, and a reference to a credential managed elsewhere. Supported references include `kubernetes://namespace/secret#key`, `vault://mount/path#field`, and a Secrets Manager ARN. Enter credential identifiers in the reference field. Keep the actual provider password, API key or client certificate in the named secret store. Opening a private dashboard requires the network access, TLS trust and login used by that service. [Nango dashboard](independent-nango.md)

Saving changes updates the shared operator records. The API and workers read their runtime endpoints and credentials from the deployment configuration. On a new console database, the chart seeds records from its configured service URLs. Edits survive API restarts and later Helm upgrades.

## Production bootstrap

1. Give the installation an immutable identifier, such as a site-assigned UUID. Keep the same identifier and public origin across releases. Provision a separate PostgreSQL database and login owned only by this installation. A separate database on the product's PostgreSQL server is supported. Its address must be reachable from the API under the existing database egress policy. The console follows the installation's configured PostgreSQL TCP or WebSocket transport. At a privileged PostgreSQL prompt, choose a unique login and database for this site. For example:

   ```sql
   CREATE ROLE deployment_console LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
   \password deployment_console
   CREATE DATABASE deployment_console OWNER deployment_console;
   REVOKE ALL ON DATABASE deployment_console FROM PUBLIC;
   ```

2. Generate a separate operator password in a private directory with `umask 077` and `openssl rand -hex 32 > deployment-admin-password`. Save the site-specific DSN in a mode-0600 file named `database-url`. Use `postgresql://<role>:<url-encoded-password>@<database-host>:5432/<database>?sslmode=verify-full`. If the database uses a private CA, append `&sslrootcert=/var/run/secrets/zasp-deployment-admin/ca.crt`. File projections may end in one newline. Store the operator password in the operations team's password manager.

3. Create the console Secret in the **product release namespace** from those protected files. The initial site setup owns this Secret independently of application releases.

   ```sh
   kubectl --context "$KUBE_CONTEXT" -n "$PRODUCT_NAMESPACE" create secret generic deployment-admin \
     --from-file=password=deployment-admin-password \
     --from-file=database-url=database-url
   ```

   For a private CA, include `--from-file=ca.crt=/secure/console-db-ca.pem` and set `deploymentAdmin.databaseCAKey: ca.crt`.

4. Set the following fields in the site's private product values. The VPS production overlay enables the console. Substitute the installation's permanent ID. Site-specific credential references and dashboard addresses can be supplied under `deploymentAdmin.initialPointers` for first startup.

   ```yaml
   deploymentAdmin:
     enabled: true
     id: <site-installation-id>
     existingSecret: deployment-admin
   ```

   Roll out the API through the normal product release procedure. On first startup it initializes the empty database and binds it to the installation ID and public origin. It rejects a populated product database, a privileged database login, or a console bound to another installation. Only the API mounts the console Secret.

5. Sign in, check the deployment identifier shown at the top of the page and save the local login hints and credential references. Include the console database and Secret in the site's protected backup/restore procedure. Back up the database's role definition separately. Restore it only to the original deployment identity. For a clone, provision a new database and operator password.

## Kubernetes evaluation profile

New private values created by `./zasp --profile kubernetes secrets init` enable the console and generate `secrets.deploymentAdminPassword`. Read that value from the private values file. For an older release, set `deploymentAdmin.enabled: true` and generate `secrets.deploymentAdminPassword` with `openssl rand -hex 32`, or set `deploymentAdmin.existingSecret` to a dedicated Secret containing the `password` key. Run the normal profile upgrade. The chart uses the public host as the default installation ID, a separate local database on the StatefulSet's PostgreSQL volume, and the profile's existing PostgreSQL backup. A release with ephemeral storage loses these records if its volume is replaced.

## Session and maintenance behavior

An operator session lasts 30 minutes. The browser receives a host-only, Secure, HttpOnly cookie with strict same-site handling. Sign-out revokes the session across API replicas. Sign-in attempts share a per-installation limit of 60 per calendar minute and a limit of six per trusted client address per minute. Rotating the operator password and restarting every API replica invalidates sessions issued under the former password. Require each operator to sign back in and keep the previous password retired. Restrict both the Secret and console database backups to the installation operators.

The console uses same-origin JSON endpoints. `POST /api/v1/deployment-admin/session` accepts a password. `GET` returns the deployment identifier, expiry and CSRF token for the signed-in browser. Include the token in `X-CSRF-Token` on logout (`DELETE`) and when replacing settings (`PUT /api/v1/deployment-admin/settings`). All mutations require the exact installation Origin header. Read the current settings with `GET` and submit their version with both service records on `PUT`. A concurrent edit returns HTTP 409. Reload the current records before resubmitting changes.
