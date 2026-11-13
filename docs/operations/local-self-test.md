# Testing the product on your own machine

This guide gets the real product (API, workers, web application) running on one laptop, in a browser, against PostgreSQL, Temporal, OpenFGA, an emulated AWS account (LocalStack) and the Stytch test project. It is a test setup for one person. It is not a deployment.

## What has and has not been verified

Verified on 2026-11-13 in a Linux sandbox, with headless Chromium, against a stack that had already completed several syncs of the emulated AWS account:

- The web application loads over HTTPS at `https://zasp.local-stack.test:8443`. Signed out, it shows a "Sign in to Zasp" card. "Continue to sign in" on `/sign-in` redirects through Stytch to the Google sign-in page. `/auth/callback` with an invalid token shows "Sign-in failed" with a correlation ID; an invitation-shaped link shows "Accept your invitation" first.
- Every page in the left navigation was opened with a signed-in session. What each one showed is listed under [What you should see](#what-you-should-see); what failed is under [Known issues](#known-issues).
- Through the browser: a search, opening a finding, opening the AWS integration, **Sync inventory now** (the sync succeeded in 97 seconds), creating, revealing, acknowledging and revoking an API token, and **Sign out**.
- After that sync the three projections were current within three seconds: Neo4j held 13 nodes and 21 relationships, the search index 15 documents, and the product listed the four IAM roles under Identities and the two failing posture checks under Findings.
- `stack.sh start`, `status` and `stop` start, report and stop the web application, its TLS front and the permission projector. The API and the workers were already running in those runs and `start` left them alone.
- The script parses and its `status` and `stop` commands run under bash 3.2, the macOS system bash.

The signed-in session of that run was a test fixture, not a sign-in. Sign-in needs a person's inbox or Google account, so the session was issued in the local database through the product's own session functions, for the existing administrator. It shows what the pages do once a session exists. It does not show that sign-in works.

Not verified:

- Anything on macOS. The first `start` on a clean machine (it runs `up`) was not run as one command; `up` on its own has been run many times on Linux.
- A completed sign-in in a browser through this front, by Google or by the emailed link. A sign-in was completed once through the API by following the invitation email.
- **Reauthenticate**, which sends the browser through sign-in again.
- Creating and authorizing an integration in the browser (**Save integration**, **Review access**). The form was opened; the integration used here had been created and authorized through the API.
- The pages on a fresh database. The stack used here held test data from earlier work (several integrations, Security Agent definitions and runs).
- Trusting the generated certificate authority in a browser. The sandbox run ignored certificate errors.

Please note the page, what you clicked and the correlation ID shown when something fails.

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Docker Desktop | current | Nine containers run (PostgreSQL, LocalStack, OpenSearch, Neo4j, Temporal, OpenFGA and their three databases). Neo4j is given a 512 MB heap. 6 GB of memory for Docker is an estimate, not a measurement. |
| Go | 1.26 (`services/platform/go.mod`) | An older Go downloads the 1.26 toolchain by itself on first build. |
| Node.js and npm | Node 22.23.1, npm 10.9.8 (`package.json`) | Any Node 22 release worked in the sandbox (22.23.4). |
| `curl`, `openssl` | any | Both ship with macOS. |
| Python 3.13 | optional | Only for `stack.sh security-workers`, which an AWS sync needs. About 4 GB of disk. |

`psql` is not needed: without it the script uses the one inside the database container.

Three one-time steps need `sudo`. The script never edits system files itself.

```bash
# 1. The browser must reach the stack under its public name.
echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts

# 2. The API and workers read an identity token from this fixed path.
#    On macOS /var/run is emptied at every reboot: repeat this step after one.
sudo mkdir -p /var/run/secrets/eks.amazonaws.com/serviceaccount
sudo chown "$USER" /var/run/secrets/eks.amazonaws.com/serviceaccount

# 3. Only for an AWS sync: the analyzers are installed here.
sudo mkdir -p /opt/zasp/security && sudo chown "$USER" /opt/zasp/security
```

## Settings

The three values of the Stytch **test** project:

```bash
export STYTCH_PROJECT_ID=project-test-...
export STYTCH_SECRET=secret-test-...
export STYTCH_PUBLIC_TOKEN=public-token-test-...
```

To avoid exporting them in every terminal, put the same three lines (without `export`) in `~/.local/state/zasp-real-stack/provider.env` and run `chmod 600` on it. Every `stack.sh` command reads that file.

`OPENROUTER_API_KEY` is needed only for the Security Agent planning worker, which `start` does not launch (see [Security Agents](#security-agents)).

## Start

From the repository root:

```bash
npm ci                                   # once, and after pulling new code
deploy/local/real-stack/stack.sh start   # first run: several minutes (images, Go build, schema)
deploy/local/real-stack/stack.sh bootstrap "Acme Security" acme.example you@your-company.example
deploy/local/real-stack/stack.sh start   # now starts the API, workers, projector and web application
```

The first `start` prepares the dependencies and the database and then stops, because no Organization exists yet. `bootstrap` creates the Organization in Stytch and in the product and makes the address its administrator. Use your own address at the domain of the Stytch account: Stytch refuses invitations to any other domain until billing is verified on the Stytch account. The second `start` ends with a status table and the address to open.

`start` launches the API, the scheduler, discovery and outbox workers, the three projection workers (graph, search, risk), the Security Agent action worker, the permission projector and the web application. Check with `status` that all of them run before testing. Two matter more than they look:

- **The permission projector** (`projector` in `status`, or `stack.sh project` in a terminal) must keep running. A new session, integration or other resource answers `authorization_pending` or `authorization_unavailable` until its next pass, every 5 seconds.
- **The projection workers** turn a finished sync into the graph, the search index, findings and attack paths. To run one by hand: `stack.sh worker projection-graph`, `projection-search` or `projection-risk`.

Other commands:

```bash
deploy/local/real-stack/stack.sh status            # one line per dependency and process
deploy/local/real-stack/stack.sh stop              # stops the processes; containers keep running
deploy/local/real-stack/stack.sh down              # stops the processes and the containers; data is kept
deploy/local/real-stack/stack.sh security-workers  # once, before the first AWS sync
```

`start` is safe to repeat. Logs are in `~/.local/state/zasp-real-stack/logs/`, one file per process. After pulling new code run `stop`, `up`, `start`: `up` rebuilds the Go binaries, and `start` rebuilds the web application when its sources changed.

## Open it in the browser

Open <https://zasp.local-stack.test:8443/>. The address must be exactly this one: the session cookie and the sign-in redirect are bound to it. `https://localhost:8443` answers with a note pointing here.

The certificate is generated on your machine, so the browser warns once. Either click through the warning (Chrome: Advanced, then Proceed), or trust the certificate authority:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  ~/.local/state/zasp-real-stack/tls/ca.crt
```

That authority can vouch only for `zasp.local-stack.test`, and its private key is deleted as soon as the server certificate is signed, so trusting it does not let anything impersonate another site. Firefox keeps its own list and needs the click-through. To undo, delete "Zasp local stack development CA" in Keychain Access.

## Sign in

Two ways. Neither has been completed through this front (see the top).

- **Google.** Click "Continue to sign in" and choose the Google account whose address you gave to `bootstrap`.
- **The emailed link.** `bootstrap` makes Stytch send an invitation. Open its link on the same machine. The page shows "Accept your invitation"; click the button. The link works once.

A failed sign-in shows "Sign-in failed" and a correlation ID. Search for that ID in `logs/api.log`.

A session lasts 60 minutes. Sensitive actions need a sign-in from the last five minutes or so: after that, Identity & Access, API Access, Data & Retention, the Console logins tab and the Security Agent execution controls show "Fresh authentication expired" with a **Reauthenticate** button, and **Sync inventory now** is not offered.

## Golden path

1. **Integrations** (left navigation, address `/connectors`). Choose **Configure Amazon Web Services** in the connector catalog and fill in:

   | Field | Value |
   | --- | --- |
   | Integration name | anything |
   | Read role ARN | `arn:aws:iam::000000000000:role/zasp-reference/customer-read` |
   | External ID | `ref:aws/external-id/localstack-dev-0001` |
   | Home region | `us-east-1` |

   Then **Save integration**. The form and its labels were seen in the browser; saving was done through the API, where an integration with exactly these values is accepted and waits in `pending_authorization`.
2. **Review access** authorizes the connection: the product assumes the role in LocalStack and checks the account. The API accepts this step only from a recent sign-in. Done through the API, not seen in the browser.
3. Open the integration from **Configured integrations** and click **Sync inventory now**. A sync needs the security analyzers (`stack.sh security-workers`). Seen in the browser: the request is accepted, the sync of the emulated account succeeds in about 100 seconds, and **Sync history** lists it. Right after the click the dialog reports "The integration operation was not confirmed" (see [Known issues](#known-issues)); the sync runs all the same.
4. **Looking at the result.** After a sync, **Identities** lists the four IAM roles and **Findings** lists the two failing posture checks. The integration's **Automatic discovery** section shows "Risk projection: current", "Graph projection: current" and "Search projection: current". Agents, Tools & MCP and Runtimes stay empty: they list only what the Kubernetes, Okta and GitHub connectors report. Everything else the sync reads (the account, policies, the EC2 instance) is an *asset*; no page lists assets, but the search box finds them.

A sync that is cut off, for example by stopping the discovery worker in the middle of a page, keeps the integration reserved. The next sync requested after ten quiet minutes releases it. This is in the schema (`release_abandoned` in `completion.sql`); it was not exercised in the browser run.

The emulated account is described in `deploy/local/real-stack/README.md`.

## Security Agents

`start` launches the action worker only. The planning worker is started by hand and needs an OpenRouter API token:

```bash
OPENROUTER_API_KEY=... deploy/local/real-stack/stack.sh worker security-agent
```

Until the OpenRouter account has credits, a run stops at planning. In the browser the runs of this stack showed the state `needs_human`, "AI usage or pricing could not be verified", "No plan has been persisted" and "No AI rationale is available for this run". No run was seen to plan or act. The paragraph on the two Security Agent workers in `deploy/local/real-stack/README.md` describes the pricing approval a planner request needs first.

## What you should see

Observed on 2026-11-13 with one synced AWS integration. Pages took 6 to 13 seconds to load while the stack was busy.

| Page | What it showed |
| --- | --- |
| Signed out, `/` | A card "Sign in to Zasp" with a **Sign in** button. A deep link such as `/connectors` shows the same card at its own address. |
| Overview | Four counters (Agents 0, High-risk paths 0, Verified changes 0, Blocked changes 0), a red line "Coverage is degraded" and a "Needs attention" card with six counters. |
| Agents, Tools & MCP, Runtimes | "No records in this scope." Expected: an AWS sync adds nothing here. |
| Identities | Four rows: `customer-read`, `agent-orchestrator`, `support-copilot-runtime`, `claims-triage-agent`, each "Unowned" and "fresh". Clicking a row fails with "Inventory detail unavailable". |
| Findings | "Discovered AWS control iam_role_administratoraccess_policy" and "Discovered AWS control ec2_instance_imdsv2_enabled", both high and open. Clicking one opens Why, Evidence, Path, Fix and Verify, with ticket and status actions. "Related Security Agent runs" shows "Related activity access denied." |
| Attack Paths | "No attack paths in this scope." |
| Red Team | "No Red Team tests in this scope." and "No Red Team runs in this scope.", with **Create test**. Its workers do not run here. |
| Attack Lab | A safety approval form that asks for a completed failing Red Team run. Its workers do not run here. |
| Policies | A create form and "No policies". **Create policy** failed (see Known issues). |
| Integrations | "Configured integrations" and a "Connector catalog" with Amazon Web Services, Generic Webhook and Kubernetes. An integration opens in a dialog: its fields, Setup progress, Connection test, Collected data, AWS account scope `000000000000`, Automatic discovery with the three projection states and "Last good inventory: 0 discovered · 13 changed · 0 removed", **Sync inventory now**, the sync schedule ("No automatic sync schedule.") and Sync history. |
| Sensors | Four counters at 0 and "No runtime sensors". |
| Security agents | Execution controls (one line per action, enabled or disabled), the definitions, the runs and "Pending approvals". A definition and a run each open in a dialog. In a run, the four "Related" lists show "Related activity access denied." |
| Approvals | "No pending approvals". |
| Identity & Access | Members (the administrator, with a role selector), the six built-in roles with their permissions, Enterprise identity ("No SSO connections", "No SCIM connections", with forms to add them), Group mappings ("No group mappings"), Organization, Workspace onboarding and Environment onboarding. Only reading was exercised. |
| API Access | "Pending reveal grants", "Create API token" and the token list. Creating a token, revealing it, "I saved it — destroy recovery copy" and **Revoke** all worked. |
| Sessions | "Agent runtime": structured filters for runtime activity. "Console logins": the console sessions of the Organization, the active ones with **Revoke session**. |
| Audit Log | Filters and the newest audit events, for example `api_token.create`. It took about 8 seconds. |
| Compliance | "Compliance request failed. Evidence inspection remains available; retry the request." (see Known issues). |
| Data & Retention | "Retention days", "Deletion enabled", **Save data controls** and the note "Data deletion unavailable". |
| Recovery | **Start signed backup**, "Backup settings" and "No recovery operation in this scope". |
| External Data Flows | One row: "identity-provider · Required · identity_metadata · degraded". |
| System Health | "Security plane degraded", `postgresql` healthy and `identity-provider` degraded. |
| Search box (top) | "agent" returned `agent-orchestrator-delegate` (asset) and `agent-orchestrator` (identity). Choosing a result opens the list page of its type, not the record. "orchestrator" returned nothing, although `agent-orchestrator` exists. |
| **Sign out** | Returns to the "Sign in to Zasp" card; the session is refused afterwards. |

The last two entries of the navigation, External Data Flows and System Health, are below the fold on a short window: scroll the navigation.

## Known issues

Seen on 2026-11-13. Each is an API answer, with the route and the error code the browser received. None of them is fixed in the web application.

- **Changes made in the browser are "not confirmed", and then lock further changes.** After **Sync inventory now** the request succeeded (`202`), but the follow-up `GET /api/v1/workflow-mutation-receipts` answered `503 authorization_unavailable` and, from then on, `503 provider_unavailable`. Every page then shows "Provider unavailable" with **Retry committed-operation recovery** at the top, and buttons that change something stay disabled. The database log names the cause: `authorization resource identity unavailable` while the receipt of the sync is being authorized. A receipt that does load shows "Recover committed operations" with **Acknowledge recovered result**; that button failed too (`POST /api/v1/workflow-mutation-receipts/{id}/acknowledge`, `503 provider_unavailable`). In the test run the receipts were marked acknowledged directly in the local database to continue.
- **Create policy fails.** `POST /api/v1/policies` answered `503 authorization_unavailable` twice; no policy was created.
- **Identity detail fails.** `GET /api/v1/identities/{id}` answers `503 provider_unavailable`; the page shows "Inventory detail unavailable".
- **Related activity is denied to the administrator.** `GET /api/v1/security-agent-activity/finding/{id}/runs` and `GET /api/v1/security-agent-runs/{id}/activity/{finding|attack_path|session|audit}` answer `403 forbidden`.
- **Compliance controls never arrive.** `GET /api/v1/compliance/controls?limit=100` is cut off after about 15 seconds without an answer.
- **An integration cannot be deleted while it waits for authorization.** `DELETE /api/v1/integrations/{id}` on a `pending_authorization` AWS integration answered `503 provider_unavailable`.
- **API tokens carry a permission the published API description does not list.** An administrator's token has eleven permissions including `run_tests`; `openapi/openapi.yaml` lists ten. The web application now accepts it.
- **Slow pages.** Most pages took 6 to 13 seconds. `GET /api/v1/audit-events?limit=50` alone took about 8.
- **Search.** "orchestrator" did not find `agent-orchestrator`; "agent" did. A result for an asset opens the Agents page, which does not list assets.

Expected on this stack, not faults:

- `GET /api/v1/integrations/{id}/schedule` answers `404` until a schedule is saved; the dialog shows "No automatic sync schedule."
- `GET /api/v1/security-agent-runs/{id}/cleanup-recovery` answers `404` for a run with nothing to clean up.
- "Coverage is degraded" and "Security plane degraded": no runtime sensor is enrolled, and the identity provider reports `degraded`.

## Known limits

- **Permissions arrive a few seconds late.** A new session, integration or other resource can answer `authorization_pending` or `authorization_unavailable` until the projector's next pass (every 5 seconds here; `status` shows the `projector` line). In production a job does this once a minute.
- **Sign-in and callback pages** are a single card; they were restyled on 2026-11-13 and seen only signed out and with invalid tokens.
- **AWS is emulated.** LocalStack accepts any external ID and never denies an action. A successful connection says nothing about a real role's trust policy or permissions.
- **Not running on this stack:** the Security Agent planning worker unless started by hand, red team and Attack Lab workers, and the runtime pipeline. Pages for those features open against an API that has no worker behind it.
- **The API reads neither the graph nor the search index.** Search, findings, attack paths and relationships in the product come from PostgreSQL. Neo4j and the search index are written by the projection workers and can be inspected directly (see "The projection workers" in `deploy/local/real-stack/README.md`).
- **Other connectors.** The catalog offers Kubernetes and Generic Webhook besides AWS. Kubernetes has placeholder credentials and cannot connect; neither was tried in the browser.
- **Stytch** refuses invitations outside the Stytch account's own email domain until billing is verified. SSO, SCIM, member onboarding and choosing between several Organizations are not exercised.
- **One Organization per stack.** Sign-in is bound to the first Organization that `bootstrap` creates.
- **The database trusts every local connection.** It listens on loopback only and holds test data. Never point this stack at a production database.

## When something does not start

`stack.sh status` names what is not running. Then read the matching file in `~/.local/state/zasp-real-stack/logs/`.

| Symptom | Cause |
| --- | --- |
| `startup refused: stage=...` in a log | The process names the stage that refused. `stage=dependencies:...` usually means a container is not running: run `stack.sh up`. |
| The browser cannot find the site | The `/etc/hosts` line is missing. `status` shows `hosts entry missing`. |
| `ui` stops at once | Port 8443 or 3100 is in use. |
| `worker-projection-graph` refuses with `stage=dependencies:projection-graph-connect` | Neo4j is not running, or port 7687 is taken by another Neo4j: run `stack.sh up`. `projection-graph-credential` means the LocalStack secret is gone (LocalStack keeps nothing across a restart); starting the worker again recreates it. |
| Sign-in returns to "Sign-in failed" | Read the correlation ID's line in `logs/api.log`. |
| `create /var/run/secrets/... (needs root)` | Prerequisite step 2 was not done, or the Mac was restarted since. |
