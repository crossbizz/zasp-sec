# Testing the product on your own machine

This guide gets the real product (API, workers, web application) running on one laptop, in a browser, against PostgreSQL, Temporal, OpenFGA, an emulated AWS account (LocalStack) and the Stytch test project. It is a test setup for one person. It is not a deployment.

Follow it from top to bottom: prerequisites, start, sign in, the golden path, then the known issues and how to reset. When something fails, note the page, what you clicked and the correlation ID shown.

## What has and has not been verified

Verified on 2026-11-14 in a Linux sandbox with headless Chromium, on a stack that already held test data from earlier work:

- Every step of the [golden path](#golden-path) below was clicked through in the browser, including the changes: connecting and authorizing an AWS integration, a sync, a policy from creation to deletion, accepting a risk and reopening the finding, creating and revoking an API token, renaming a workspace and restoring the name, and a Security Agent from creation to a closed run.
- After each of those changes the page became usable again without a reload. The one exception is deleting an authorized integration (see [Known issues](#known-issues)).
- Every page in the left navigation opened with a signed-in session and without an error message.

The signed-in session of that run was a test fixture, not a sign-in. Sign-in needs a person's inbox or Google account, so the session was issued in the local database through the product's own session functions, for the existing administrator. It shows what the pages do once a session exists. It does not show that sign-in works.

Not verified:

- Anything on macOS. The script parses and its `status` and `stop` commands run under bash 3.2, the macOS system bash; nothing else was run there.
- The first `start` on a clean machine as one command. `up`, which it runs, has been run many times on Linux.
- A completed sign-in in a browser through this front, by Google or by the emailed link. A sign-in was completed once through the API by following the invitation email. A headless browser reached the Google sign-in page.
- **Reauthenticate**, which sends the browser through sign-in again.
- The pages on a fresh database. The stack used here held several integrations, Security Agent definitions and runs.
- Anything a Security Agent does after planning. The OpenRouter account used has no credits, so every run stopped at the planning request.
- Starting a Security Agent run on a fresh stack. The runs of this pass used findings that had been inserted into the local database by hand (see [Known issues](#known-issues)).
- Trusting the generated certificate authority in a browser. The sandbox run ignored certificate errors.
- The reset commands at the end of this guide.

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Docker Desktop | current | Nine containers run (PostgreSQL, LocalStack, OpenSearch, Neo4j, Temporal, OpenFGA and their three databases). Neo4j is given a 512 MB heap. 6 GB of memory for Docker is an estimate, not a measurement. |
| Go | 1.26 (`services/platform/go.mod`) | An older Go downloads the 1.26 toolchain by itself on first build. |
| Node.js and npm | Node 22.23.1, npm 10.9.8 (`package.json`) | Any Node 22 release worked in the sandbox (22.23.4). |
| `curl`, `openssl` | any | Both ship with macOS. |
| Python 3.13 | needed for an AWS sync | For `stack.sh security-workers`. About 4 GB of disk. |
| An OpenRouter API token | optional | Only for the Security Agent steps. Without credits on the account a run stops at planning, which is what this guide describes. |

`psql` is not needed: without it the script uses the one inside the database container.

Three one-time steps need `sudo`. The script never edits system files itself.

```bash
# 1. The browser must reach the stack under its public name.
echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts

# 2. The API and workers read an identity token from this fixed path.
#    On macOS /var/run is emptied at every reboot: repeat this step after one.
sudo mkdir -p /var/run/secrets/eks.amazonaws.com/serviceaccount
sudo chown "$USER" /var/run/secrets/eks.amazonaws.com/serviceaccount

# 3. For an AWS sync: the analyzers are installed here.
sudo mkdir -p /opt/zasp/security && sudo chown "$USER" /opt/zasp/security
```

The three values of the Stytch **test** project:

```bash
export STYTCH_PROJECT_ID=project-test-...
export STYTCH_SECRET=secret-test-...
export STYTCH_PUBLIC_TOKEN=public-token-test-...
```

To avoid exporting them in every terminal, put the same three lines (without `export`) in `~/.local/state/zasp-real-stack/provider.env` and run `chmod 600` on it. Every `stack.sh` command reads that file.

## Start

From the repository root:

```bash
npm ci                                             # once, and after pulling new code
deploy/local/real-stack/stack.sh security-workers  # once: the analyzers an AWS sync runs
deploy/local/real-stack/stack.sh start             # first run: several minutes (images, Go build, schema)
deploy/local/real-stack/stack.sh bootstrap "Acme Security" acme.example you@gmail.com
deploy/local/real-stack/stack.sh start             # the one command from now on
```

The first `start` prepares the dependencies and the database and then stops, because no Organization exists yet. `bootstrap` creates the Organization in Stytch and in the product, makes the address its administrator and has Stytch send it an invitation. The second `start` ends with a status table and the address to open. From then on `start` is the only command you need; it is safe to repeat.

Which address to give `bootstrap`: the Stytch test project sends its magic link to the address you name, so use one whose inbox you can open on this machine, for example your Gmail address. Stytch refuses invitations to addresses outside the Stytch account's own email domain until billing is verified on that account; if `bootstrap` reports that, use an address at that domain.

`start` launches the API, seven workers (scheduler, discovery, outbox, the graph, search and risk projection workers, and the Security Agent action worker), the permission projector and the web application. Run `status` and check that every line is up before testing. Two of them matter more than they look:

- **The permission projector** (`projector` in `status`, or `stack.sh project` in its own terminal) applies permissions for everything new: a session, an integration, a policy, a run. It runs a pass every 5 seconds. Without it nothing new can be read.
- **The projection workers** turn a finished sync into the graph, the search index, findings and attack paths.

The Security Agent planning worker is the eighth worker and is started by hand, in its own terminal, because it needs the OpenRouter token:

```bash
OPENROUTER_API_KEY=... deploy/local/real-stack/stack.sh worker security-agent
```

It is not listed by `status`; its terminal shows whether it runs.

Other commands:

```bash
deploy/local/real-stack/stack.sh status   # one line per dependency and process
deploy/local/real-stack/stack.sh stop     # stops the processes; containers keep running
deploy/local/real-stack/stack.sh down     # stops the processes and the containers; data is kept
```

Logs are in `~/.local/state/zasp-real-stack/logs/`, one file per process. After pulling new code run `stop`, `up`, `start`: `up` rebuilds the Go binaries, and `start` rebuilds the web application when its sources changed.

## Open it in the browser

Open <https://zasp.local-stack.test:8443/>. The address must be exactly this one: the session cookie and the sign-in redirect are bound to it. `https://localhost:8443` answers with a note pointing here.

The certificate is generated on your machine, so the browser warns once. Either click through the warning (Chrome: Advanced, then Proceed), or trust the certificate authority:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  ~/.local/state/zasp-real-stack/tls/ca.crt
```

That authority can vouch only for `zasp.local-stack.test`, and its private key is deleted as soon as the server certificate is signed, so trusting it does not let anything impersonate another site. Firefox keeps its own list and needs the click-through. To undo, delete "Zasp local stack development CA" in Keychain Access.

## Sign in

- **The emailed link (Stytch test magic link).** `bootstrap` makes Stytch send an invitation to the address you gave it. Open the link in the browser on the same machine. The page shows "Accept your invitation"; click the button. The link works once.
- **Google.** Click "Continue to sign in" and choose the Google account with that address.

Neither has been completed through this front (see the top). A failed sign-in shows "Sign-in failed" and a correlation ID. Search for that ID in `logs/api.log`.

Right after sign-in you may see a card "Authorization pending" for a few seconds. The page retries on its own; **Retry** does the same at once.

Two clocks to keep in mind:

- **A session lasts 60 minutes.** After that the page shows "Sign in to Zasp" again.
- **Sensitive actions need a sign-in from the last five minutes or so.** After that, Identity & Access, API Access, Data & Retention, Recovery, the Security Agent execution controls and a Security Agent's activation show "Fresh authentication expired" or a **Reauthenticate** button. Do the steps marked *(fresh sign-in)* below soon after signing in, or use **Reauthenticate**.

## What happens after every change

Every change (a button that saves, creates, deletes or starts something) is followed by a few seconds in which the product applies permissions for what changed. During that time:

- the buttons on the page are disabled,
- a small note at the bottom of the page reads "Applying recent changes… This takes a few seconds.",
- then the page continues by itself. In the test run this took 5 to 15 seconds.

If it takes longer, the top of the page shows "Applying recent changes… Permissions are still being updated; this page checks again on its own." with **Check now**. You do not need to reload.

If the browser lost the answer to a change that the server had stored, the top of the page shows **Recover committed operations** with what was requested and what was stored. Read it and click **Acknowledge recovered result**; the page continues.

## Golden path

Each step says what you should see. The numbers in brackets are what the test run measured.

### 1. Connect the emulated AWS account *(fresh sign-in)*

1. Open **Integrations** in the left navigation (address `/connectors`). You see "Configured integrations" and a "Connector catalog" with Amazon Web Services, Generic Webhook and Kubernetes.
2. Click **Configure Amazon Web Services** and fill in:

   | Field | Value |
   | --- | --- |
   | Integration name | anything |
   | Read role ARN | `arn:aws:iam::000000000000:role/zasp-reference/customer-read` |
   | External ID | `ref:aws/external-id/localstack-dev-0001` |
   | Home region | `us-east-1` |

3. Click **Save integration**. You see "Integration created." and the state `pending_authorization`, with the note "Provider authorization is pending. No provider scope is trusted until verification succeeds."
4. Click **Authorize AWS reference**. The product assumes the role in LocalStack and checks the account. You see the state `active`, "Reference authorization is active." and "AWS account scope 000000000000". This button needs the fresh sign-in.

### 2. Sync

1. In the same dialog click **Sync inventory now**. You see "Inventory sync queued."
2. Wait. The sync of the emulated account took 77 to 97 seconds in the test runs. The dialog does not count down; click **Refresh discovery status** or reopen the integration.
3. You should then see, under **Automatic discovery**, "Risk projection: current", "Graph projection: current" and "Search projection: current", a line "Last good inventory: …", and the sync as `succeeded` at the top of **Sync history**.

A sync fails at its second page when the analyzers are not installed (`stack.sh security-workers`).

### 3. Identities and findings

1. **Identities** lists four IAM roles: `customer-read`, `agent-orchestrator`, `support-copilot-runtime` and `claims-triage-agent`, each "Unowned" and "fresh". Click one: a dialog shows its canonical record, ownership, evidence and source observations.
2. **Findings** lists "Discovered AWS control iam_role_administratoraccess_policy" and "Discovered AWS control ec2_instance_imdsv2_enabled", both high. Click one: you see Why, Evidence, Path, Fix and Verify, "Related Security Agent runs", and the actions.
3. In a finding, type a reason under **Accept risk** and click **Accept risk**. The status becomes `accepted` and the reason is shown. Click **Reopen finding**: the status is `open` again. **Mark under review** sets `under_review`.

Agents, Tools & MCP and Runtimes stay empty ("No records in this scope."): they list only what the Kubernetes, Okta and GitHub connectors report. Everything else the sync reads (the account, policies, the EC2 instance) is an *asset*; no page lists assets, but the search box finds them.

### 4. Graph and search

1. Type `agent` in the search box at the top and click **Search**. You should see `agent-orchestrator-delegate` (asset) and `agent-orchestrator` (identity). Choosing a result opens the list page of its type, not the record.
2. **Attack Paths** shows "No attack paths in this scope." for this account.
3. The graph has no page of its own. The integration dialog reports its state ("Graph projection: current"). To look inside Neo4j or the search index, use the commands under "The projection workers" in `deploy/local/real-stack/README.md`.

### 5. A policy: monitor, enforce, disable, delete

1. Open **Policies**. Enter a **Policy ID** that starts with `policy-` followed by lowercase letters, digits or hyphens (for example `policy-test-1`) and a name, then **Create policy**. Any other ID is refused under the field and the button stays disabled.
2. You see "Policy created. Audit …" and a card "Policy detail" with the state `draft`.
3. **Roll to monitor**: "Policy is monitor."
4. **Enforce policy**: "Policy is enforced."
5. **Simulate against runtime history**: a line "0 matched historical actions · 0 would block" (nothing produces runtime history on this stack).
6. **Disable policy**: "Policy is disabled."
7. **Delete policy**, then **Confirm delete of policy-…**: "Policy policy-… deleted." and the list is empty again.

### 6. A Security Agent: create, activate, run *(fresh sign-in for activation)*

Before the first run, the planning worker must be running (see [Start](#start)) and the Environment needs a pricing approval (see [Planner pricing](#planner-pricing)). Without the approval a run stays `queued`.

1. Open **Security agents** and click **Create Security Agent**. Choose the template **Finding Response**, give it a name, and set:

   | Field | Value used in the test run |
   | --- | --- |
   | Trigger mode | **Manual only** |
   | AI cost budget (nano OpenRouter credits) | `50000000` |
   | AI token budget | `4096` |
   | Step limit | `1` |
   | Runtime seconds | `300` |

   Choose **Manual only** on purpose. With the default trigger mode an enabled agent starts a run on its own for every open finding that matches its trigger; in the test run that was nine runs within a minute of enabling it.
2. Click **Save Security Agent definition**. The definition appears under "Security Agent definitions" as `disabled`.
3. Click the definition. In its dialog click **Validate definition** (the badge becomes `validated`), then **Enable supervised execution** (the badge becomes `supervised`). Both need the fresh sign-in; otherwise the dialog offers **Reauthenticate to activate**.
4. Optional: type a **Simulation goal** and the ID of a finding as **Evidence ID** (the ID is in the finding's address and in its dialog), then **Simulate plan**. You see "Simulation only. This does not execute the proposed steps." and a summary such as "Planned 1 action(s) from 1 evidence record(s)", with "zero side effects".
5. Type the ID of an open finding as **Evidence ID** and click **Start supervised run**. The run appears at the top of "Security Agent runs" as `queued`.

   The finding must match the agent's trigger. The Finding Response template reacts to findings whose rule is `credential`. The two findings of the AWS sync have other rules (`iam_role_administratoraccess_policy` and `ec2_instance_imdsv2_enabled`), and a run for one of them is refused (`409 operation_conflict`, shown as "The Security Agent operation was rejected, changed elsewhere, or execution controls are disabled."). The test run used "Long-lived credential reachable by an agent" findings with the rule `credential`, which earlier work had written into the local database by hand. A fresh stack has none: see [Known issues](#known-issues). A second run of the same agent for the same finding is refused ("The Security Agent operation was rejected, changed elsewhere, or execution controls are disabled.").

### 7. The provider rejects the plan; close the run

1. Click the run. Within about 15 seconds it shows the state `needs_human` and a box **Why this run stopped**:

   > The AI provider refused the planning request before it generated anything. Nothing was charged and no action ran. Typical causes are a provider account without credits, a credential the provider does not accept, or a rate limit.
   > Recorded code: `planner_provider_rejected`

   This is the expected result until the OpenRouter account has credits. Below it: "No plan has been persisted.", "No action has executed." and "No AI rationale is available for this run."
2. Under **Close this run** choose a reason ("No action required" or "Resolved outside the product"), optionally type a one-line note, and click **Close run**.
3. The run now shows a second badge `closed` and a box **Closed by a person** with the reason, the time, who closed it and the note. The run keeps the state `needs_human`; closing cannot be undone and is written to the audit log.

Other stop reasons you may see in that box:

| Recorded code | Meaning | Reasons offered when closing |
| --- | --- | --- |
| `planner_provider_rejected` | The provider refused the request before generating anything. Nothing was charged. | No action required, Resolved outside the product |
| `planner_not_sent` | No request left the product. Nothing was sent or charged. | No action required, Resolved outside the product |
| `budget_usage_unknown` | A request was sent, but its outcome and usage could not be verified. The usage stays recorded as unknown, and the run holds its agent's capacity until it is closed. | Accept that the AI usage stays unknown |

Only the first was produced in the browser run. Runs with the other two existed from earlier work and were closed through the API.

The list of runs shows only the state, so a closed run still reads `needs_human` there; open it to see the `closed` badge.

When you are done, open the definition and click **Save as disabled draft** so the agent starts nothing further.

### 8. API token and workspace name *(fresh sign-in)*

1. **API Access**: type a **Token name** and click **Create API token**. You see "API token created; reveal it before the grant expires". Click **Reveal token**, copy the token, then **I saved it — destroy recovery copy**. While a token waits to be revealed, the other buttons on the page stay disabled. **Revoke** asks for confirmation and the token then shows "Revoked".
2. **Identity & Access**, section Workspace onboarding: type a new **Workspace display name** and click **Update workspace**. The workspace selector shows the new name. Change it back the same way.

### 9. Sign out

**Sign out** returns to the "Sign in to Zasp" card; the session is refused afterwards.

## Planner pricing

A planner request is sent only under an administrator's pricing approval for the Environment: which provider account and model, and the most a request may cost. There is no screen for it and no way to read the current approval back. It is set with one request, `PUT /api/v1/security-agent-planner-pricing`, which the API accepts only from a browser session with a fresh sign-in.

The approval names the OpenRouter token by a reference and by its SHA-256 digest, never by value. Compute the digest in a terminal; the 64 hex digits it prints go after `sha256:` below:

```bash
printf '%s' "$OPENROUTER_API_KEY" | shasum -a 256    # Linux: sha256sum
```

Then, signed in as the administrator and within the fresh sign-in window, open the browser's developer console on any product page and run this, with the digest pasted in:

```js
const digest = "sha256:<the 64 hex digits>";
const operation = "create";   // "version" to replace an approval, "disable" to switch it off
const currentVersion = 0;     // 0 for the first approval, otherwise the version the last answer returned
const accountVersion = 0;     // 0 for the first approval, otherwise account_version of the last answer

const s = await (await fetch("/api/v1/session/bootstrap")).json();
const stamp = (d) => d.toISOString().replace(/\.\d+Z$/, ".000000Z");
const now = new Date();
const response = await fetch("/api/v1/security-agent-planner-pricing", {
  method: "PUT",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": s.csrf_token,
    "X-Zasp-Expected-Scope": `${s.organization_id}/${s.workspace_id}/${s.environment_id}`,
    "X-Zasp-Fresh-Auth": "confirmed",
    "Idempotency-Key": `pricing-${Date.now()}`,
    "If-Match": `"${currentVersion}"`,
  },
  body: JSON.stringify({
    environment_id: s.environment_id,
    operation,
    expected_account_version: accountVersion,
    policy: {
      provider: "openrouter", model: "openai/gpt-5-mini", account_profile: "local-stack", cost_unit: "openrouter_credit",
      maximum_tokens: 4096, maximum_cost_nano_credits: 50000000,
      request_policy_version: "security-agent-planner-v1", request_token_limit: 2048,
      credential_reference: `secret_ref_planner/${s.organization_id}/${s.workspace_id}/${s.environment_id}/openrouter`,
      credential_digest: digest,
      effective_at: stamp(now), expires_at: stamp(new Date(now.getTime() + 14 * 24 * 3600 * 1000)),
    },
  }),
});
[response.status, await response.json()];
```

A `200` answer carries `version` and `account_version`; write both down, because the next change must name them. An approval lasts at most 30 days (`expires_at`); this one asks for 14.

What was tested: this exact snippet with `operation = "version"` replaced the approval of the test stack twice (answers `200`, versions 2 and 3), and a run started after the first replacement reached the provider. The first approval of that stack was written through the database before the route worked, so `operation = "create"` through the route has not been tried. The model, policy version and token limit are the values `stack.sh` gives the planning worker.

## What you should see

Observed on 2026-11-14. Pages took 6 to 10 seconds to load while the stack was busy; Compliance took about 25.

| Page | What it showed |
| --- | --- |
| Signed out, `/` | A card "Sign in to Zasp" with a **Sign in** button. A deep link such as `/connectors` shows the same card at its own address. |
| Overview | Four counters (Agents 0, High-risk paths 0, Verified changes 0, Blocked changes 0), a red line "Coverage is degraded" and a "Needs attention" card. Its "Needs human" counter counts Security Agent runs that need a person and are not closed. |
| Agents, Tools & MCP, Runtimes | "No records in this scope." Expected: an AWS sync adds nothing here. |
| Identities | The four IAM roles. A row opens a detail dialog. |
| Findings | The two AWS posture findings and whatever else exists. A row opens the finding with its actions. |
| Attack Paths | "No attack paths in this scope." |
| Red Team | "No Red Team tests in this scope." and "No Red Team runs in this scope.", with **Create test**. Its workers do not run here. |
| Attack Lab | A safety approval form that asks for a completed failing Red Team run. Its workers do not run here. |
| Policies | The create form and the list. A policy opens a detail card with its actions and "Runtime decision history". |
| Integrations | "Configured integrations" and the "Connector catalog". An integration opens in a dialog: its fields, Setup progress, Connection test, Collected data, the AWS account scope, Automatic discovery with the three projection states, **Sync inventory now**, the sync schedule ("No automatic sync schedule.") and Sync history. |
| Sensors | Four counters at 0 and "No runtime sensors". |
| Security agents | Execution controls (one line per action), the definitions, the runs and "Pending approvals". A definition and a run each open in a dialog. A run lists its related findings, attack paths, sessions and audit records. |
| Approvals | "No pending approvals". |
| Identity & Access | Members, the built-in roles, Enterprise identity, Group mappings, and the Workspace and Environment forms. |
| API Access | "Pending reveal grants", "Create API token" and the token list. |
| Sessions | "Agent runtime": structured filters for runtime activity. "Console logins": the console sessions of the Organization. |
| Audit Log | Filters and the newest audit events. |
| Compliance | Framework and control filters, and the controls with their evidence. |
| Data & Retention | "Retention days", "Deletion enabled", **Save data controls** and the note "Data deletion unavailable". |
| Recovery | **Start signed backup** (or **Reauthenticate to start backup**), "Backup settings" and "No recovery operation in this scope". |
| External Data Flows | One row: "identity-provider · Required · identity_metadata · degraded". |
| System Health | "Security plane degraded", `postgresql` healthy and `identity-provider` degraded. |

The last two entries of the navigation, External Data Flows and System Health, are below the fold on a short window: scroll the navigation.

## Known issues

Seen on 2026-11-13 and 2026-11-14. Where the cause is an API answer, the route and the error code are given.

**Things that stop you**

- **Deleting an authorized integration locks every change.** **Delete integration** on an integration in the state `active` moves it to `revoking`. Nothing on this stack completes a revocation, so it stays there. The top of every page then shows **Recover committed operations** for "Delete Integration", and **Acknowledge recovered result** answers "Authoritative resource still exists after the committed deletion". All buttons that change something stay disabled for your user. Do not delete an authorized integration on this stack. An integration that still waits for authorization (`pending_authorization`) is deleted at once. To get out of the locked state, [reset](#reset), or mark the receipt as acknowledged in the local database:

  ```bash
  psql "postgres://postgres@127.0.0.1:55434/zasp?sslmode=disable" \
    -c "update zasp_workflow_receipts set acknowledged_at = now() where acknowledged_at is null and operation = 'deleteIntegration'"
  ```

- **On a fresh stack no finding can start a Security Agent run.** The emulated AWS account produces two findings, and neither matches the trigger of the Finding Response template (see step 6). Steps 6.5 and 7 were done with findings that had been inserted into the local database by hand; no way to create such a finding through the product was found on this stack. On a fresh stack you can create, validate and enable an agent, and the run step ends with the refusal message.
- **A deleted sync schedule cannot be set again.** After **Delete automatic sync** the schedule answers `404` on read, and saving a new cadence answers `409` whatever version is sent. The integration then has manual syncs only.
- **Webhook delivery status and test delivery fail.** `GET /api/v1/integrations/{id}/delivery-status` and `POST /api/v1/integrations/{id}/test-delivery` answer `503`. They depend on a readiness record that only a later release step creates.
- **Exports are not available.** The export routes are not mounted on this stack and answer `404`.

**Things that look wrong and are not**

- **A few seconds of waiting after every change.** See [What happens after every change](#what-happens-after-every-change). Underneath, the API answers `503 authorization_unavailable` or `409 authorization_changed` until the permission projector's next pass; the web application repeats the request. The browser's developer console lists those answers in red.
- **A `400` in the developer console when a run starts.** `POST /api/v1/security-agents/{id}/runs` refuses the short form of the request with `400 invalid_request` on this stack; the web application then sends the form that carries the finding's version and source, which is accepted (`202`).
- **`409 operation_conflict` on reads for some seconds** while several runs are being processed (seen on the lists of runs, execution controls and receipts). The web application repeats the read.
- **A record that does not exist answers `403`, not `404`.** Opening the address of a deleted policy, integration, Security Agent or finding shows an authorization message.
- `GET /api/v1/integrations/{id}/schedule` answers `404` until a schedule is saved; the dialog shows "No automatic sync schedule."
- `GET /api/v1/security-agent-runs/{id}/cleanup-recovery` answers `404` for a run with nothing to clean up; the run shows "Cleanup recovery is unavailable for this run."
- "Coverage is degraded" and "Security plane degraded": no runtime sensor is enrolled, and the identity provider reports `degraded`.

**Limits of what a run can show**

- **Nothing after planning has been exercised.** With no OpenRouter credits every run ends with `planner_provider_rejected`. Plans, approvals, actions, verification and the AI rationale have not been seen in the browser.
- **A run that was cut off blocks its agent until someone closes it.** A run with unknown planner usage (`budget_usage_unknown`) keeps holding its agent's capacity. Close it with "Accept that the AI usage stays unknown".
- **A sync that was cut off keeps its integration reserved.** For example when the discovery worker is stopped in the middle of a page. A later sync waits in `queued`. The reservation is released only by the next sync that is requested after the abandoned one has been quiet for ten minutes. This is in the schema (`release_abandoned` in `completion.sql`); it was not exercised in the browser.

**Smaller things**

- **Slow pages.** Most pages took 6 to 10 seconds on a busy machine, Compliance about 25.
- **Search.** "orchestrator" did not find `agent-orchestrator`; "agent" did. A result for an asset opens the Agents page, which does not list assets.
- **No screen for planner pricing**, and no way to read the current approval (see [Planner pricing](#planner-pricing)).
- **Starting a second run for the same agent and finding** is refused with a general message (`409 operation_conflict`).

## Known limits

- **AWS is emulated.** LocalStack accepts any external ID and never denies an action. A successful connection says nothing about a real role's trust policy or permissions.
- **Not running on this stack:** red team and Attack Lab workers, the runtime pipeline and whatever completes an integration's revocation. Pages for those features open against an API that has no worker behind it.
- **The API reads neither the graph nor the search index.** Search, findings, attack paths and relationships in the product come from PostgreSQL. Neo4j and the search index are written by the projection workers and can be inspected directly.
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
| Every page stays on "Authorization pending", or every new record is unreadable | The permission projector is not running. Check the `projector` line of `status`. |
| A sync fails at its second page | The analyzers are not installed: `stack.sh security-workers`. |
| A Security Agent run stays `queued` | The planning worker is not running, or the Environment has no pricing approval. |
| `worker-projection-graph` refuses with `stage=dependencies:projection-graph-connect` | Neo4j is not running, or port 7687 is taken by another Neo4j: run `stack.sh up`. `projection-graph-credential` means the LocalStack secret is gone (LocalStack keeps nothing across a restart); starting the worker again recreates it. |
| Sign-in returns to "Sign-in failed" | Read the correlation ID's line in `logs/api.log`. |
| `create /var/run/secrets/... (needs root)` | Prerequisite step 2 was not done, or the Mac was restarted since. |

## Reset

To stop and keep everything:

```bash
deploy/local/real-stack/stack.sh down
```

To start over with an empty product database, remove the database container, the Neo4j container and the state directory, as `down` itself suggests, then start again:

```bash
deploy/local/real-stack/stack.sh down
docker rm -f zasp-real-stack-pg zasp-real-stack-neo4j
rm -rf ~/.local/state/zasp-real-stack
deploy/local/real-stack/stack.sh start
deploy/local/real-stack/stack.sh bootstrap "Acme Security" acme.example you@gmail.com
deploy/local/real-stack/stack.sh start
```

The state directory holds the generated keys, certificates and passwords; the Neo4j administrator password takes effect only when its container is first created, which is why both go together. Your `provider.env` with the Stytch values is in that directory too: copy it out first. After a reset the browser warns about the certificate again, and the Organization in Stytch still exists; `bootstrap` resolves it instead of creating it. These commands were not run in the test pass.
