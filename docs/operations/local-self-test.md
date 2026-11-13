# Testing the product on your own machine

This guide gets the real product (API, workers, web application) running on one laptop, in a browser, against PostgreSQL, Temporal, OpenFGA, an emulated AWS account (LocalStack) and the Stytch test project. It is a test setup for one person. It is not a deployment.

## What has and has not been verified

Verified on 2026-11-13 in a Linux sandbox, with headless Chromium:

- `stack.sh start`, `status` and `stop` start, report and stop the web application, its TLS front and the permission projector. In that run the API and the three workers were already running and `start` left them alone, so `start` launching them itself was not exercised.
- The web application loads over HTTPS at `https://zasp.local-stack.test:8443`. Signed out, it shows "Sign in to Zasp".
- "Continue to sign in" redirects through Stytch to the Google sign-in page.
- `/auth/callback` with an invalid token shows "Sign-in failed" with a correlation ID. An invitation-shaped link shows "Accept your invitation" first.
- An API call through the TLS front with an API token returns 200 (`GET /api/v1/agents`).
- The script parses and its `status` and `stop` commands run under bash 3.2, the macOS system bash.
- The three projection workers (graph, search, risk) start and report ready against a local Neo4j, the local search node and the database. They were started by hand with the commands `start` uses; `start` launching them itself, and `up` creating the Neo4j container on a clean machine, were not exercised as whole commands (the functions `up` calls for Neo4j were each run).

Not verified:

- Anything on macOS. The first `start` on a clean machine (it runs `up`) was not run through the new command either; `up` on its own has been run many times on Linux.
- A completed sign-in in a browser through this front. A sign-in was completed once through the API by following the invitation email. Nobody has yet completed Google sign-in, and nobody has seen a signed-in page of the web application against this API.
- Every step under [Golden path](#golden-path) after sign-in, in the browser. The parts verified by other means are named there.
- The projection workers turning a discovered snapshot into a graph, search documents, findings and attack paths. No sync had completed when they were brought up; only synthetic snapshots were written to Neo4j and to the search index, and removed again.
- Trusting the generated certificate authority in a browser. The sandbox run ignored certificate errors.

Expect to find problems after sign-in. Please note the page, what you clicked and the correlation ID shown.

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

`OPENROUTER_API_KEY` is not used by this stack yet: the Security Agent worker does not start here (see [Known limits](#known-limits)).

## Start

From the repository root:

```bash
npm ci                                   # once, and after pulling new code
deploy/local/real-stack/stack.sh start   # first run: several minutes (images, Go build, schema)
deploy/local/real-stack/stack.sh bootstrap "Acme Security" acme.example you@your-company.example
deploy/local/real-stack/stack.sh start   # now starts the API, workers, projector and web application
```

The first `start` prepares the dependencies and the database and then stops, because no Organization exists yet. `bootstrap` creates the Organization in Stytch and in the product and makes the address its administrator. Use your own address at the domain of the Stytch account: Stytch refuses invitations to any other domain until billing is verified on the Stytch account. The second `start` ends with a status table and the address to open.

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

Two ways. Both are unverified through this front (see the top).

- **Google.** Click "Continue to sign in" and choose the Google account whose address you gave to `bootstrap`.
- **The emailed link.** `bootstrap` makes Stytch send an invitation. Open its link on the same machine. The page shows "Accept your invitation"; click the button. The link works once.

A failed sign-in shows "Sign-in failed" and a correlation ID. Search for that ID in `logs/api.log`.

## Golden path

The labels below are taken from the source and from the API's connector catalog. They have not been seen in a browser.

1. **Integrations** (left navigation, address `/connectors`). Choose **Amazon Web Services** in the connector catalog and fill in:

   | Field | Value |
   | --- | --- |
   | Name | anything |
   | Read role ARN | `arn:aws:iam::000000000000:role/zasp-reference/customer-read` |
   | External ID | `ref:aws/external-id/localstack-dev-0001` |
   | Home region | `us-east-1` |

   Then **Save integration**. Verified through the API: an integration with exactly these values is accepted and waits in `pending_authorization`.
2. **Review access** authorizes the connection: the product assumes the role in LocalStack and checks the account. The API accepts this step only from a browser session that signed in a few minutes ago; sign in again if it is refused. Verified by a component test against LocalStack, not through the API or the browser.
3. **Sync inventory now**, then watch **Sync history**. A sync needs the security analyzers (`stack.sh security-workers`). Verified by a component test: the collector reads the emulated account and yields 13 entities, 21 relationships and 5 posture results, 2 of them failing. A sync requested through the product has not yet been seen to complete.
4. **Looking at the result.** The product files everything it reads from AWS as an *asset*. The Agents, Tools, Identities and Runtimes pages list only what the Kubernetes, Okta and GitHub connectors report, so they stay empty after an AWS sync. There is no page that lists assets. Findings and attack paths are produced by the risk projection worker (`status` shows `worker-projection-risk`) from a completed sync; whether the posture results appear under Findings is not verified.

The emulated account is described in `deploy/local/real-stack/README.md`.

## Known limits

- **Permissions arrive a few seconds late.** A new integration or other resource can answer `authorization_unavailable` until the projector's next pass (every 5 seconds here; `status` shows the `projector` line). In production a job does this once a minute.
- **Slow pages.** On 2026-11-13 several read routes took 5 to 8 seconds, and audit events and the default compliance-controls page timed out. Later the same day one cause was fixed in the development database; the routes were not all measured again.
- **Pages that depend on a browser session and were never seen working:** Organization, members, group mappings, SSO connections, Security Agent execution controls, audit log. Their database functions were tested; the pages were not.
- **Sign-in and callback pages are plain text** without layout. They work; they are not styled.
- **Signed out, a deep link such as `/connectors` shows the sign-in page at `/`.** Whether you return to the deep link after sign-in is not verified.
- **AWS is emulated.** LocalStack accepts any external ID and never denies an action. A successful connection says nothing about a real role's trust policy or permissions.
- **Not running on this stack:** the Security Agent worker, red team and Attack Lab workers, and the runtime pipeline. Pages for those features open against an API that has no worker behind it.
- **The graph of an AWS sync is expected to fail.** The graph worker runs, but the graph store refuses kinds that contain the word `aws`, and every AWS entity kind does. Search and risk are not affected. See "The projection workers" in `deploy/local/real-stack/README.md`. The API reads neither the graph nor the search index: search, findings, attack paths and relationships in the product come from PostgreSQL.
- **Kubernetes, GitHub and Okta connectors** have placeholder credentials and cannot connect.
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
