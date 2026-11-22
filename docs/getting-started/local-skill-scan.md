# Check local agent skills with zaspctl

A developer can inventory Claude Code or Codex skills, check one bundle and read a local report before joining a Zasp Environment. These commands inspect files statically. They work offline and do not start MCP servers or run skill code.

The offline scanner benchmark shows which benign declarations produce review findings and where source comments can trigger a capability warning. [Benchmark and fixtures](../operations/local-skill-scanner-benchmark.md)

## Build and run

From the repository root, build the developer CLI with Go 1.26.0 or a compatible newer toolchain.

```sh
cd cmd/zaspctl
go build -o zaspctl .
./zaspctl --help
```

With the binary on your PATH, run from your project directory.

```sh
zaspctl addons inventory --local --scope project --project . --report-html ./inventory.html
zaspctl addons scan .claude/skills/ticket-helper --local
zaspctl addons scan .claude/skills/ticket-helper --local --json > scan.json
```

Open the HTML file on your device. Use a new filename for each report. The report contains the selected locations, observed copies, coverage and bundle digests. The individual scan lists the rule, affected relative file and suggested follow-up. A complete scan with no findings still has limited coverage. Installation establishes no evidence about use or authorization.

## Choose which locations to read

The default `--harness claude-code` profile uses the following roots.

| Scope | Locations inspected |
| --- | --- |
| `project` | The selected directory's immediate `.claude/skills/` bundles and its `.mcp.json` declarations. Includes uncommitted files. |
| `personal` | The current user's immediate `~/.claude/skills/` bundles. |
| `managed` | Immediate `skills/` bundles and `managed-mcp.json` under the Claude Code managed configuration root for this OS. |
| `all` (default) | Personal and managed locations. A project participates when you pass `--project DIR`. |

Managed lookup uses `/Library/Application Support/ClaudeCode` on macOS, `/etc/claude-code` on Linux, and `%ProgramFiles%\ClaudeCode` on Windows. Enabled plugin stores, synced stores and the personal `.claude.json` config are outside this discovery profile. Explicit scans accept a skill directory, its `SKILL.md`, or a supported MCP declaration. Identical complete observations of a skill in two scopes keep their individual installation rows.

A missing optional location is **absent**. An unreadable location, a skipped link or a bounded scan that cannot finish is **partial**. Inspect the skipped reason and rerun against a readable, complete local copy. A partial bundle has no approvable digest. The report includes the scanner's ruleset and advisory coverage.

## Check Codex skills

Choose `--harness codex` explicitly, or `--harness all` to inspect both profiles. The Codex profile reads the selected repository’s `.agents/skills`, the current user’s `~/.agents/skills`, and the documented Unix admin root `/etc/codex/skills` as permitted by `--scope`. To include nested repository lookup, pass the repository root as `--project` and its working directory as a relative `--codex-cwd`. The scan checks each directory along that path up to the selected boundary. [OpenAI local skill locations](https://learn.chatgpt.com/docs/build-skills)

```sh
zaspctl addons inventory --local --harness codex --scope project --project . --codex-cwd services/tickets
zaspctl addons inventory --local --harness codex --scope personal
```

The output identifies the harness and discovery profile for each observed bundle. Matching bytes can appear in multiple locations. Codex can follow skill symlinks, while this privacy-bounded discovery profile reports them as partial. Built-ins, plugin stores, configuration-dependent enablement, actual invocation and the Windows Codex admin root have no verified coverage in this profile.

## Use results in CI

```sh
zaspctl addons scan .claude/skills/ticket-helper --local --json --fail-on medium > scan.json
```

Output is one JSON document. Diagnostics appear on standard error.

| Exit code | Meaning |
| --- | --- |
| 0 | Scan or inventory completed. An interactive scan may contain findings. |
| 2 | Input or output error, such as a missing argument or an existing HTML destination. |
| 3 | Coverage is partial or the evaluation was unavailable. |
| 10 | A complete scan met the severity selected with `--fail-on`. |

## Preview a findings-only submission

Local reports can contain filenames, dependency names and other private information. Preview the fields that the submission command will send. Replace the example with your Environment ID.

```sh
zaspctl addons submit scan.json --mode findings-only --environment pid_00000000-0000-0000-0000-000000000001 --dry-run
```

The preview works offline. It shows the Environment, origin, completeness, manifest digest when complete, rule counts, skipped count and scanner versions. To send those fields to a deployment with the add-on scan API, configure its HTTPS origin in `ZASP_API_URL` and supply an Environment-scoped `ZASP_API_TOKEN` through your secret manager. Run the same command without `--dry-run`. The receipt for a complete report includes the review link. Scope and review authorization are enforced by the deployment.

For an interactive developer session, set `ZASP_API_URL` and run `zaspctl auth login --environment <environment-id>`. Open the first-party link and enter the code printed separately in your terminal. Check the Environment and choose **Approve CLI access**. Approval requires a fresh browser session with permission to manage API tokens for that Environment. The CLI redeems the single-use grant and stores its 15-minute findings-only credential in the user’s OS credential store. Use `--no-open` to open the URL yourself. Linux requires a desktop Secret Service and `/usr/bin/secret-tool`. macOS Keychain support requires a native build with cgo. Windows uses Credential Manager. Failure to use secure storage ends the interactive login.

On a managed Mac, `zaspctl device status` reads the assigned local endpoint's current policy revision, mode, sync state, and receipt counts. Use `zaspctl device doctor` for recovery guidance or add `--json` for machine output. The native macOS build verifies the service's root identity on the local socket. A stopped, unsupported or unassigned endpoint yields exit 3. The reported policy state describes this device's cached coverage.

A protected CI job can attach a commit-bound signature to a complete repository scan. The review can then distinguish a CI version from a personal installation with matching bytes. [Register and use a CI signer](../operations/addon-ci-provenance.md)

A data-controls administrator can explicitly send a selected ZIP to an Environment's configured private static worker. Tools & MCP shows the worker host for confirmation before transferring bytes. The ZIP is processed in memory. Before transfer, the browser shows whether the result stays in the browser or enters the Environment review registry. A recorded complete scan provides a version review link. [Configure the private scanner and understand its retention](../operations/private-addon-worker.md)

## Export a managed pilot report

An authorized security lead can open **Compliance → Export managed pilot evidence** and choose a registered cohort, device, or device-bound session reference. Request the retained report in a fresh browser session, then use its existing status and download controls. The report covers reported device policy acknowledgments, bounded endpoint decisions and installation digests. It marks truncated results, independent target verification, skill usage and the assigned fleet denominator explicitly.

The CLI can open the same form, optionally with `--no-open` to print the link. Set the first-party HTTPS origin in `ZASP_API_URL`.

```sh
zaspctl evidence export --environment ENVIRONMENT_ID --cohort PILOT_GROUP
zaspctl evidence export --environment ENVIRONMENT_ID --device DEVICE_ID --session ENDPOINT_SESSION_REF
```

The session reference comes from an endpoint observation in the selected device, including its device-level pilot report. This selector has no implicit relationship to hosted-gateway or console session IDs. The browser rechecks the Environment and requires an explicit export action. A CLI credential cannot download these files.

Open **Matching device installations** on a reviewed version to see devices that reported the same content digest. Each device link opens its scoped fleet record. A partial snapshot can add observed installations. A prior complete match stays visible with its earlier generation until a newer complete snapshot confirms removal. A revoked review and a confirmed removal have separate statuses.

## Check an offline advisory catalog

AppSec can provide a reviewed catalog and its SHA-256 through a trusted channel. Each row names one exact package release in npm or PyPI and the advisories known for that release. This lets an employee or CI runner rescan a private project's declared dependencies without sending package names to a registry. A scan with no catalog reports that advisory checks were unevaluated.

```sh
zaspctl addons scan ./skills/ticket-helper --local --json --fail-on high \
  --advisory-snapshot ./approved-releases.json --advisory-sha256 "$CATALOG_DIGEST"
```

Example catalog with a synthetic advisory and an explicitly evaluated release with no matches:

```json
{"schema_version":"zasp-advisories.v1","generated_at":"2026-11-01T00:00:00Z","packages":[
  {"ecosystem":"npm","name":"example-tool","version":"1.2.3","advisories":[{"id":"DEMO-001","severity":"high"}]},
  {"ecosystem":"pypi","name":"example-library","version":"2.0","advisories":[]}
]}
```

The local report includes catalog digest, age, matches and counts of evaluated and unresolved declarations. An absent version, unpinned dependency or catalog older than 30 days yields incomplete advisory coverage and exit 3. A known advisory meeting the explicit failure threshold yields exit 10 on a complete file scan. The findings-only team submission sends static rule counts and the manifest digest. Package names, advisory IDs and the private catalog stay local. Reissue the catalog with a fresh timestamp and checksum after reviewing updated advisory sources.
