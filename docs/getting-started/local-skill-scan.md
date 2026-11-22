# Check local agent skills with zaspctl

A developer can inventory Claude Code or Codex skills, check one bundle and read a local report before joining a Zasp Environment. These commands inspect files statically. They work offline and do not start MCP servers or run skill code.

The offline scanner benchmark shows which benign declarations produce review findings and where source comments can trigger a capability warning. [Benchmark and fixtures](../operations/local-skill-scanner-benchmark.md)

## Get a verified binary

Open **Scan this device**. When your deployment has published a release, choose its exact OS and architecture. Use **Verify your download** to authenticate the signed manifest with your organization's trusted Ed25519 public key, then compare the file's SHA-256 before execution. A deployment with no staged release shows the source build. [Release owner instructions](../../deploy/cli-release/README.md)

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

## Inspect Claude Code declarations

Opt in to the additional local declaration profile. You can select a checked-out plugin or the installed plugin directory itself as the project root.

```sh
zaspctl addons inventory --local --harness claude-code --scope project --project . --declarations --json
zaspctl addons inventory --local --harness claude-code --scope personal --declarations --report-html personal.html
```

| Location | Evidence returned |
| --- | --- |
| Project or personal `.claude/agents/*.md` and `.claude/commands/*.md` | Filename, component type and whether frontmatter declares a tool list. A sub-agent needs a name and description. |
| Personal/project `.claude/settings.json`, project `.claude/settings.local.json`, managed `managed-settings.json` | Counts of declared hook handlers and command handlers. Ordinary settings and hook contents stay private. |
| An explicitly selected plugin directory with `.claude-plugin/plugin.json` | The manifest's recognized component keys and declarations in its conventional immediate `agents/`, `commands/` and `hooks/hooks.json` paths. |

These local rows carry the separate `claude-code-declarations.v1` profile. Usage and enablement remain unknown. Only the selected paths participate. The parser does not resolve manifest-supplied paths, registry URLs or custom component locations. Marketplace cache discovery, nested command groups, `CLAUDE_CONFIG_DIR` overrides and merged effective permissions remain outside the profile. File and entry limits, malformed metadata and linked directories surface partial coverage. Each run inspects up to 256 declaration entries, each at most 256 KiB, under the existing inventory time budget.

A declaration has no immutable skill manifest digest. Scanning a declaration alone cannot approve a plugin, export a shareable skill version, or prove execution. [Claude Code plugin manifest](https://code.claude.com/docs/en/plugins-reference) · [Settings](https://code.claude.com/docs/en/settings) · [Sub-agents](https://code.claude.com/docs/en/sub-agents)

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

For an interactive developer session, set `ZASP_API_URL` and run `zaspctl auth login --environment <environment-id>`. Open the first-party link and enter the code printed separately in your terminal. Check the Environment and choose **Approve CLI access**. Consent requires fresh sign-in and the active Environment’s existing OpenFGA `run_tests` grant. Developer owners, security engineers, security admins and organization admins receive it within their assigned scope. Compliance viewers and read-only viewers do not. The CLI receives only `submit_addon_scans` for local findings. Removing the user’s testing grant stops redemption and further uploads. The CLI redeems the single-use grant and stores its 15-minute findings-only credential in the user’s OS credential store. Use `--no-open` to open the URL yourself. Linux requires a desktop Secret Service and `/usr/bin/secret-tool`. macOS Keychain support requires a native build with cgo. Windows uses Credential Manager. Failure to use secure storage ends the interactive login.

On a managed Mac, `zaspctl device status` reads the assigned local endpoint's current policy revision, mode, sync state, and receipt counts. Use `zaspctl device doctor` for recovery guidance or add `--json` for machine output. The native macOS build verifies the service's root identity on the local socket. A stopped, unsupported or unassigned endpoint yields exit 3. The reported policy state describes this device's cached coverage.

A protected CI job can attach a commit-bound signature to a complete repository scan. The review can then distinguish a CI version from a personal installation with matching bytes. [Register and use a CI signer](../operations/addon-ci-provenance.md)

A data-controls administrator can explicitly send a selected ZIP to an Environment's configured private static worker. Tools & MCP shows the worker host for confirmation before transferring bytes. The ZIP is processed in memory by default. In Environments with private encrypted retention enabled, you can separately choose to keep the ZIP for up to 24 hours. Before transfer, verify the worker host, any archive expiry, and whether the finding counts stay in the browser or enter the Environment review registry. A recorded complete scan provides a version review link. [Configure the private scanner and understand its retention](../operations/private-addon-worker.md)

## Export a managed pilot report

An authorized security lead can open **Compliance → Export managed pilot evidence** and choose a registered cohort, device, or device-bound session reference. Request the retained report in a fresh browser session, then use its existing status and download controls. The report covers reported device policy acknowledgments, bounded endpoint decisions and installation digests. It flags truncated results and identifies unknown skill usage and fleet assignment. For a signed macOS ticket decision, the JSON, CSV and printable report can show the linked test run, evidence digest and recorder result. A finding of no protected write covers only the verified observation window and requires an allowed control write from the same device generation, session and policy revision. Missing or ambiguous evidence leaves the target effect unknown.

The CLI can open the same form, optionally with `--no-open` to print the link. Set the first-party HTTPS origin in `ZASP_API_URL`.

```sh
zaspctl evidence export --environment ENVIRONMENT_ID --cohort PILOT_GROUP
zaspctl evidence export --environment ENVIRONMENT_ID --device DEVICE_ID --session ENDPOINT_SESSION_REF
```

The session reference comes from an endpoint observation in the selected device, including its device-level pilot report. This selector has no implicit relationship to hosted-gateway or console session IDs. The browser rechecks the Environment and requires an explicit export action. A CLI credential cannot download these files.

Open **Matching device installations** on a reviewed version to see devices that reported the same content digest. Each device link opens its scoped fleet record. A partial snapshot can add observed installations. A prior complete match stays visible with its earlier generation until a newer complete snapshot confirms removal. A revoked review and a confirmed removal have separate statuses.

## Read V2 static findings

New scans use `zasp-static.v2`. Process and network checks skip comments and documentation strings in the supported Python, JavaScript/TypeScript, shell and PowerShell syntax. Four additional findings identify an instruction override, a credential read, a remote/decoded interpreter invocation, and an unresolved package launcher or unprotected plaintext MCP endpoint. Review the matching file and suggested fix. The code was observed statically and its execution is unknown. Package hygiene and unevaluated advisory notices are listed independently and do not trigger `--fail-on`.

A saved v1 receipt keeps its original ruleset, counts and review. Use `zaspctl addons scan PATH --local --ruleset zasp-static.v1` to reproduce a prior scan, or add `--ruleset zasp-static.v1` to `zaspctl addons attest` when attesting an old receipt. V1 and V2 reports for matching bytes have separate reviewed identities. [Measured scope and limits](../operations/local-skill-scanner-benchmark.md)

## Inspect a versioned dependency finding

A local `dependency.unpinned` finding identifies the relative declaration file, its SHA-256, the skill manifest digest when complete, the scanner ruleset, the matching condition and the suggested fix. A range such as `^1.2.0` leaves the exact dependency version unresolved. The offline JSON, terminal and HTML reports show the reviewed framework references including OWASP Agentic 2026 ASI04. For a findings-only submission, inspect the dry run and follow the version link returned by the server. An authorized reviewer sees the declared rule and count, the same framework edition, and the exact manifest digest. Package names, file names, file hashes, advisory matches and source stay local. Run `zaspctl frameworks notices` offline to read the bundled catalog licenses and attribution. A later edit has its own version and review.

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

### Verify a signed snapshot offline

AppSec can distribute a `zasp-advisories.v2` catalog derived from a pinned revision of the GitHub Advisory Database. Configure the reviewer's Ed25519 public key through a separate trusted channel, such as an IT-managed configuration. A catalog and its detached signature can be distributed together. The scanner verifies the exact file bytes against the configured key and records the signer fingerprint, source repository, source revision, catalog digest, generation time and age in the local report.

```sh
zaspctl addons scan ./skills/ticket-helper --local --json \
  --advisory-snapshot ./approved-releases.json \
  --advisory-signature ./approved-releases.sig \
  --advisory-key /path/to/company-approved-feed-signer.pem
```

The v2 catalog uses the same `packages` array as v1. Set `schema_version` to `zasp-advisories.v2`, `source` to `https://github.com/github/advisory-database` and `source_revision` to the reviewed 40-character Git commit. Each advisory may include a reviewed `fixed_version` or `withdrawn: true`. A signer can produce the raw detached signature with `openssl pkeyutl -sign -rawin -inkey reviewer-private.pem -in approved-releases.json -out approved-releases.sig`. Keep the private key on the signing host. The public key uses PEM SubjectPublicKeyInfo format.

An exact package declaration can match an entry in that catalog. The report counts unresolved ranges, exact releases missing from the feed, and withdrawn matches separately. Stale snapshots retain their historical matches and display their age. The signature authenticates the reviewer's assertions. Installed bytes, reachability and transitive dependencies require separate observations.
