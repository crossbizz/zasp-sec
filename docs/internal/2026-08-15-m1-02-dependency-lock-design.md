# M1-02 Dependency Lock Design

**Date:** August 15, 2026
**Decision owner:** Product owner, delegated to the implementation agent
**Status:** Approved for execution by the instruction to decide, fix, and proceed

## Decision

Add one reviewed product-runtime dependency inventory at
`build/dependencies.lock.yaml` and one fail-closed validator at
`scripts/validate-dependencies.mjs`. The root `verify` command will run the
validator before the existing tests, typecheck, lint, and build, so the current
push and pull-request workflow enforces the lock without a second CI path.

The initial inventory contains only direct dependencies of deployable product
manifests. It excludes proof harnesses, development/build tools, optional peer
dependencies, and transitive packages because those have separate lockfiles,
proof-specific license records, or later SBOM tasks. The exact initial runtime
set is:

| Manifest | Dependency | Version | SPDX license | Product owner |
| --- | --- | --- | --- | --- |
| `package.json` | `drizzle-orm` | `0.45.2` | `Apache-2.0` | `platform-data` |
| `package.json` | `lucide-react` | `1.31.0` | `ISC` | `web-platform` |
| `package.json` | `react` | `19.2.6` | `MIT` | `web-platform` |
| `package.json` | `react-dom` | `19.2.6` | `MIT` | `web-platform` |
| `package.json` | `stytch` | `14.2.0` | `MIT` | `identity-platform` |

The lock also names every product-runtime manifest currently expected to be
dependency-free: the web and red-team worker package manifests, the Python
security-worker project, the three service Go modules, and the CLI Go module.
This turns a later direct dependency in any product deployable into a reviewed
lock change rather than an invisible manifest edit.

## Lock contract

The YAML document is bounded, duplicate-safe, alias-free, and has exact
top-level keys. It records a schema version, approved internal owners,
allowlisted permissive licenses, prohibited copyleft licenses, the complete
product-manifest inventory, and sorted unique dependency entries.

Every dependency entry requires exactly:

- ecosystem, manifest, package name, and exact resolved version;
- SPDX license and internal product owner;
- runtime scope and an explicit approved review state.

The validator rejects missing/unknown fields, aliases, duplicate entries,
non-exact versions, unknown owners, licenses outside the allowlist, every
prohibited copyleft license, and every runtime entry not explicitly approved.
It compares the effective direct runtime dependency set to the lock and checks
the npm package lock's resolved version and license for the five current
packages. A manifest addition, deletion, version drift, license drift, or owner
policy drift therefore fails before application tests.

## Product-manifest parsing

- npm manifests contribute their direct `dependencies`; development and peer
  dependencies do not become product runtime dependencies.
- product Go modules contribute direct non-`indirect` `require` directives.
- the Python worker contributes its PEP 621 `project.dependencies` entries.
- syntax outside the deliberately small supported manifest forms fails closed
  rather than being ignored.

The validator performs no install, download, provider, Docker, credential, or
network operation. It reads only tracked repository files and prints one fixed
success or failure line. Its library boundary throws fixed categorized errors
for tests; the executable boundary does not emit paths or dependency payloads.

## Verification and status

Tests precede production. Hermetic Node tests cover the exact initial document,
required fields, duplicate/unknown members, aliases, version/license/owner
drift, unreviewed runtime entries, copyleft entries, manifest additions, empty
product manifests, and fixed process output. A repository contract binds the
source task, this design, the implementation plan, CI wiring, status arithmetic,
and unchanged blockers.

Completion requires six focused passes, the real dependency check, all product
module/worker regressions, the root repository build, the full pinned repository
gate, production audit, whitespace, secret scans, and zero-finding review.
Only then may M1-02 move to Complete. M1-03 remains Pending. M0-09, M0-18,
M0-19, and PROV-01 remain Blocked; R-03 remains incomplete and R-11 Not run.
