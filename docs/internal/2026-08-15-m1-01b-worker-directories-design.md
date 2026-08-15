# M1-01b Worker Directories Design

Date: August 15, 2026

## Goal

Create the approved Python security-worker and Node redteam-worker package
skeletons and prove that each starts one no-op health command. This task creates
package and deployable ownership boundaries only. It does not load an adapter,
provider, queue, graph, prompt, finding, credential, configuration, or customer
payload, and it does not claim worker readiness beyond the local command result.

## Selected structure

Create two independent worker packages matching the authoritative deployables:

```text
workers/security-python/
  pyproject.toml
  security_worker/__init__.py
  security_worker/__main__.py
  tests/test_health.py

workers/redteam-node/
  package.json
  health.mjs
  health.test.mjs
```

The Python distribution is `zasp-security-worker`; its package is
`security_worker`. The Node package is private and named
`@zasp/redteam-worker`. Neither package joins the repository-root JavaScript
dependency graph, and neither introduces a third-party runtime dependency.

These are separate deployables and ownership boundaries. Later
Cartography/Prowler adapter work belongs to `workers/security-python`; later
Promptfoo adapter work belongs to `workers/redteam-node`. The current task does
not import or execute those engines.

## Command contracts

- `python -m security_worker health` writes exactly
  `security-worker health ok` plus one newline and exits zero.
- `node health.mjs health` writes exactly `redteam-worker health ok` plus one
  newline and exits zero.
- Missing, extra, or different arguments fail with no stdout.
- Injected writer failures are returned or produce a nonzero process result.
- The commands read no environment variable, dotenv file, profile, credential,
  proxy, endpoint, provider state, queue, graph, prompt, finding, or filesystem
  input. They open no listener and perform no network operation.

The fixed output is a package-start smoke result only. Shared service liveness
and readiness endpoints remain deferred to M1-28.

## Alternatives rejected

- Placing both workers in one language package would violate the approved
  Python adapter and Node red-team deployable boundaries.
- Adding worker loops, queues, adapter imports, or provider clients would
  preempt later scoped tasks and create unreviewed runtime authority.
- Reusing proof-only Prowler, Cartography, or Promptfoo harnesses would couple
  production package ownership to temporary fixture evidence.
- Adding a root workspace dependency would widen the package graph for two
  commands that require only standard runtimes.

## Verification

Tests precede each production command. Python unit tests and Node built-in tests
cover exact success, invalid argument shape, no output on rejection, and writer
failure. Final verification runs six focused passes, Python bytecode-free tests,
Node tests under 22.23.1, direct exact command executions, source-boundary
contracts, the retained Go command suites, the full pinned repository gate,
production audit, whitespace checks, secret scans, and zero-finding review.

Only after those gates pass may M1-01b move to Complete. M1-01c remains Pending.
M0-09, M0-18, M0-19, and PROV-01 remain Blocked; R-03 remains incomplete and
R-11 remains Not run.
