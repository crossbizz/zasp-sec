# M1-25 UI API Map Seed Design

## Decision

Create one strict checked-in `docs/product/ui-api-map.yaml` seed that maps two
planned product screens to their canonical future public OpenAPI operations:

- Home: `getHomeSummary` and `globalSearch`;
- System Health: `getSystemStatus`, `listSystemComponents`, and
  `getSystemVersion`.

The map records a stable screen identifier, product label, and one stable
action identifier per operation. Every action is explicitly
`planned` because M1-23 intentionally has `paths: {}`. This preserves an honest
forward reference: no API is claimed implemented or callable.

## Exact artifact schema

The top level has exactly `schema_version` and `screens`. Version is exactly 1.
`screens` is an ordered nonempty list with unique `id` and `label`.
Each screen has exactly:

- `id`: lower snake case product identifier;
- `label`: fixed product navigation label;
- `actions`: ordered nonempty list.

Each action has exactly:

- `id`: lower snake case identifier unique across the artifact;
- `operation_id`: canonical case-sensitive planned OpenAPI operation ID;
- `availability`: exactly `planned` for this seed.

The source plan has not yet fixed product route strings, so the seed does not
invent them. The map contains no route, method, API path, schema, server,
credential, provider, or runtime URL; OpenAPI remains the sole API contract and
later UI/operation tasks cannot silently diverge through duplicated metadata.

## Resolution boundary

M1-25 validates the strict map and proves its five forward references against a
synthetic operation-ID inventory shaped like the future coverage input. It does
not add an OpenAPI operation or CI coverage command. M1-26 owns the reusable CI
coverage script that reads the actual OpenAPI root, permits an absent operation
only while its map action is `planned`, resolves it automatically when defined,
and fails missing or unmapped active public operations.

This distinction avoids weakening the current empty OpenAPI root while making
the future coverage behavior deterministic. Duplicate YAML keys, aliases,
merge keys, unknown fields, duplicate screens/actions/operations, reordered or
invented seed data, and invalid identifiers fail closed.

## Verification and status boundary

Tests first require the absent artifact and capture RED. GREEN requires strict
YAML parsing, exact schema and seed inventory, hostile mutation rejection, and
synthetic all-five-operation resolution. Full pinned repository verification,
build, audits, secret scans, and zero-finding review precede completion and
exact-SHA CI.

M1-26 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.
