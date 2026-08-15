# M0-21a Security Agent planner boundary proof design

Date: August 15, 2026

## Decision

Prove the planner-only boundary with standard-library Node and a synthetic
OpenRouter-compatible server on a random numeric loopback port. The proof uses
no hosted model, OpenRouter credential, SDK, `.env`, proxy, profile, or ambient
provider setting. It has no executable tool, no general network access, and
no general shell authority.

The planner sees a fixed system policy, one bounded operator goal, one explicitly
untrusted evidence string containing an instruction-injection attempt, an exact
two-action catalog, and exact in-scope Organization-owned identifiers. The
untrusted text is data and cannot alter the catalog or scope.

## Catalog and scope

The exact two-action catalog contains:

1. `create_temporary_block_policy` for one fixed in-scope agent, with an exact
   TTL-bounded argument schema.
2. `assign_finding_owner` for one fixed in-scope finding and one fixed in-scope
   user, with an exact argument schema.

The fake endpoint returns a two-step plan using each catalog action exactly
once. Product validation independently checks the version, plan/run/finding
identity, exact step count and order, exact action names, exact argument keys
and values, scope membership, and fixed rationale text. The planner output has
no authority to execute either step.

Unknown actions or arguments, duplicate actions, missing steps, changed order,
new target IDs, out-of-scope IDs, arbitrary URL fields or URL text, shell fields
or shell-like text, tool calls, prose outside the structured document, aliases,
duplicates, wrong types, malformed UTF-8, trailing bytes, and oversized output
fail closed.

## Transport and lifecycle

The request is one exact bounded `POST /api/v1/chat/completions` with fixed
synthetic authorization and a closed JSON-schema response contract. Both sides
bind exact Host/raw headers, request/response bytes, model, token metadata, and
one-request authority. Only canonical `127.0.0.1` with an explicit numeric port
is allowed.

Main and request phases have absolute deadlines and abort signaling. Cleanup
uses a separate deadline, drains sockets, closes the retained server, and wins
error precedence. All failures use fixed categories and expose no injected
text, plan, arguments, IDs, URL, shell content, request/response, endpoint,
stack, or provider error.

Success is exactly:

`Security Agent planner proof passed: catalog=true scope=true injection=false url=false shell=false cleanup=true.`

## R-14 decision

M0-21 already supplies the redacted explanation/privacy half. R-14 may become
PASS only after this proof demonstrates the valid catalog-only plan and every
arbitrary URL, shell, new-action, and out-of-scope mutation is rejected.
