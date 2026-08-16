# M1-27 Raw Fetch Lint Design

## Goal and boundary

M1-27 adds an ESLint enforcement boundary that prevents normal frontend code
from bypassing the M1-24 generated TypeScript client with a hand-written Fetch
request. The rule applies to JavaScript and TypeScript under `app/**` and
`apps/web/**`. Exactly two files form the trusted client boundary and are
excluded: `apps/web/api/client.ts` and `apps/web/api/generated.ts`.

Proof harnesses, backend services, build scripts, and third-party dependencies
are outside this frontend-only rule. M1-28a remains Pending. M0-09, M0-18, and
M0-19 remain Blocked.

## Selected approach

Use a repository-owned ESLint 9 flat-config plugin rather than a text scanner
or a collection of `no-restricted-syntax` selectors. The local rule can inspect
executable syntax without treating comments, documentation, or inert strings as
network calls, and it can cover the Fetch call shapes through one reviewed
implementation.

The production rule lives in `eslint-rules/no-raw-fetch.mjs`. The root
`eslint.config.mjs` imports it as `zasp/no-raw-fetch` and enables it at error
severity only for the frontend roots. No dependency or lockfile change is
needed.

## Detection contract

The rule reports a call when its callee is any of these raw Fetch forms:

- `fetch(...)`;
- `globalThis.fetch(...)`, `window.fetch(...)`, or `self.fetch(...)`;
- the equivalent static computed property form such as
  `globalThis["fetch"](...)`;
- optional-call variants; or
- `.call(...)`, `.apply(...)`, or `.bind(...)` invoked from one of the raw
  Fetch references.

The entire normal frontend Fetch boundary is forbidden, rather than only calls
whose first argument is a statically visible `/api/v1/` literal. This closes
the trivial evasion of moving the public path into a variable or `Request`
object. Typed calls such as `client.GET("/api/v1/home/summary")` are allowed
because their callee is the reviewed generated client, not raw Fetch.

The rule emits one stable message ID, `useGeneratedClient`, directing the
caller to `apps/web/api/client.ts`. It has no options and performs no file or
network I/O.

## Verification

`eslint-rules/no-raw-fetch.test.mjs` uses ESLint's in-memory `Linter` against
real syntax. It proves:

- a seeded direct `/api/v1/` Fetch violation fails;
- member, computed, optional, and call/apply forms fail;
- variable and `Request` arguments cannot evade the rule;
- generated-client method calls and inert `/api/v1/` strings pass; and
- the flat config applies to normal frontend paths while exempting exactly the
  two generated-client boundary files.

The root commands are:

```text
npm run raw-fetch:test
npm run lint
```

`raw-fetch:test` is wired into `npm run verify` before the repository-wide lint
gate. The M1-27 quality contract binds the source requirement, exact scope,
commands, README wording, task arithmetic, prerequisite, successor, and
unchanged blockers. Completion requires witnessed RED/GREEN evidence, six
stable focused runs, full pinned verification, zero production audit findings,
redacted secret scans, exact-SHA Runnable UI success, and a clean synchronized
branch.
