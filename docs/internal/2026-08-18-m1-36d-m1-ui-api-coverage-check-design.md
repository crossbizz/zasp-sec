# M1-36d M1 UI/API Coverage Check Design

Date: August 18, 2026

## Goal

Run the repository's reviewed UI/API traceability validator and prove that every
current interactive API operation is mapped to one UI action or remains an
explicit implementation-plan forward reference. M1-36d records validation
evidence only; it does not add an operation, route, client call, screen, or map
entry.

## Selected boundary

M1-25 and M1-26 already own the required implementation:

- `docs/product/ui-api-map.yaml` is the strict checked-in action map;
- `openapi/openapi.yaml` is the reviewed public operation authority;
- `scripts/check-ui-api-coverage.mjs` is the bounded validator;
- `npm run ui-api:test` exercises the current and hostile future states; and
- `npm run ui-api:check` executes the fixed repository validation boundary.

M1-36d therefore adds no wrapper, map copy, report artifact, dependency, or
operation. The execution sequence is:

```bash
npm run ui-api:test
npm run ui-api:check
```

The current honest result is exactly:

```text
UI/API coverage passed: planned=5 available=0 public=0 internal=0.
```

All five checked-in actions are `planned` forward references and must remain
absent from the current empty public operation inventory. A future `available`
action must resolve exactly once under `/api/v1`; every public operation must
have exactly one available mapping; `/internal/v1` operations remain unmapped;
and any missing, duplicate, unclassified, or lifecycle-drifted operation fails.

## Input, output, and safety boundary

The command reads only the fixed map and OpenAPI files. Both are bounded,
regular, non-symlink UTF-8 inputs. Duplicate YAML keys, aliases, merge keys,
multiple documents, unknown fields, invalid identities, invalid availability,
duplicate screen/action/operation identities, and unclassified paths fail
closed.

Success emits only the aggregate fixed line above. Failure emits only:

```text
UI/API coverage rejected.
```

No file content, path, operation identity, environment value, parser detail, or
stack trace crosses the CLI boundary. The validator performs no write,
dependency installation, network, provider, database, Docker, Kubernetes,
LocalStack, customer-environment, or customer-state operation.

## Scope and successor boundary

M1-36d proves traceability only. M1-36e remains Pending and separately owns the
local Kubernetes and LocalStack smoke checks. This task does not claim local
infrastructure health, make a planned action available, generate the OpenAPI
client, or alter the completed M1-36c boundary.

A repository quality contract binds the exact source row, M1-36c dependency,
existing command and input set, fixed output, planned/available/public/internal
semantics, successor boundary, status arithmetic, and exact blockers. README
documents the bounded gate and commands.

M1-36d starts at 648 Pending / 1 In progress / 76 Complete / 3 Blocked overall
and M1 68 total / 15 Pending / 1 In progress / 52 Complete / 0 Blocked. It may
move to Complete only after genuine status RED/GREEN, six consecutive validator
runs, the full hostile test suite, full pinned repository and Go verification,
production dependency audit, pinned secret scans, zero-finding whole-range
review, push, and exact-SHA Runnable UI success. Completion is 648 Pending / 0
In progress / 77 Complete / 3 Blocked overall and M1 15 / 0 / 53 / 0. M1-36e
remains Pending throughout.

## Alternatives rejected

- A new runner would duplicate the reviewed M1-26 validator and fixed output.
- A generated coverage report would create another authority that could drift.
- Treating planned actions as missing coverage would falsely require APIs not
  yet delivered; admitting a present planned operation would hide lifecycle
  drift.
- Treating internal operations as interactive UI surface would conflate product
  and data-plane contracts.
- Folding local infrastructure checks into this task would pre-claim M1-36e.
