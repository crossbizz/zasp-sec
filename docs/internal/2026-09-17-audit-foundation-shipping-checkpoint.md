# Audit foundation candidate, September 17

The recovered tree had 174 modified and 435 untracked paths. Nothing was
blanket-staged. Fetch confirmed origin/main fda8ae99921be468b3d95f2369f54112a725e046;
merge8bcc584341b2dccecd32b61132537057e2aae49a incorporated it without changing
the recovered file contents or dropping any dirty work.

## Candidate boundary

The existing three local commits bf66c176, 698b38f6 and a39e2730 contain scoped
export artifact storage, immutable codecs and reserved API schemas. Independent
dependency review found them self-contained as an inactive foundation, with one
required compatibility correction: five mixed-case SSO/SCIM actions already
persisted by schema19 were rejected by the new codec and schema.

The candidate contains those commits plus only the retained-action allowlist,
positive/near-miss codec tests, matching AuditEvent/AuditExportEvent patterns,
and their schema test. Generic event-emission grammar is unchanged. Export
routes remain absent and reserved-schema descriptions/hidden-route tests remain.
PlannedObjectReference, new SQL, workers, mounted APIs and all reconciliation
changes stay outside this boundary. This does not complete the export feature.

## Exact-candidate evidence

Plain archive of8bcc5843, with the four-file correction, is at
/private/tmp/zasp-audit-foundation-candidate.EwaihZ. Its own lock installed using
npm ci --offline --ignore-scripts --no-audit --no-fund, not the recovered tree's
different dependency versions. Independent review found no findings in this
exact correction and confirmed routes remain unpublished.

- Go race audit/artifactstore/s3driver/bucketlayout: exit0, 90af03.
- OpenAPI38/38, official generated-output check and typecheck: exit0, a175a6.
  Generated types are unchanged by the two pattern corrections.
- Full Vitest:197 files,1244 tests passed,68.56s, e92f7f.
- Production UI build: exit0, 0ec8f9.
- Standalone HTTP smoke: root200 and all7 emitted JS/CSS assets200, 6226f0.
  Owned server7895 was stopped after the check (78f4ff). This is not browser
  hydration or authenticated end-to-end proof.

SHA256 bindings:

| Candidate file | SHA256 |
| --- | --- |
| package-lock.json | 71186de1c037e0749b4fac856c6b65afbee8ee30c9fae225e771b8134831acd3 |
| services/platform/audit/export.go | 63b116fb3ca044a8d241d9cab64e60c140568cfc1402b5d306d5498610f3dd47 |
| services/platform/audit/export_test.go | 35e48a6c5de09ae621fe8c2cd4d04f50c30619033629fecafd07f1789d261840 |
| openapi/openapi.yaml | 03304406eb0779bc51e0b551c1d4fa36176a08a1f094b241a761cbd34e2af598 |
| openapi/identity-admin.test.mjs | 843c648ef25ef11363c0ad3d96e81b49c3a5dd8d0e1713c32afa18d3f5f8ca70 |

## Still not a release

No push or production promotion. Fresh approved dependency advisory evidence
and the remaining candidate release checks are required. The recovered release
gate's204 contract tests passed separately (0511ec); that different source tree
is not this candidate's release-gate proof. Its fail-closed advisory guard must
not be replaced with the historical offline-zero-counter check.

The online npm audit disclosure question was presented again without issuing
an audit request. Continue independent implementation while that gate is open.
All original728 tasks and the additional collector scope remain unchanged.
