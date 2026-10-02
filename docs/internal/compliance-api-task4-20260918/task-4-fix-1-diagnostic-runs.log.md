# Task 4 fix1 RED and diagnostic evidence

The source, decoder, attachment, and legacy compatibility failures are behavioral REDs. The first SQL audit injector was not valid audit-write-path evidence: adding an administration-table trigger changed readiness/catalog authority, so the request denied before acquiring the expected read lease. That injector was removed, not bypassed. The accepted injector instead observes the actual INSERT relation lock and cancels that SQL operation. Fingerprint mismatch is intentional calibration evidence, not a product regression. The TypeScript error exposed the additive legacy compatibility requirement; provisional fixture changes were reverted.

## fix1clientred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-download.test.ts
```

Exit: 1

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

 ❯ apps/web/api/compliance-download.test.ts (5 tests | 1 failed) 16ms
     × uses a four MiB attachment default while honoring explicit lower limits 8ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  apps/web/api/compliance-download.test.ts > compliance download transport > uses a four MiB attachment default while honoring explicit lower limits
APITransportError: API response exceeded the configured limit
 ❯ readBounded apps/web/api/client.ts:234:13
    232|     if (length > maximumBytes) {
    233|       void reader.cancel();
    234|       throw new APITransportError("response_too_large", "API response …
       |             ^
    235|     }
    236|     chunks.push(value);
 ❯ validateResponse apps/web/api/client.ts:183:21
 ❯ transport apps/web/api/client.ts:118:4
 ❯ coreFetch node_modules/openapi-fetch/src/index.js:171:19
 ❯ apps/web/api/compliance-download.test.ts:10:24

⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯


 Test Files  1 failed (1)
      Tests  1 failed | 4 passed (5)
   Start at  17:57:27
   Duration  1.40s (transform 51ms, setup 232ms, import 40ms, tests 16ms, environment 856ms)

```

## fix1decoderred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts
```

Exit: 1

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

 ❯ apps/web/api/compliance-decoders.test.ts (5 tests | 1 failed) 7ms
     × requires the authoritative freshness on direct live controls 3ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  apps/web/api/compliance-decoders.test.ts > compliance current contracts > requires the authoritative freshness on direct live controls
Error: schema mismatch
 ❯ bad apps/web/api/administration-decoders.ts:71:31

 ❯ exact apps/web/api/administration-decoders.ts:56:355
 ❯ control apps/web/api/administration-decoders.ts:54:51
 ❯ apps/web/api/administration-decoders.ts:43:111
 ❯ apps/web/api/administration-decoders.ts:52:186
 ❯ decoded apps/web/api/administration-decoders.ts:55:189
 ❯ page apps/web/api/administration-decoders.ts:52:86
 ❯ decodeComplianceControlPage apps/web/api/administration-decoders.ts:43:64
 ❯ apps/web/api/compliance-decoders.test.ts:11:10

⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯


 Test Files  1 failed (1)
      Tests  1 failed | 4 passed (5)
   Start at  17:59:31
   Duration  973ms (transform 43ms, setup 176ms, import 28ms, tests 7ms, environment 663ms)

```

## fix1sqlred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-fix1-red --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-worker-final.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestComplianceHTTPPostgres(ControlFreshness|GrantLifecycle)$' -test.v -test.timeout 240s
```

Exit: 1

```text
=== RUN   TestComplianceHTTPPostgresControlFreshness
=== RUN   TestComplianceHTTPPostgresControlFreshness/fresh_101st_source
    compliance_http_postgres_test.go:47: authoritative soc2_security-policies control: {ID:soc2_security-policies Freshness: FreshUntil:2020-01-02 00:00:00 +0000 UTC EvidenceIDs:[policy-001 policy-002 policy-003 policy-004 policy-005 policy-006 policy-007 policy-008 policy-009 policy-010 policy-011 policy-012 policy-013 policy-014 policy-015 policy-016 policy-017 policy-018 policy-019 policy-020 policy-021 policy-022 policy-023 policy-024 policy-025 policy-026 policy-027 policy-028 policy-029 policy-030 policy-031 policy-032 policy-033 policy-034 policy-035 policy-036 policy-037 policy-038 policy-039 policy-040 policy-041 policy-042 policy-043 policy-044 policy-045 policy-046 policy-047 policy-048 policy-049 policy-050 policy-051 policy-052 policy-053 policy-054 policy-055 policy-056 policy-057 policy-058 policy-059 policy-060 policy-061 policy-062 policy-063 policy-064 policy-065 policy-066 policy-067 policy-068 policy-069 policy-070 policy-071 policy-072 policy-073 policy-074 policy-075 policy-076 policy-077 policy-078 policy-079 policy-080 policy-081 policy-082 policy-083 policy-084 policy-085 policy-086 policy-087 policy-088 policy-089 policy-090 policy-091 policy-092 policy-093 policy-094 policy-095 policy-096 policy-097 policy-098 policy-099 policy-100]} want freshness=fresh deadline=2026-09-20 00:59:36 +0000 UTC preview=100
=== RUN   TestComplianceHTTPPostgresControlFreshness/all_stale
    compliance_http_postgres_test.go:49: authoritative soc2_security-policies control: {ID:soc2_security-policies Freshness: FreshUntil:2020-01-02 00:00:00 +0000 UTC EvidenceIDs:[policy-001 policy-002 policy-003 policy-004 policy-005 policy-006 policy-007 policy-008 policy-009 policy-010 policy-011 policy-012 policy-013 policy-014 policy-015 policy-016 policy-017 policy-018 policy-019 policy-020 policy-021 policy-022 policy-023 policy-024 policy-025 policy-026 policy-027 policy-028 policy-029 policy-030 policy-031 policy-032 policy-033 policy-034 policy-035 policy-036 policy-037 policy-038 policy-039 policy-040 policy-041 policy-042 policy-043 policy-044 policy-045 policy-046 policy-047 policy-048 policy-049 policy-050 policy-051 policy-052 policy-053 policy-054 policy-055 policy-056 policy-057 policy-058 policy-059 policy-060 policy-061 policy-062 policy-063 policy-064 policy-065 policy-066 policy-067 policy-068 policy-069 policy-070 policy-071 policy-072 policy-073 policy-074 policy-075 policy-076 policy-077 policy-078 policy-079 policy-080 policy-081 policy-082 policy-083 policy-084 policy-085 policy-086 policy-087 policy-088 policy-089 policy-090 policy-091 policy-092 policy-093 policy-094 policy-095 policy-096 policy-097 policy-098 policy-099 policy-100]} want freshness=stale deadline=2020-01-02 00:00:00 +0000 UTC preview=100
=== RUN   TestComplianceHTTPPostgresControlFreshness/missing
    compliance_http_postgres_test.go:51: authoritative soc2_security-policies control: {ID:soc2_security-policies Freshness: FreshUntil:1970-01-01 00:00:00 +0000 UTC EvidenceIDs:[]} want freshness=missing deadline=1970-01-01 00:00:00 +0000 UTC preview=0
=== RUN   TestComplianceHTTPPostgresControlFreshness/migration_seeded_only
    compliance_http_postgres_test.go:53: authoritative soc2_security-configuration control: {ID:soc2_security-configuration Freshness: FreshUntil:1970-01-01 00:00:00 +0000 UTC EvidenceIDs:[pid_6a000003-0000-4000-8000-000000000003]} want freshness=missing deadline=1970-01-01 00:00:00 +0000 UTC preview=1
=== NAME  TestComplianceHTTPPostgresControlFreshness
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=24 data=/tmp/TestComplianceHTTPPostgresControlFreshness2754848224/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceHTTPPostgresControlFreshness (6.17s)
    --- FAIL: TestComplianceHTTPPostgresControlFreshness/fresh_101st_source (0.18s)
    --- FAIL: TestComplianceHTTPPostgresControlFreshness/all_stale (0.14s)
    --- FAIL: TestComplianceHTTPPostgresControlFreshness/missing (0.12s)
    --- FAIL: TestComplianceHTTPPostgresControlFreshness/migration_seeded_only (0.12s)
=== RUN   TestComplianceHTTPPostgresGrantLifecycle
    compliance_http_postgres_test.go:170: audit commit failure consumed grant: <nil>
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=53 data=/tmp/TestComplianceHTTPPostgresGrantLifecycle717657630/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceHTTPPostgresGrantLifecycle (5.80s)
FAIL
```

## fix1pinred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task4-fix1-pin --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-worker-final.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestComplianceCompiledFingerprintPostgres$' -test.v -test.timeout 240s
```

Exit: 1

```text
=== RUN   TestComplianceCompiledFingerprintPostgres
    compliance_postgres_test.go:466: compiled compliance fingerprint differs: actual=30358a1ceacbb18f0283e42353a06c88834d78927814dd8c6a9552a3a1d77a6f
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=23 data=/tmp/TestComplianceCompiledFingerprintPostgres3649466383/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
--- FAIL: TestComplianceCompiledFingerprintPostgres (4.72s)
FAIL
```

## fix1legacyred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/vitest/vitest.mjs run apps/web/api/compliance-decoders.test.ts
```

Exit: 1

```text

 RUN  v4.1.11 /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

 ❯ apps/web/api/compliance-decoders.test.ts (6 tests | 1 failed) 11ms
     × decodes the disabled-service legacy response without inventing freshness 6ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  apps/web/api/compliance-decoders.test.ts > compliance current contracts > decodes the disabled-service legacy response without inventing freshness
APITransportError: API success response failed its operation schema
 ❯ requireAPIData apps/web/api/client.ts:49:55
     47|   if (result.data !== undefined) {
     48|     if (!decode) return result.data as T;
     49|     try { return decode(result.data); } catch { throw new APITransport…
       |                                                       ^
     50|   }
     51|   if (isProductError(result.error)) throw new APIProductError(result.r…
 ❯ apps/web/api/compliance-decoders.test.ts:19:10

⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯


 Test Files  1 failed (1)
      Tests  1 failed | 5 passed (6)
   Start at  18:06:46
   Duration  1.37s (transform 84ms, setup 302ms, import 68ms, tests 11ms, environment 877ms)

```

## fix1tscred

Working directory: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/typescript/bin/tsc --noEmit
```

Exit: 2

```text
app/features/sessions/SessionsComplianceView.test.tsx(13,3): error TS2322: Type '() => Promise<{ id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }[]>' is not assignable to type '() => Promise<readonly { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }[]>'.
  Type 'Promise<{ id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }[]>' is not assignable to type 'Promise<readonly { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }[]>'.
    Type '{ id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }[]' is not assignable to type 'readonly { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }[]'.
      Property 'freshness' is missing in type '{ id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }' but required in type '{ readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }'.
app/features/sessions/SessionsComplianceView.test.tsx(14,3): error TS2322: Type '() => Promise<{ control: { id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }; freshness: "fresh"; evidence: { id: string; asset_id: string; source: string; at: string; }[]; }[]>' is not assignable to type '() => Promise<readonly { readonly control: { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }; readonly evidence: readonly { ...; }[]; readonly freshness: "fresh" | ... ...'.
  Type 'Promise<{ control: { id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }; freshness: "fresh"; evidence: { id: string; asset_id: string; source: string; at: string; }[]; }[]>' is not assignable to type 'Promise<readonly { readonly control: { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }; readonly evidence: readonly { ...; }[]; readonly freshness: "fresh" | ... 1 more...'.
    Type '{ control: { id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }; freshness: "fresh"; evidence: { id: string; asset_id: string; source: string; at: string; }[]; }[]' is not assignable to type 'readonly { readonly control: { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }; readonly evidence: readonly { ...; }[]; readonly freshness: "fresh" | ... 1 more ... | "...'.
      Type '{ control: { id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }; freshness: "fresh"; evidence: { id: string; asset_id: string; source: string; at: string; }[]; }' is not assignable to type '{ readonly control: { readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }; readonly evidence: readonly { ...; }[]; readonly freshness: "fresh" | ... 1 more ... | "missing"; }'.
        Types of property 'control' are incompatible.
          Property 'freshness' is missing in type '{ id: string; framework: string; name: string; evidence_ids: string[]; fresh_until: string; }' but required in type '{ readonly evidence_ids: readonly string[]; readonly framework: string; readonly fresh_until: string; readonly freshness: "fresh" | "stale" | "missing"; readonly id: string; readonly name: string; }'.
```
