# Download decoder batch progress

Status: component implementation, not accepted or production-available.

## 2026-09-19 malformed content and grouped verification

The previous communication-only turn was no progress. This continuation fixed
the reproduced whitespace panic and ran native grouped verification plus the
separate registered worker process test.

Root cause: the content validator checked raw length, then indexed the first
byte of a trimmed string. Two spaces passed the length check and panicked.
The retained `red-content-bounds.txt` records that failure. The fix uses a safe
prefix check on trimmed content. Invalid content returns false without panic.

Command, from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^(TestSecurityAgentExportDownload.*|TestCompliancePersisted.*)$' -count=1 -v
```

Observed exit0, package time2.161s, six top-level PASS, zero SKIP:

- TestCompliancePersistedAttributionAndHistoricalBytes
- TestCompliancePersistedEmptyFindingReferences
- TestSecurityAgentExportDownloadOriginalFormats
- TestSecurityAgentExportDownloadManifestBinding
- TestSecurityAgentExportDownloadFailsWithoutDisclosure
- TestSecurityAgentExportDownloadContentBounds

This is native race/component evidence. It doesn't prove registered download
grant permissions, mounted HTTP routes, final consume-before-response, browser
downloads, live storage or production availability. Boundary coverage and
independent review remain open. M7A-23 stays component-only.

## Expanded boundary checkpoint

Added regression coverage for cancellation during storage Get, grant-deadline
propagation, all seven source identity kinds, manual identity rules, invalid
selection versions/digests, duplicate selections, the100/101 selection boundary
and accepted JSON depth32. These characterize existing implementation behavior;
no new RED cycle is claimed for these test-only additions.

Ran the same cached native Go environment with:
`go test -race ./apiserver -run '^TestSecurityAgentExportDownload.*$' -count=1 -v`.
Exit0,2.078s, six top-level PASS, zero SKIP. The two new top-level tests are
TestSecurityAgentExportDownloadCancelledDuringRead and
TestSecurityAgentExportDownloadSelectionBounds. Existing four decoder tests
also passed. `git diff --check` exit0.

Independent read-only review dispatched to evidence_export_worker_review for
the decoder and registered process fixture. Frozen source SHA256 values:

```text
06d12f29987e08647a77599a8c05cc21693d9c7aa9b4155ad5298cba5a0f23db security_agent_export_download.go
198b30b12d98fd8309886bc0a61533acdd3612af3629dc451d482078b1ddcf3d security_agent_export_download_test.go
1391cf3e840afb082be5c8ef19a88bcfed6eb9a89c246b5f048a6f3b6c7370c9 security_agent_export_worker_process_postgres_test.go
```

All three are new files under services/platform/apiserver at unchanged HEAD
8733b16f8d939d38a8157dd2519e57fc6f630542. Review is pending; no acceptance,
microtask completion, main publication or production claim follows.

## Review correction checkpoint

Independent review found two P3 coverage gaps and no production-code defect;
see review.md. Corrected the reader's request expectation to stay independent
from its returned artifact. Wrong-version and foreign-reference cases now
require both integrity and unavailable errors. Added ordered two-record binding,
malformed package schema and format/package limit cases with recomputed hashes.
No production changes were needed in this follow-up.

Exact command from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^TestSecurityAgentExportDownload.*$' -count=1 -v
```

Exit0,3.262s, seven top-level PASS, zero SKIP. Full output is retained in
green-review-boundaries.txt. Test source SHA256 is now
81f967ccbbb24e287d16f8d3ccbb3b723dfd304bc87b3163d6a848031d19db86;
production decoder and process fixture hashes are unchanged. Scoped reviewer
follow-up is pending. Earlier evidence remains valid for unchanged components.

Runtime integration inspection confirmed ExecuteSecurityAgentRun and its
worker consumer accept only legacy effect receipts or empty needs_human budget
stops. Export SQL returns a separate scoped pending receipt and persists the
parent as verifying. The next integration must preserve that distinction with
typed export dispatch and a dedicated link-settlement lease. SQL ownership
remains with the database implementer; no runtime behavior changed here.
