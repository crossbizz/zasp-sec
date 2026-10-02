# Cloud checkpoint content-security review

This is a WIP source/evidence preservation gate, NOT a production merge,
requirement acceptance, deployed-provider proof or completed cloud transfer.
The full 728-task goal remains active and unchanged.

## Bound source and scanner evidence

Preservation commit: `1079ff4750f20f0065cfd4f57c76cc5e2e147f14`.
Reviewed tree: `d19fd666b65d7cb736a6de0524e86c7a70503092`.
Original worktree HEAD: `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`.
The alternate-index checkpoint preserved the original branch, dirty source and
empty real index. Original and candidate content hashes matched all77,093
captured entries with zero mismatches. Six rebuildable native test binaries
remain local and are excluded. Following commits change handoff metadata only;
the final Git commit binds the complete updated capture manifest.

Gitleaks8.30.1 scanned the candidate with redaction100, ignored no inline
allow-comments or repository fingerprint file, and used its default rules.
The exact-source run covered2.55GB:3847 flags, exit1. New-history73commits:8
flags, exit1. Metadata-only update:23.28MB, one English-text flag, exit1.
Do not report any of these scanner runs as a clean pass.

Private local report identities (reports are NOT uploaded):

- Exact-source report SHA256: `96ad90a1e1adeb1d86470fb757a18c1787e9a8ef88d60e0c783db446a276341c`.
- New-history report SHA256: `b87cee9df959f6f73795317809ac51061c31aecbce5e1176269d2c556349affe`.
- Metadata report SHA256: `72fd22c545ba2e5c6e05e0ea2583b6558480ed92e69aabf25755790369c2cf13`.

The later metadata-only candidate tree
`5fbd24310ce8d779ec6ee3ac995651f45908ce3b` produced8 classified flags: one
English external-prerequisites phrase and seven Git commit/tree/source-head
identifiers. Report SHA256:
`8db8b92b09978a2fcaa97355a9e15b208cb35056cca4c158d52e4fe92091fcbb`.
Root verified the Git identifiers against the repository or the clean official
Superpowers checkout; the independent reviewer confirmed these classifications.
Scanner exit remained1, not a clean scanner pass.

This correction changes transport metadata only. The corrected transport tree
will be scanned again before capture. Its final metadata scan identity, exit,
finding classifications and exact tree are recorded in the capture commit
message, outside that commit's scanned tree, to avoid a recursive report-hash
rewrite. Read that message alongside this document and the final manifest;
neither historical report is silently relabeled as the final transport scan.

Root bound all3847 reported findings to1329 captured paths,183 distinct full
file contents,977 distinct content/rule/location/match identities, with zero
unbound paths. Repeated archive copies were compared by full content identity;
the review classified credential-risk clusters, not repeated copies as separate
code reviews. Scanner limitations remain; this is not a guarantee that no
future scanner or security review can identify another issue.

## Independent read-only review

Superpowers requesting-code-review/verification-before-completion were used.
Reviewer `/root/precision_batch_repair` made no edits, index/ref changes, network
or provider requests, PostgreSQL launches, or application changes.

Reviewed classifications:

- 176 AWS detections are six distinct copies of a synthetic test fixture. Root
  independently confirmed the fake identifier and repeated-character secret/
  session inputs without printing their values.
- One Sourcegraph-rule match is an existing Git commit identifier, not a token.
- Five source identity maps contain4720 entries each, exclusively SHA256 hex;
  their94 flagged entries each are metadata, not provider/API credentials.
- Release publication logs contain source-hash maps (76 flags in a2703-entry
  object); archived duplicates have identical bytes. Run metadata contains
  path-to-hash values; its commands have no credential-named environment values.
- Typed missing-reference captures flag identity-argument vectors, not secrets.
  Baseline/snapshot/summary values are source hashes, test evidence and digests.
- Go flags occur only in test files. TS/MJS flags resolve to deterministic local
  E2E, hermetic Nango/loopback LocalStack, hostile OTel redaction inputs, or test
  idempotency/effect/correlation/lease identifiers. No production Go credential
  was identified. New-history8 flags belong to the same static test families.
- Remaining prose and module-checksum flags are documentation or integrity
  evidence. The metadata-only flag is plain English describing external gates.

No environment file, SSH/private key/certificate bundle or credential-bearing
npm configuration was captured. The npm configuration only sets install
strategy. Existing scanner fingerprint exceptions are exact, with no wildcard
or broad rule; no exceptions were added to suppress this review's findings.
Do not reuse synthetic test keys outside their test-only scopes.

## Historical Stytch caveat resolved without authentication

The old fixed magic-link literal exactly matches Stytch's published sandbox
test value. Official documentation limits sandbox values to the Test API,
requires valid API credentials, and says they do not work with frontend/mobile
SDKs. [Stytch sandbox values](https://stytch.com/docs/api-reference/b2b/api/resources/sandbox-values).

Root compared the old proof module line4 and test line100 internally against
the exact published value; its digest is
`bd59e6e5baba26b79b18f0451dd967f053a06c800bd9587b007293a66c5cad6b`.
No literal is reproduced here and no Stytch authentication request was made.
Its introduction commit `b89460deb3a2eb95c8a02cd31183b9f075465cf0` is already an
ancestor of public `origin/main`. Both current proof files byte-match main and
do not contain that old literal. The reviewer accepted this evidence, resolving
the initial offline uncertainty without approving real-provider acceptance.

## Public origin and remaining gates

GitHub repository API reports `crossbizz/zasp-sec` is PUBLIC, with local actor
push access. No repository visibility or authentication configuration changed.
The reviewer explicitly reassessed PUBLIC upload and found no actual secret or
remaining credential-like uncertainty requiring exclusion. Content gate: clear
for the specifically authorized dedicated handoff branch, NOT main.

Before upload, verify the final tree, its updated manifest and metadata-only
scan. Keep the full redacted reports outside Git. Preserve local originals.
The receiving cloud environment ID/workspace remains unverified; CLI task list
is empty. No cloud task has started or accepted checkpoint ownership. Follow
the cloud receipt gate in `cloud-handoff-2026-10-01.md` before telling the user
they may stop local execution. Original product/runtime/production gates remain.
