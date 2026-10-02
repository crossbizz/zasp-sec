# Reviewed secret-scan findings, October 2, 2026

The pinned gitleaks8.30.1 history scan retained 538 findings in a private redacted JSON report. A separate five-batch delta scan retained two further documentation matches. Independent review examined historical blobs and all 66 baseline paths, then adjudicated all 540 reported matches as noncredential data. This decision does not establish credential validity, native acceptance or production advisory acceptance.

The findings include artifact/source identity digests, Git object references, literal test credentials and idempotency fixtures, SQL version labels, canonical effect/lease digests, schema/prose tuples and proof-log identities. One initially unresolved documentation match was independently identified as a B-tree access-path description. The finalized classifier artifact retains its unresolved row; the independent decision supersedes its interpretation rather than rewriting that evidence. Current versus historical digest drift remains separate from native validation.

The reviewed findings collapse to 435 unique scanner fingerprints because multiple one-line artifact matches share a coordinate. The appended exceptions use only the exact scanner fingerprint format: commit, repository path, rule and starting line. Original exception bytes remain intact. No scanner rule, path blanket, pattern or content exclusion was added. Independent review verified exact set equality against both reports and approved the scope without findings.

Private evidence SHA256:

| Evidence | SHA256 |
| --- | --- |
| Original history report | `1d94645c2db11e8f778f2a96813e3f25db074e937ee9f81dcfca58e979516e76` |
| Five-batch delta report | `a7ce5bfe4d184f6a41eb654fc1351d589843dc4bd8ab20650d775f3191a1120a` |
| Final classifier before independent adjudication | `26f5cc2a489f7502f5aa215c9162494ef73ea58ba362d062c13b57b7a7ae6fb9` |
| Original ignore bytes | `5ecc6c3a2d7940de3f00e7da143c8d649eadb9a166a0ab4bc67f713ed77f799c` |
| Reviewed candidate ignore | `b5984e728c583cfcf583d0138d8339b9f54e470e1d8190de25813bc0b77112c3` |

Raw finding text and credentials are not published. Immutable reports and original ignore bytes are retained privately; repository history remains intact.

## Detection controls and current validation

An owned temporary Git repository used random synthetic canaries, never real service credentials. The unchanged scanner detected an unreviewed commit (exit1, one finding); after adding only that temporary exact fingerprint it returned exit0 with zero findings. A new commit at the same path was still detected (exit1, one finding), as was a copied new path (exit1, two findings). Temporary canary contents were neither printed nor retained in the repository.

The completed full-history rescan returned exit0 with zero findings:1416 commits,322.27MB,447.97s. JSON report SHA256 `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`. The scan started with the live-dispatch checkpoint; a subsequent explicit range through the source-copier and collation-fix commits also returned exit0/zero findings. The original receipt records the end-of-run HEAD observation; an additive scope receipt distinguishes it from scanner-start refs. This resolves the observed secret-scan failure for those exact inputs. Mandatory fresh Go/image advisory evidence and the production release guard remain separate and open. No original728 requirement row is promoted.

## Classification provenance

The preliminary summary at19:45:18UTC bound classifier SHA256
`db7f79a228a8005210d199a0ca2f04b7a6ea9b78cef797539a886e5c3c0ac250`.
Before freezing, the19:45:44UTC finalization added historical-source digest and
immutable-historical-blob provenance fields to four status-document rows. It
changed no categories, reasons, counts or unresolved interpretation. Removing
only those eight metadata fields in memory recovers the exact preliminary
hash. Preliminary bytes were not separately retained as an immutable artifact;
the earlier summary remains unchanged and binds that preliminary stage. The
final classifier digest in the table binds the frozen artifact used for review.
Raw scan reports and original ignore bytes remain unchanged.
