# Fresh original33 fixture evidence

This bundle preserves a fresh bounded original-registration reference from
source commit `02a974e2472c11fc7347e0cdf30c54fbe9ff293d`. It is not production,
A/B, native379 or installed-worker acceptance.

`manifest.json` binds the exact compressed bytes, execution log and independent
reviews. Gzip uses timestamp zero. Decompressing the reference and build envelope
reproduces their original reviewed SHA-256 identities. No historical archive or
immutable packet was overwritten.

The envelope records original cloud paths. It is evidence of that run, not a
portable executable recipe: binaries, full immutable source/tool/module trees
and owned build cache are not included. A future execution requires a new
source/build review with actual paths and hashes.

The packet scan's two provenance-hash false positives are explicitly recorded
in the publication review. The separate full-history source gate's538 untriaged
findings remain a release blocker; this bundle provides no waiver.


## Separate source-only A/B successors

The current A/B archives preserve every actual source and packet member with
separate manifests/reviews. They retain Darwin reference provenance and grant
no native or installed authority. Restore the approved A only into a new,
empty `.superpowers/sdd/2026-10-05-reviewed-current-A-successor-v1` directory
before using the fixed B CLI. Verify its archive SHA256 from
`current-A-manifest.json` first, admit only the 165 regular safe relative
members, reject preexisting/symlink/unlisted content, and verify all 164 members
against the exact snapshot manifest. Never extract over historical snapshots
or the development source tree. B tests restore their own verified private
fixtures and do not require an ignored repository seed.

The B CLI supports only `--write` and `--check` at its separately fixed
successor destination. It preflights conflicts and creates missing files
exclusively; it does not promise transactional publication after unrelated
I/O failures. Its manifest and byte checks reject incomplete output.
