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
