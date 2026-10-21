# Official advisory Git roster: offline capacity component

This continues step 1a of the existing immutable advisory intake work. It measures
the selected Git topology and declared capacity before acquiring advisory blobs.
It does not replace `collectPinnedNpmAdvisoryComponent`, create a public intake
receipt, or change production release admission. `releaseAccepted` is always
`false`.

The earlier 112102 mixed tree rows included directories and could not establish
that the original 100000-file limit was exceeded. The component now accepts
bounded local captures, verifies Git object hashes, and distinguishes regular
files, JSON candidates, directories, and declared byte totals. It has no network,
credential, Git subprocess, package-classification, or deployment functionality.

## Run against retained captures

```sh
python3 -B scripts/npm-public-api-query/git_tree_roster_component.py \
  --capture-manifest /absolute/captures.json \
  --output /absolute/new-roster.json
```

The closed capture manifest has this shape. Values below are placeholders, not
an observed official snapshot:

```json
{
  "format": "official-advisory-git-tree-captures-v1",
  "repository": "https://github.com/github/advisory-database",
  "expectedCommit": "<40 lowercase hexadecimal characters>",
  "rawCommit": {
    "path": "/absolute/raw-commit-payload",
    "sha256": "<64 lowercase hexadecimal characters>"
  },
  "captures": [
    {
      "requestPath": "/repos/github/advisory-database/git/trees/<tree-object-id>",
      "path": "/absolute/original-tree-response.json",
      "sha256": "<64 lowercase hexadecimal characters>"
    }
  ]
}
```

`rawCommit` must contain the exact raw Git commit payload. The component hashes
`commit <byte-length>\0<payload>` and extracts its original tree header. A GitHub
commit JSON response cannot be reconstructed into this payload. Expected IDs,
repository strings, paths, and supplied hashes bind the selected bytes; they do
not authenticate upstream provenance, commit signatures, history, or freshness.

Tree request paths permit only the fixed repository, an exact SHA1 object ID,
and optionally `?recursive=1`. The supported response contract is the Git Trees
API object with exactly `sha`, `url`, `tree`, and `truncated`. Entries contain
`path`, `mode`, `type`, `sha`, and `url`; only blobs also contain `size`.
`truncated` must be the boolean `false`. This shape has synthetic protocol
controls; compatibility with a retained real complete response has not yet
been verified. The previous saved observation contains hashes/category names,
not the raw commit and complete response bodies needed for a real run.

Use complete recursive subtree captures, complete direct traversal, or a
combination that closes every selected frontier. A failed truncated capture is
not an input to a successful transcript: preserve that failure separately.
Identical subtree objects may occur at distinct reachable paths. Consistent
recursive/direct overlap is permitted when each captured root is itself
reachable and the object rows agree. Duplicate capture roots, conflicting
observations (including different declared sizes for one blob ID), missing trees, unreachable captures,
unsafe paths, and unknown advisory categories refuse. The root must bind the
exact `advisories/github-reviewed` and `advisories/unreviewed` trees. Regular
mode `100644` is required inside those trees; symlinks, executables, and gitlinks
there refuse. Other repository content participates in ancestor tree hashes
without becoming a claim of full repository closure.

Each tree hash uses canonical Git byte ordering and binary tree encoding,
including directory mode `40000`, basename bytes, and raw object IDs. JSON
member order and locale sorting cannot establish a Git tree hash. Recursive
responses must include complete child relationships, including empty trees.

## Capacity and evidence boundaries

The component retains the existing strict JSON decoder and original API limits:
20 MiB per response, 128 MiB aggregate response bodies, 256 captures, and 300000
API members. It separately caps expanded reachable traversal work at 300000,
including reused subtree visits. Raw commits and the capture manifest are each
limited to 1 MiB; paths to 4096 UTF-8 bytes; depth to 64; result evidence to
32 MiB. Metadata cap refusal is not proof that the original corpus file cap was
exceeded.

JSON candidates are regular paths ending in `.json`, not parsed or verified
advisories. The output reports both candidate and all-regular-file counts.
It compares declared metadata with the unchanged producer limits: 100000 full
files, 1 GiB full bytes, and 1 MiB per blob. The 512 MiB npm limit cannot be
evaluated without reading and classifying record contents.

**Git trees do not authenticate blob sizes.** Changing an API `size` leaves its
Git tree hash unchanged. The roster's SHA256 binds that observed size metadata,
but capacity results remain explicitly declared-only. They do not prove actual
blob lengths, compressed/object/checkout peaks, available disk, or admission to
the existing producer.

Local input files must be absolute, regular, owned by the executing user, and
have one link; symlink paths refuse. Input metadata and hashes are checked before
and after execution. The output parent directory is opened and pinned before
input verification. Creation, inspection, cleanup, and fsync use that retained
directory descriptor; the selected parent and ancestor identities and canonical
path are revalidated before and after publication. Parent replacement refuses
and cleanup removes only this invocation's output inode from the retained
directory. Output is bounded and create-only with mode `0600`; an existing
output is preserved. Successful stdout contains only the output hash,
size, and `releaseAccepted:false`. Refusals use a fixed diagnostic and nonzero
exit. No caller-supplied field can enable verification or clearance flags.

## Verification and remaining work

Run the four grouped synthetic controls explicitly:

```sh
python3 -B scripts/npm-public-api-query/git_tree_roster_component_test.py -v
```

They exercise direct/recursive closure, reused subtree accounting, canonical
ordering and empty trees, declared-size nonproof, hash/authority/parser/bounds
refusals, unknown categories, unreachable captures, and the actual local CLI's
create-only and source-file boundaries. They do not test GitHub internals or
constitute a real corpus measurement. The filename deliberately stays outside
the existing `*controls.py` discovery; the original sixteen-test hosted census
and source manifest remain unchanged.

A future separately reviewed actual intake owner must retain exact source/tool
pins, authenticated fixed-origin transport, current proxy/network policy,
request/resource/deadline bounds, cancellation, and normal process joins. It
can use this component before blob acquisition. It still must obtain an
authentic raw commit, fetch and verify every selected blob and actual length,
classify records, establish full local committed nonpromisor closure, and bind
independently admitted upstream provenance before the original producer runs.
No partial fetch or reconstructed commit is an acceptable shortcut.

The current missing raw inputs and resource/transport authority remain open.
Full npm source/bundle coverage, the seven Go MVS roots and standard library,
rendered image/platform scans, severity handling, provider evidence, and final
release admission remain separate required work. This metadata component makes
none of them production-available.
