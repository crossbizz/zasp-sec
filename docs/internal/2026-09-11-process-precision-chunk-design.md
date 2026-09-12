# Owned precise chunk checkpoint integration

This implements the remaining checkpoint portion of precision design step2.
Source daemon admission, server archive support and activation remain open.

Use the existing chunk persistence state machine for both record generations.
Duplicating its locking, directory ownership, cache rollback and progress checks
would create two security-sensitive implementations to keep in sync. Widening
the old record decoder would let old frozen consumers accept a new meaning.
Instead parameterize the private chunk state machine by record type and supply
an immutable private contract from each public constructor.

Keep `ChunkProcessor`, `chunkCheckpoint` and `pendingChunk` as aliases for the
legacy record instantiation. Their serialized fields/order and V1 constants stay
unchanged. Keep the private `normalizer *Normalizer` for cache ownership and
existing tests. New `PreciseChunkProcessor` aliases the precise instantiation.
`NewPreciseChunkProcessor(ChunkProcessorConfig)` accepts only the owned V3 source
profile, with the same root/slot/disjointness checks as the old constructor.
It uses the precise normalizer's private cache owner and precise Normalize.

The private record contract selects checkpoint version, target mode, envelope
schema/version, digest, preparation/replay, canonical body decoding, event size
and source observation extraction. V2 checkpoints use
`tetragon-chunk-checkpoint-v2`; target mode is `sensor-ingest-envelope-v2`.
Source binding includes the unchanged original V3 source object and root inode.
Retain the existing progress chain algorithm, whose initial value already binds
the source profile/generation; there is no chain adoption across generations.

Pending envelope storage shares only the credential-free field layout through
RuntimeEnvelope internally. Each contract checks the exact version and schema
before conversion to its public envelope type; old constructors never obtain
the precise contract. Precise pending records must validate the full record and
source cluster/node/boot, with their nanosecond start retained in cache. Expiry
doesn't make a saved checkpoint invalid; replay returns ErrEnvelopeExpired and
keeps it. Preparation failure persists normalized events for the next retry.

Acceptance requires actual files/locks and constructor-driven normalization:
uncertain upload, close/reopen, byte-identical retry under changed credentials,
then a partial file event whose identity comes from restored process cache.
V1 rejects a V2 checkpoint at the same cursor and V2 rejects V1. A source boot
change rejects replay before credentials or chunk reads. Failed checkpoint writes
must prevent upload. Existing V1 package suites must still pass unchanged.

No original task credit follows from fake HTTP acceptance. The daemon must still
admit and assign an actual V3 producer and server persistence must support V2.
