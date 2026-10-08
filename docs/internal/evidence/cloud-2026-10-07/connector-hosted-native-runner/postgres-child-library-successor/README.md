# PostgreSQL child-library prerequisite successor

Both hosted runs 37723757136 and 37723753346 on 38481e10a5895f4bd19d433088f04d9fbc270f37 failed the original top-level test after only the postgres-start fixture stage. Neither reached database connection, canonical migrations or any of the nine subcases. The command exited normally with status 1, no timeout, signal, output cap or malformed JSON. Safe original annotations are retained here. This narrows the refusal to PostgreSQL startup; it does not establish the precise inner error or a capture SQL failure.

The successor restores the child-process library environment of the retained working PostgreSQL wrappers. It consumes only 179 unique safe library names from the exact pinned public manifest, verifies each current owned-image target is a contained regular file, and exports owned non-glibc aliases for nested sibling execution. Historical absolute paths are not consumed. Direct execution still uses the same pinned image, explicit image loader, full image library path, Debian layout and exact version. Original nine subcases, assertions, resource floors, deadlines, custody and cleanup remain unchanged.

Independent review passed for source only. Hosted original integration acceptance and normal process cleanup remain required; this is not deployment or ledger completion evidence.
