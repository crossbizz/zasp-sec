# Reviewed companion import closure

The consolidated reference builder previously included companion test bytes
without traversing their imports. The higher replay tests consequently omitted
the worker replay module and its descriptor from the emitted source pins and
snapshot. This source-only repair queues companions, fixed current-inventory
test roots and explicit extra module roots, then closes their import graph.

Production import parsing, computed-import refusal, regular-file topology,
containment and the authenticated historical data-bundle exception remain
unchanged. Four existing computed fixture harnesses require an exact path,
reviewed SHA256 and fixed complete local dependency roster. A test suffix
alone grants no exception, and modules reached through tests receive ordinary
production traversal. The affected test uses the running Node executable
instead of a laptop path.

## Fresh behavioral evidence

Node `22.23.1` on Linux reproduced nine targeted failures before implementation
and passed all nine after the repair. Isolated-copy tests verify replay and
descriptor bytes in emitted pins/manifests/snapshots, binding changed descriptor
behavior, missing/symlink dependency refusal, unknown computed companion and
production import refusal, exact-reviewed companion drift refusal and nested
imports from extra test roots.

The complete consolidated suite reports 14 passing tests and one known failure:
`checked-in packet and immutable snapshot match the closed deterministic build`.
Its diagnostic is `complete capture output differs
services/platform/migrations/ordered_current/consolidated-capture-contract.json`.
The portable executable selection exposes the documented stale packet instead
of failing at a nonexistent laptop Node path. No historical output was rewritten
to make this assertion pass.

Two independent in-memory builds produced identical packet, snapshot and
manifest bytes: seven packet members, 164 snapshot members and 157 source pins.
The manifest SHA256 is
`a0087046b6992479753a3e59ba196e735ab1a6f6608c387e79100e1bb1f81400`;
the emitted contract SHA256 is
`6f5a8cc081f159b9c4e130de5969af47f2b98ccde477b3e932a2b56db4d33870`.
These hashes bind this source candidate, not a published or accepted native
capture. `installable:false` remains unchanged.

Independent source/security review matched all four fixture SHA pins and their
dependency rosters, inspected grouped RED/GREEN evidence and approved only the
two emitter/test files with no blocking findings. Node syntax checks and
`git diff --check` passed.

This closes the specific companion import omission. Reviewed successor
publication, registration capture, full native379, portability, installed
worker acceptance and verified legacy retirement remain separate work. No
source pins, historical snapshots, generated references, production refusal
guards or task availability classifications were promoted.
