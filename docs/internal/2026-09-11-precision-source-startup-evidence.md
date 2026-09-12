# Explicit precision source startup

The producer daemon previously always called the stream-v2 constructor despite
having an implemented precise stream/spool path. ZASP_LINEAGE_SOURCE_PROFILE now
accepts only empty, tetragon-local-stream-v2 or tetragon-local-stream-v3. Empty
retains v2. Production generation startup uses the configured profile through
the existing socket, boot, Kubernetes identity and immutable-spool checks.

TDD first caught an ignored unknown profile, then a configured v3 generation
still starting as v2. The owned gRPC→spool→consumer→retry test now loads daemon
configuration and uses the same startup helper as production. It checks the v3
manifest, exact nanoseconds and identical retry bytes. Explicit/default v2
generation tests and rejected whitespace/v1/unknown selections preserve old
behavior. Targeted races passed2.092s; independent review repeated them2.068s
with no findings. Full sensor-agent races passed126.787s.

Customer-edge rendering now accepts a closed sourceProfile option, defaults to
v2 and writes ZASP_LINEAGE_SOURCE_PROFILE only to the producer. Helm rejects
unsupported profiles. Tests caught the missing environment selection and an
accepted non-object options input. Release/session contracts passed46 tests in
9.590s before the final options-type check; final edge tests passed4/4 in0.394s.
Independent chart review found no issues and repeated4/4 tests in0.524s.

The consumer already selects its precise processor from the immutable v3
manifest. This does not relabel stored generations or bypass enrollment checks.
It does not prove Linux host-mount identity, a live Tetragon deployment, customer
node readiness, or control-plane acceptance after rollout. V3 source activation
must follow the completed consumer/intake gates. No live apply, push or task credit.
