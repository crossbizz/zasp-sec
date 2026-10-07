Concurrent production readiness probes

A faithful unchanged local browser run reproduced authorization-readiness refusal after both owned Temporal/OpenFGA services and current schema setup. A separate private timing overlay kept the original fixed queries, checksums and shared five-second timeout: core passed in3332ms; the agent refused at1668ms with the context deadline exhausted. It is diagnostic evidence, not unchanged browser acceptance. The actual API timeout is five seconds; a different worker fixture uses one second.

Both existing per-principal bootstrap metadata probes now run concurrently in one parent-bound budget. Both must pass; either error cancels the sibling, and both are joined before return or pool closure. Final context cancellation refuses readiness. The agent may now read its own fixed metadata when core refuses; tenant/product reads and writes are not added. Services still precede these probes and the prior readiness callback runs only after both succeed. SQL, checksums, identity, permissions and timeout are unchanged.

A real barrier regression failed against the old sequential gate (one query entered). The corrected complete API race suite exited normally: {'pass': 386, 'fail': 0, 'skip': 10} named outcomes / {'pass': 127, 'fail': 0, 'skip': 10} top-level outcomes. Existing prerequisite-gated SKIPs are not verified. The first join-test draft omitted its handshake close and failed; its actual result is explicitly transcribed and preserved. Independent review and exact browser acceptance remain separate requirements.

Local failures are kept separately: original120s worker compilation timeout, original same-device allocation refusal, faithful startup failure, and separate timing-overlay failure. Priming compilation and copying exact verified tool bytes onto the state filesystem altered neither browser limits nor runtime guards. All four runs observed unchanged tracked source bodies for their own lifetime. Selected bindings reference private complete body maps; no formal native lifetime custody is claimed.

No ledger promotion, native admission, real deployed Stytch/provider success or launch readiness is claimed.
