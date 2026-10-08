# Sealed Atlas reuse: resource refusal

This offline source derivation attempt reused the retained f84 source Atlas and applied the independently verified bounded executable bootstrap from 54feb7e0. It did not recopy the 159 MB Atlas and did not transfer source authority between those commits.

The outer owner joined normally with exit 1 after 15.044 seconds. At 14.598 seconds, memory headroom was 225,869,824 bytes, below the unchanged 268,435,456-byte floor. Workspace and temporary storage floors passed. The owner requested TERM for its owned Node session; Node joined with return code -15. The derivation did not complete, wrote zero outputs and issued no native anchors. Input maps remained equal, all retained Atlas entries remained unchanged, and the final owned-session census was empty.

The observed memory deficit was 42,565,632 bytes at that sample. This is a lower bound, not a capacity estimate for completion; the later peak is unknown. Original failed evidence is preserved. No resource floors, scope, validation or release guards were reduced. This failure does not invalidate the grouped bootstrap check and does not prove native or production availability. The 728-row ledger is unchanged.
