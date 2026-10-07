# Launch configuration check evidence

The initial Go RED is a missing-command compilation refusal. The initial Node RED has nine passes and two failures for the absent checker/entrypoint. The complete API race run passes 409 named cases, with ten existing opt-in prerequisite skips and no failures. Eleven launcher tests pass. The actual built binary refuses this cloud configuration with exit1 and a fixed message; no dependency builder was invoked. Vet passes separately. These are syntax/launcher component checks, not provider, native admission or deployed acceptance.

An initial test command used repository-relative copy paths from the platform directory and failed to install the tests; its Go invocation matched no tests. That attempt is not RED evidence. Its original log remains private. The corrected missing-command RED and subsequent complete run are retained above.

The final green adds an actual subprocess entry check. The same test fails against the exact predecessor main body (private Go overlay), proving the dispatch is necessary to return before production construction. The original initial green remains retained separately.

The original T15-deployment IDs in `task-dependency-links.tsv` share this configuration prerequisite. These links identify the batch dependency, not per-row implementation or task completion.
