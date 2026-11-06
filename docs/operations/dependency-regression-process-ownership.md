# Dependency regression process ownership

Run `npm run dependencies:check` to validate the dependency inventory and execute the original nine Node regressions. The command requires Python 3 in addition to the pinned Node/npm runtime.

On Linux, a fresh launcher becomes a child subreaper and reaps its adopted descendants while the Node tests run. The existing tests still require their real process groups to disappear. The launcher does not alter their assertions, timeouts or fixtures, and it preserves Node output and failure status.

Linux requires pidfds, subreaper support and readable process identity metadata. When the optional kernel child-list file is absent, bounded numeric `/proc` metadata reads discover current children. Permission denial does not enable that fallback. Before signaling, each target must still match the launcher's current child relationship, UID, start identity and pinned pidfd. Cleanup must join all owned children; incomplete ownership or cleanup returns an error.

The launcher never signals historical PID1 zombies or unrelated processes. It does not repair the host's process reaper or provide isolation against a privileged or hostile host. Its public command runs only the two fixed dependency test files. The private command seam exists for the three grouped lifecycle checks.

On macOS the launcher executes the original Node command directly. Other platforms return an explicit unsupported error. Linux capability refusal fails before test execution rather than reporting a passing check.

The independent CI job runs the three Python groups and all nine original Node checks with complete source custody verified before and after. These checks establish dependency and process-lifecycle behavior; full platform and deployed acceptance remain separate requirements.
