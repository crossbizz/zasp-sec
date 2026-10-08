# Raw sibling PostgreSQL interpreter prerequisite

The initdb prerequisite refused normally with only the fixed initdb-command-refused category before the native test build. The original nine cases were not reached. The owned image-loader PostgreSQL version check passes; that does not exercise initdb's direct sibling executable path.

This independently reviewed successor performs a five-second owned raw-image PostgreSQL --version command with the same 179-library child environment, and requires the exact full version after normal exit zero. It retains the separate explicit image-loader version check. Only fixed categories are published; no binary is changed or server started, and original initdb, integration assertions, resource/custody guards and cleanup remain mandatory. Host-interpreter compatibility is not native application acceptance or a sole-cause claim. Actual observations remain pending.
