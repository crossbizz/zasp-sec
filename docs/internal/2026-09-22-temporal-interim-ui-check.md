# Interim frontend build, not product acceptance

Controller checked the retained frontend while P3A changed Go/SQL. No frontend source edits were made by this check. Current branch remains the dirty retained replacement worktree; these commands do not approve a push of all outgoing commits.

The first local build/typecheck/compiled-import pass used host Node26.8.2 and produced a module.register deprecation warning. It passed, but did not match CI. The controller found the pinned runtime at `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/` and repeated the checks with that directory first in the command-local PATH. No host default was changed.

Pinned runtime outputs: `node --version` = `v22.23.1`; `npm --version` = `10.9.8`.

| Command under pinned Node/npm | Result |
| --- | --- |
| `npm run build` | Exit0; all five vinext build stages passed; standalone output generated in dist/standalone |
| `npm run typecheck` | Exit0; no TypeScript diagnostics |
| `npm run production:imports:compiled` | Exit0; client_chunks=7, server_chunks=8 |
| `node --test deploy/production/compliance-export-toolchain.test.mjs` | Exit0;3 tests passed,0 failed,0 skipped;40.034ms |

Build output paths remain ignored; `git status --short tsconfig.tsbuildinfo dist .wrangler` returned no tracked changes. Existing user-owned frontend edits were preserved.

This proves only the interim build/typecheck/import boundary and launcher behavior. It is not a browser-flow test, actual provider/API execution, authenticated multi-tenant acceptance, deployed proof or final release-candidate verification. P3B/P3C, FGA and the original product gates remain required. Rerun affected frontend acceptance when those interfaces change and final candidate verification before pushing.
