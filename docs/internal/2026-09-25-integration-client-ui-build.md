# Integration client UI build checkpoint

Controller verification on the retained dirty worktree, HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. This supplements the frozen integration packet; it does not modify its manifest or constitute review approval, browser acceptance or deployment proof.

Commands used command-local PATH beginning with `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin`. The existing runtime reports Node `v22.23.1` and npm `10.9.8`. No dependencies were installed or changed.

| Check | Observed result |
| --- | --- |
| `npm run typecheck` | Exit0, `tsc --noEmit`, no diagnostics. |
| `npm run build` | Exit0, all five vinext stages passed; standalone output generated in `dist/standalone`. |
| `npm run production:imports:compiled` | Exit0, compiled graph passed with7 client and8 server chunks. |
| `node node_modules/eslint/bin/eslint.js apps/web/api/decoders.ts apps/web/api/decoders.integration-signing-version.test.ts` | Exit0, no output; scoped changed-UI lint in session5076 under the same pinned Node. |

Typecheck/build ran sequentially in session3430, which joined with exit0. Build stages reported223 client-reference modules,168 server-reference modules,221 RSC modules,2039 client modules and174 SSR modules. No warnings were emitted in these command outputs.

Afterward, controller rehashed all15 live source entries in the integration packet manifest `06b5122ad49b469bfcf053a6c94befdb59c163d4533a22d26dbb86c78fe220d1`; all matched. `git status --short -- dist tsconfig.tsbuildinfo .wrangler` reported no tracked changes. Existing unrelated dirty work was preserved.

Independent integration SPEC/QUALITY review remains pending. Full configured startup, authenticated browser flows, real Stytch/provider interactions, native writer isolation, worker admission and required release/CI gates remain open. This checkpoint alone does not authorize a push of the entire dirty tree or establish production readiness.
