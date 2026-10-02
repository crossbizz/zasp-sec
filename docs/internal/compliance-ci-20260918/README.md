# Compliance browser CI evidence

Root retained25 text artifacts from the plan workspace and verified each against
its original, allowing trailing newline normalization. The five changed source
files match their manifest AFTER identities. Independent spec/quality review
approved with no findings; see compliance-ci-review.md.

The actual assembled-backend browser run passed locally on macOS. Root inspected
the final PNG: signed-in Staging, SOC2 policy controls, version8 evidence and
visible export action. Controlled provider/database evidence is not live AWS or
hosted Ubuntu evidence. Release/advisory and final publication gates remain open.

The original bundle remains at
`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-18-compliance-production-plan/`.
Its25 copied text files retain their relative layout here. The report describes
original-bundle paths; the following large/binary originals were not duplicated:

- `compliance-ci-before-browser-identities.json` and
  `compliance-ci-after-identities.json`: byte-identical4513-entry source/build
  captures. Root computed shared SHA256
  `f4aa9ad1f7ae14c9d39d1ddfeb7d72fc7ed0bfcd7b537d2ac289ed610d59cbdb`.
- `compliance-ci-evidence/grouped-node-before-contract-update.log`: rejected
  diagnostic run, SHA256
  `16c03c8ad83fea9ac67ff0100ac93a99ead90be22303764c042cc26caab19905`.
  This is not passing evidence. Final passing group/focused logs are copied here.
- `compliance-ci-evidence/artifacts/compliance-final.png`: SHA256
  `73dd1a195568804ff3cbd1cb5e8db1471b5f58f92406f2d98d92e999799f5b23`.
  Also retained at `/tmp/zasp-compliance-browser-p5x89H/compliance-final.png`.

Do not remove the original evidence workspace before these references are
preserved by the publication workflow. No source staging or push is claimed.
