# Mounted browser12 artifacts

Copied byte-for-byte from the owned browser12 evidence directory after the full
run exited0 and joined its processes. Every record is local controlled-provider
evidence, not live EKS/Fargate or hostile-code acceptance.

| Run | Result | JSON SHA256 | PNG SHA256 |
| --- | --- | --- | --- |
| pid_85f400d1-12ca-4862-9a43-ccdee7daa1aa | Supervised, verified, Needs human, cleanup complete | 720fbe7c89ad7c38ef274b48d799dd4d0dc0360c020942d8a6ed9e064ed6d772 | f8b07a7ea5bca7bebacc56255580897dd0e068ec7ee101d5ba053fea10cfc88d |
| pid_883e05d4-3f5a-4b3b-8516-3acf20891373 | Autonomous, not_reproduced, Needs human, cleanup complete | 796e63f54e0d91d45653b068176c525fbe6427bab1a487ace7f100ee3fc5dcd4 | bfd71d56d2189ec60c098419df24d6ea4026d251f4279baff8e0763daa8eecb6 |
| pid_11c52ab9-8cbd-4114-92aa-ea61809bcbfa | Public parent cancellation, cleanup retained then confirmed | abc3baa396c1418baf61d520e9b5ff16496f4394ce71b29eb7fc9dbe8ad1a6cf | 47ed695292f7b0e0e18cf393fb8678e8579c5cd3ad1b9e47a99e89d72360f6b2 |
| pid_82b23093-3c32-48f0-9b02-afd3967eabfb | Missing source, persisted Needs human reason, no execution | ef764b1dd93be803399df743ac38d918693709abc918c6f99159046019d37195 | 953d47046aee7263e6cf7688286f227e52867b9db41ebb2147b57938eba256e8 |

Both positive modes and the stopped case retain one provider call/Job POST
across process restart and lost acknowledgement; settlement retry count is2.
The browser asserts exact source/version/attempt, safe approval context,
evidence/settlement digests, reload persistence and no Remediated claim.

All four PNGs were visually inspected. The three execution outcome views are
stable and legible. The missing-source PNG caught a drawer transition and has
overlapping background content. Its actual JSON, bounded DOM text assertion and
reload/zero-effect checks pass; that PNG is not visual polish proof.
