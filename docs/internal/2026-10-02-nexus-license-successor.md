# Exact Nexus release-license successor

The platform now selects `github.com/nexus-rpc/nexus-proto-annotations`
`v0.1.1-0.20260629224316-835bd8d49cb4`, whose exact checksum-verified archive
contains MIT terms. The old `v0.1.0` archive still has no license; historical
evidence about that release remains correct. No release policy was relaxed.

## Provenance and minimal change

The old tag is commit `e558d6edaf84e280dddfc87b5b8ce1662f66ac8b`.
The selected successor is commit `835bd8d49cb45c8efa22614164b90335f7e56918`,
dated `2026-06-29T22:43:16Z`. GitHub's comparison and the actual Go module ZIPs
both show that its only addition is the 21-line `LICENSE`. Every one of the
eight existing files is byte-identical, including the generated Go annotations
and `go.mod`. The manifest delta is one indirect version and two checksum entries.

| Identity | Old archive | Selected archive |
| --- | --- | --- |
| Go checksum | `h1:2fELd+9sqUtNu6Fg//pw8YFsxOvp8vZ8hfP0nHhNI80=` | `h1:wAa/+xHX86PvLA6srCRhGm5Mzqvla7wxCJs++3rVzb8=` |
| ZIP SHA256 | `45f1a64bce0a471698e72d577fd38edb997b44e10f1d99d0d11fb953d086ac69` | `8f433dbc3f675f7443554c5293524683016517b9b373fedbe495a88ce65ee6f1` |

Both `go.mod` checksums are `h1:n3UjF1bPCW8llR8tHvbxJ+27yPWrhpo8w/Yg1IOuY0Y=`.
The selected LICENSE SHA256 is
`06847bcc52e67fceae1691299bdd42dbfdff138c91e3ea89811a7aa2827988d6`.
It identifies Temporal Technologies Inc. and includes the MIT permission,
notice-retention, warranty and liability terms.

## Fresh verification and independent review

Linux Go `1.25.13`, `GOTOOLCHAIN=local`, normal Go module downloads and enabled
`sum.golang.org` verification were used. The allowed `goproxy.io` mirror
supplied exact modules when the default mirror redirected to a denied host.
No cache contents or license files were patched.

The unchanged `moduleLicense` detector and Go allowlist loop from
`deploy/production/release-gates.mjs` were evaluated against the actual selected
Go module directory. The original selection returned `NOASSERTION` and failed;
the successor returned `MIT` and passed. The detector SHA256 in both runs was
`eb0434212ff404a0c57c9fe9fca8b80aa3fca76901b7856b620fa34124d695a5`;
the unchanged policy-loop SHA256 was
`8ae91151932a4bd633564b27712f2f1750667b892b8394c5b9b199c21253d14e`.

`go mod verify`, compilation of the actual
`github.com/nexus-rpc/nexus-proto-annotations/go/nexusannotations/v1` package,
archive byte comparison and whitespace checks passed. Independent review
repeated module provenance, archive comparison and unchanged-policy acceptance
and approved only this dependency delta with no blocking findings.

This resolves the specific Nexus license refusal. Full release, dependency/image
advisory clearance, deployed acceptance and the original 728 requirements are
separate gates. No availability row, runtime authority or historical proof was
promoted by this repair.
