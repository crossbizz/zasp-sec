# Upstream source-map dependency repair

GHSA-68fv-2mgg-jv7q affects source-map-js >=1.0.0,<1.2.2. Four existing lock locations now select the official patched 1.2.2 release with an exact override. Official registry metadata confirms its tarball/integrity, unchanged BSD-3-Clause license and node >=0.10.0, and no dependencies. Dependency graph locations remain unchanged.

Public issuer commit: `fcd4a52293434d962e04aa6428cb4e4c4afe5d28`.
Whole public lock SHA256: `0e8b7fa1332878386816dd73ba0118fb8dfc8a414b7912f90e95f2dda8bae51c`.
The exact published GitHub raw bytes were checked before rebinding the public query producer. Original request/byte/time/resource/ownership guards and withdrawn/reviewed/unreviewed/malware coverage remain unchanged.

Existing grouped UI/typecheck/build and official public advisory checks must pass before normal merge. No new per-edit tests were added. The repository ledger remains 728 distinct original IDs, 523 historical production-available, 144 component-only and 61 blocked/external; no row is promoted by this dependency change.

GHSA-vfj7-8cjw-p6xm affects braces <=3.0.3; the registry latest 3.0.3 has no patched release. Its production vinext→vite-plugin-commonjs→vite-plugin-dynamic-import→fast-glob→micromatch path remains a release blocker. This batch does not assert dependency clearance, image/Go/SBOM/license clearance, deployed integration or release acceptance.
