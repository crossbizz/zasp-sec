# Reviewed SBOM dependency-topology prerequisite

The original exact-source full verification failed after 755 seconds. Its release group passed 284 tests and failed one: the actual npm SBOM command reported 207 missing requirements; build was not reached. This failure remains recorded.

The same pinned Node 22.23.1/npm 10.9.8 command passed at the real project root and failed in the detached project whose entire node_modules directory was a shared symlink. Actual Arborist inspection found 208 offending upstream edges producing the same 207 unique missing-requirement strings. A private exact 0b clone with its own byte-identical actual dependency directory passed the command with 64 SPDX packages and the same package/license entries. No installation, package/lock/source change, optional-peer waiver, fake SBOM or weakened guard was needed.

The full physical copy and original shared bytes were verified across 102,084 files, 12,484 directories and 55 internal relative symlinks, including modes and executable bits, with no hardlinks or outside-resolved links. The unchanged original release-source test then passed in 174.752 seconds, including its actual SBOM, license, GoSPDX, Helm and full-history secret guards. Independent physical graph and final postguard reviews passed.

Retained originals are encoded verbatim using deterministic gzip. The original 23-member manifest is preserved unchanged. The 26 MB full raw closure map is omitted with its exact bytes/hash and private identity disclosed; its sealed golden snapshot and independently reviewed pre/postguard records remain authoritative. Complete plain originals plus the two reviews were actually scanned before encoding: default directory scan exit 0/findings 0, not an assumed or fabricated failure. That limited metadata scan does not clear compressed payloads, a current/future source commit, full verification, build, native execution or deployment.

The fresh full retry is separate and active elsewhere. This publication does not inspect or hash its changing caches, rewrite the original failed proof, or claim present/future immutability from older maps.
