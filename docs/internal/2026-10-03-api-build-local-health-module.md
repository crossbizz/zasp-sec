# API dependency stage includes its local health module

The API Dockerfile previously ran `go mod download` in `/src` without copying the health module required by platform's `replace ../health`. Materializing its actual dependency-stage COPY instructions reproduced a missing `../health/go.mod` failure with a read-only full module graph query.

The build now works in `/src/platform` and copies `services/health` to `/src/health` before resolving dependencies. Its pinned base images, compiler, build commands, runtime and security settings are unchanged.

The regression test materializes those actual COPY instructions in an owned temporary directory, uses the existing sanitized Go launcher, requires Go1.25.13 and resolves the full module graph with `-mod=readonly`. It verifies the copied health module and unchanged platform locks. Baseline RED and candidate GREEN were independently reviewed. Coordinator live checks passed both this regression and the existing container pin, non-root, health and secret-boundary contract.

This fixes the source recipe and dependency layout. An actual shipping image build, digest, runtime verification, final-image license/advisory checks and production deployment remain pending. No ledger acceptance is promoted.
