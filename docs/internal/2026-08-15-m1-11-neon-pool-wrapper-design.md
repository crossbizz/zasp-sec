# M1-11 Neon Pool Wrapper Design

## Decision

Add one dependency-free `services/platform/database` package that wraps a
narrow driver-owned pool interface. Keep pgx and Neon URL parsing in the
existing `proofs/neon-pooled` module, where the current reviewed endpoint,
TLS, environment, and live-provider boundaries already exist.

This is preferable to adding pgx to the platform module because product code
needs stable timeout, lifecycle, and telemetry semantics rather than pgx
types. Reusing the proof package directly is rejected because a `main` proof
module is not a production dependency boundary.

## Product interface

The product package owns these types:

- `Config` with a required query timeout and health timeout, each positive and
  no greater than 30 seconds.
- `Row`, the minimal `Scan(...any) error` result needed to finish a single-row
  query while its timeout context is alive.
- `Driver`, with `QueryRow`, `Ping`, `Stats`, and `Close` methods.
- `DriverStats`, the raw non-secret counters supplied by an adapter.
- `Stats`, the validated product view: wait count/duration, canceled waits,
  in-use, idle, constructing, total, maximum, and closed state.
- `Pool`, constructed with `New(driver, config)`, with `QueryRow`, `Health`,
  `Stats`, and idempotent `Close` methods.

`QueryRow` validates a bounded nonempty UTF-8 statement and at least one scan
destination, applies the configured total query timeout, and completes the
driver query and scan before canceling that context. It returns only fixed
product errors. SQL ownership remains with later scoped repository packages;
M1-11 does not add repositories or dynamic query construction.

`Health` uses an independent health timeout, pings the driver, then returns the
same validated snapshot as `Stats`. A snapshot fails closed if counters are
negative or violate `in_use + idle + constructing == total`, `total <= max`,
or duration/count invariants.

## Lifecycle and concurrency

The wrapper admits operations under a read lock. `Close` takes the exclusive
lock, preventing new work and waiting for admitted query/health/stat calls to
finish. It calls the driver exactly once, validates a final snapshot with zero
in-use, constructing, idle, and total connections, records the stable close
result, and makes later closes idempotent. Queries and health checks after close
return a fixed closed error.

Every driver call is panic-contained and mapped to a fixed product error. A
nil or typed-nil driver, invalid configuration, malformed row, malformed stats,
driver failure, timeout, cancellation, close panic, or nonzero final pool state
fails without exposing SQL, arguments, connection fields, provider text, or
panic values.

## pgx adapter and live proof

The existing `proofs/neon-pooled` module adds an adapter from its strictly
validated `pgxpool.Pool` to the product `database.Driver`. The adapter maps only
pgxpool counters into `DriverStats`; pgx configuration, credentials, URL, TLS,
and provider errors remain outside the product package.

The live mode uses the ignored `DATABASE_URL`, derives the reviewed pooler
endpoint, limits the pool to two connections, and starts ten bounded reads.
While contention exists it requires one snapshot with wait count greater than
zero and in-use greater than zero. After every reader finishes it requires
in-use zero; after wrapper close it requires total zero. Output is exactly:

`Neon pool wrapper passed: reads=10 waited=true in_use=true acquired=0 closed=true.`

No branch or schema mutation occurs. The retained M0-04 proof stays green, and
M1-10 migration behavior remains unchanged.

## Tests and completion

Hermetic tests cover valid and invalid configuration, nil/typed-nil drivers,
query timeout and caller cancellation, scan completion inside the deadline,
fixed errors, driver and row panics, exact argument forwarding, stats mapping
and invariants, observed wait/in-use counters, health timeout, close ordering,
concurrent close, idempotency, close panic, and post-close rejection.

The root commands are `npm run db:pool:test` and `npm run db:pool:run`. M1-11
may move to Complete only after focused stability, all Go and pinned repository
gates, the exact live proof, scans, independent zero-finding review, push, and
exact-SHA Runnable UI success. M1-12 remains Pending throughout.
