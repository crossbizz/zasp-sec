# M1-08 External Client Policy Design

## Decision

Add one dependency-free `services/platform/externalclient` package that wraps
an HTTP operation with a total deadline, bounded concurrency, transient-only
retry classification, and exponential backoff with jitter. The helper owns no
provider client, endpoint, credential, request construction, response schema,
logging, or product error mapping.

## Policy

`Policy` is an opaque comparable value created with explicit:

- total request timeout;
- maximum retry-safe attempts;
- base and maximum backoff;
- maximum concurrent operations.

The constructor rejects zero, negative, internally inconsistent, or excessive
values. The supported bounds are intentionally small: timeout up to two
minutes, at most five attempts, backoff up to thirty seconds, and concurrency
up to 1,024. Invalid direct state fails validation.

## Request safety classes

Each execution declares exactly one request kind:

- `ReadOnly` may retry transient outcomes;
- `IdempotentMutation` may retry transient outcomes because the caller owns the
  idempotency contract;
- `NonIdempotentMutation` receives exactly one attempt regardless of outcome.

This package never guesses idempotency from an HTTP method. It cannot authorize
a destructive retry or reconcile an ambiguous mutation; callers must select
the safe class and later M1-09 supplies the shared idempotency helper.

## Deadline and concurrency

The executor derives one total context deadline before waiting for a concurrency
slot. Slot wait, every attempt, and all backoff consume the same budget. A
caller deadline that expires sooner wins. The operation receives only the
derived context. Cancellation or deadline exhaustion stops immediately and is
never retried.

One semaphore slot is held across the whole attempt sequence so a retry storm
cannot exceed the configured operation concurrency. Slot acquisition and
release are cancellation-safe, including operation panic unwinding.

## Retry classification

Retry-safe request kinds retry only:

- bounded transport failures identified as temporary/timeout network errors,
  connection reset/refused, EOF, or unexpected EOF, excluding caller context
  cancellation/deadline errors; and
- HTTP 408, 425, 429, 500, 502, 503, or 504.

All other errors and statuses return immediately. Intermediate retry responses
are closed after a small bounded drain; the final response remains caller-owned.
A nil response with nil error is invalid and never retried.

Backoff doubles from the base to the configured cap and applies bounded full
jitter. Waiting is context-aware. The package exposes no global mutable policy,
background goroutine, queue, metric, or retry after the call returns.

## Scope and safety

- Fixed package errors contain no URL, request, response, credential, or
  provider text.
- The executor does not log, inspect bodies, follow redirects, construct HTTP
  clients, or weaken TLS/proxy rules.
- Provider-specific status semantics and `Retry-After` handling remain client
  responsibilities unless a later reviewed extension is required.
- M1-09 remains Pending until M1-08 completes and exact-SHA CI passes.
