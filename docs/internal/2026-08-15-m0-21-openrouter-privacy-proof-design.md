# M0-21 OpenRouter privacy proof design

Date: August 15, 2026

## Decision

Prove the explanation-only OpenRouter boundary with a standard-library Node
lifecycle and one synthetic OpenRouter-compatible server bound to a random
numeric loopback port. The proof accepts no OpenRouter credential, hosted
endpoint, SDK, `.env`, proxy, profile, model configuration, or ambient network
authority. A fixed synthetic bearer value exists only inside the local fixture.

M0-21 does not implement or claim the Security Agent action-catalog planner.
M0-21a owns that separate boundary, so R-14 remains Not run after M0-21 even
when this explanation/privacy proof succeeds.

## Product boundary

The gateway accepts one exact bounded finding-explanation input. Product code
constructs a closed request from allowlisted identifiers and metadata, redacts
seeded secret and PII substrings from the bounded explanation summary, and
checks the resulting request for residual prohibited material before I/O. It
rejects unknown keys, hostile objects, invalid identifiers, invalid metadata,
over-limit input, unsupported purpose/model/provider, and every non-loopback
destination before opening a socket.

The fake endpoint accepts exactly one `POST /api/v1/chat/completions` request
with exact raw headers and a strict, duplicate-free, bounded JSON body. It
returns one fixed OpenRouter-compatible completion whose assistant content is
a strict JSON document. The product validator permits only a closed structured
result schema: schema version, finding ID, explanation, and recommendation.
Aliases, duplicate keys, unknown fields, wrong types, invalid UTF-8, trailing
data, model/identity drift, multiple choices, tool calls, URLs, shell content,
and prose outside that document fail closed.

## Privacy and output

The successful endpoint capture must not contain any seeded secret, email,
phone number, person name, raw-evidence value, or their JSON-escaped aliases.
It may contain only the fixed redaction token plus allowlisted synthetic
finding metadata. Request and response bytes are retained only inside the
proof process and never emitted.

Success is exactly:

`OpenRouter privacy proof passed: explanation=true secret=false pii=false structured=true cleanup=true.`

Failures are one fixed category line. No prompt, summary, PII, secret, raw
request/response, endpoint, port, header, model output, stack trace, or provider
message reaches stdout or stderr.

## Lifecycle

The main phase has one absolute deadline and passes its AbortSignal through
request handling. The request has a shorter hard deadline plus combined body
bounds. Cleanup uses an independent deadline, stops accepting connections,
drains sockets, and proves the retained fake server is closed. Cleanup failure
wins precedence. Construction, asynchronous rejection, timeout, cancellation,
and panic paths all pass through the same fixed-output boundary.

## Verification

- Tests-first exact request and redaction behavior.
- Tests-first strict OpenRouter response and closed structured result schema.
- Seeded secret and PII absence at the captured endpoint.
- Hostile object, parser, header, destination, timeout, and cleanup cases.
- Six focused passes, exact local run, full pinned repository gates, production
  audit, whitespace, redacted secret scan, exact-SHA push gate, and review.
