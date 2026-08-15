# M0-20 PostHog privacy proof design

Date: August 15, 2026

## Decision

Prove the product-owned analytics privacy boundary against a synthetic fake
PostHog capture endpoint on a random loopback port. The proof uses no PostHog credential,
SDK, account, hosted service, `.env`, proxy, or ambient endpoint.
PostHog remains optional and has no authority over deterministic product or
security behavior.

## Product boundary

The serializer accepts one typed product event only:

- event name `proof_completed`;
- fixed synthetic Organization scope;
- environment `test`;
- source `m0-20`;
- boolean success.

It constructs the capture document from those values instead of copying caller
objects. It requires exact primitive types and values, rejects prototypes and
accessors, and must fail closed on every unknown property. Prompt, secret, IP
address, raw evidence, arbitrary context, person profile, feature-flag, and
vendor-native passthrough fields are outside the catalog. Their keys and seeded
values are rejected before any network call.

## Fake endpoint

The proof owns one `node:http` server bound to numeric `127.0.0.1` on a random
loopback port. It accepts exactly one `POST /capture` request with exact JSON
content type, no redirect, no query, a 16 KiB request cap, a two-second socket
deadline, duplicate-free JSON, and the exact allowlisted document. It returns
an exact bounded success acknowledgement and records only the validated
allowlisted document.

The client uses a direct loopback-only `node:http` request, disables agents and
ambient proxy behavior, applies an absolute two-second deadline, caps the
response at 4 KiB, and accepts only the exact status, headers, and body. Reads
may not broaden the destination after validation.

## Failure and cleanup

The proof runs within a ten-second main deadline and an independent five-second
cleanup deadline. Server close and socket drainage continue after any failure;
cleanup failure wins. The CLI emits one fixed line only:

```text
PostHog privacy proof passed: event=true prompt=false secret=false ip=false evidence=false cleanup=true.
```

Failures are `PostHog privacy proof failed: <category> rejected.` with a fixed
category catalog. Raw events, seeded prohibited values, URLs, ports, HTTP
responses, stack traces, and errors never cross the output boundary.

## Evidence decision

R-13 can pass only if one exact allowlisted event reaches the fake endpoint,
each prohibited seeded field is rejected with zero request attempts, the
endpoint receives no unexpected request, and cleanup is proven. This local
privacy proof does not claim hosted PostHog availability, account
configuration, feature-flag behavior, or production analytics delivery.
