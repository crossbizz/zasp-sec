# M1-07 Configuration Loader Design

## Decision

Add one dependency-free `services/platform/config` package that loads the
smallest typed startup configuration shared by the platform API and worker.
The loader distinguishes startup-critical dependencies from optional egress
integrations and stores secret references rather than secret material.

## Source boundary

`Load` receives an injected lookup function. Production commands may supply
`os.LookupEnv` later, while tests use an explicit map. The package does not
read process state, files, `.env`, profiles, metadata services, or secret
values by itself.

The required keys are:

- `AGENTSEC_STYTCH_PROJECT_ID`
- `AGENTSEC_STYTCH_SECRET_REF`
- `AGENTSEC_NEON_DSN_SECRET_REF`
- `AGENTSEC_AWS_REGION`
- `AGENTSEC_OTEL_COLLECTOR_ENDPOINT`

Missing, empty, or malformed required values fail loading
with a fixed configuration error. This matches the v1 requirement that
Stytch, Neon, AWS, and in-cluster OpenTelemetry are product dependencies.

The optional dependency groups are:

- PostHog: endpoint plus secret reference;
- OpenRouter: endpoint plus secret reference;
- remote OTLP: endpoint plus an optional secret reference.

An entirely absent optional group produces an absent typed value and does not
fail startup. A partially configured group fails closed. Optional dependency
absence never changes the required group or deterministic runtime behavior.

## Typed values

`Config` contains `RequiredDependencies` and `OptionalDependencies` values
with unexported fields and read-only accessors. `DependencyEndpoint`,
`SecretReference`, `AWSRegion`, and `StytchProjectID` are opaque comparable
values created only by strict parsers.

- the in-cluster Collector endpoint is an absolute `http` or `https` URL;
  optional external egress endpoints require `https`; all endpoints exclude
  user information, query strings, fragments, control characters, and
  non-canonical whitespace;
- secret references are AWS Secrets Manager ARNs for the `aws`, `aws-us-gov`,
  or `aws-cn` partition and never resolve or expose the referenced value;
- AWS regions use bounded lowercase region grammar;
- Stytch project IDs are bounded printable product configuration identifiers,
  not credentials.

Invalid zero/direct-cast values fail validation. Fixed errors contain only the
configuration key or category, never the rejected value.

## Safety and scope

- The loader retains no raw credential, token, DSN, or provider response.
- Returned values are immutable by construction and safe to compare.
- Required failures are deterministic and optional absence is explicit.
- Secret resolution, client construction, retries, deadlines, concurrency,
  health probes, command wiring, logging, and provider calls remain later
  tasks.
- M1-08 remains Pending until M1-07 completes and exact-SHA CI passes.
