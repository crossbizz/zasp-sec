# Optional egress operator commands

These commands configure the supplementary optional-egress authority. They do
not approve a provider, establish a contractual data policy, create credentials,
or prove deployed end-to-end behavior. Optional destinations remain off after
installation and profile registration.

Run the command from the same release image used by the API and workers:

```
agentsec-migrate optional-egress-profile-checksums
```

The JSON output contains only the compiled `normal` and `audit` checksums. This
command does not connect to PostgreSQL. Configure API and worker consumers with
the same explicitly selected `ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM`.

The composed `up-authorization-runtime-profile` deployment uses the **audit**
worker parent. After that exact parent is installed, run:

```
agentsec-migrate up-optional-egress-audit-profile
```

`up-optional-egress-profile` is the separate standalone recipe for the original
worker parent. Neither command installs or converts its parent. Installing the
other recipe into an existing optional-egress namespace is refused. Both need
`ZASP_POSTGRES_DSN` and the actual registered
`ZASP_MIGRATION_DB_PRINCIPAL`; installation uses the existing migration timeout
and authority checks.

## Explicit operator configuration

The following commands additionally require:

- `ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM`: the selected checksum from this image.
- `ZASP_OPTIONAL_EGRESS_CONFIGURATION_FILE`: an absolute, regular, private JSON
  file with permissions `0400` or `0600`, at most 16 KiB. Symlinks, changed files,
  duplicate/unknown fields and nulls are refused.

No profile contents, credential references or database diagnostics are printed.
An unsuccessful command reports a fixed failure and does not imply acceptance.

`register-optional-egress-principals` accepts exactly `human_principal`,
`planner_principal` and `settlement_principal`. The three distinct logins must
already have their original registered API/Temporal roles. This command binds
all three purposes atomically; it does not create logins or alter parent roles.

`configure-optional-egress-profile` accepts exactly `organization_id`,
`workspace_id`, `environment_id` and `profile`. The profile is the complete
versioned `optionalegress.Profile` contract, including scope-bound credential
reference, actual approved account/model/backend, content digest, capability and
pricing evidence pins, canonical UTC timestamps, token limits, rate ceilings,
concurrency and unresolved exposure ceiling. The operator must obtain these
values and approvals from the actual deployment/provider owners. The command
checks typed content/digest binding; SQL remains the authority for complete
profile validity and limits. It neither supplies defaults nor invents approvals.
In this new profile, `*_nano_credits` fields mean nano-USD, with one USD equal to
1,000,000,000 units; rates are nano-USD per million tokens. Existing planner
credit/account conversion rules remain separate.

Registering the first profile leaves OpenRouter disabled. An authorized human
can explicitly enable the destination through External Data Flows with fresh
authentication and the current policy version.

For rotation, first disable the destination through that same API. Register the
new approved immutable version, then use `activate-optional-egress-profile` with
exact `organization_id`, `workspace_id`, `environment_id`, `profile_id`,
`profile_version` and `expected_version`. Activation requires the policy to be
disabled, compares its version and appends audit evidence. Re-enabling requires
a separate authorized human update. Captured requests keep their old binding;
rotation cannot manufacture a new send for an existing key.

Consumer startup requires the preinstalled matching catalog and the actual
registered purpose logins. Deployment hooks must not manufacture an approved
profile or silently enable optional egress. Real Stytch/provider acceptance,
credential-holder withdrawal, operational evidence and all release guards still
apply.
