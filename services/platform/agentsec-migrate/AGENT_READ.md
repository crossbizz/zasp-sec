# Current Agent read profile

This supplementary profile supplies current authorization for Agent detail,
capabilities, relationships and observed runtime session references. It does not
install filters or grant access to related object details or session events.
The original canonical migrations and historical readers remain unchanged.

Print the exact compiled normal and Audit recipe checksums with
`agentsec-migrate agent-read-profile-checksums`. After the corresponding current
Temporal/authorization/worker prerequisites have been genuinely installed and
verified, select the matching checksum in `ZASP_AGENT_READ_PROFILE_CHECKSUM` and
run `up-agent-read-profile` or `up-agent-read-audit-profile` as the configured
original migration LOGIN. Source-owner admission, fixed parent catalogs and the
new profile catalog must pass; namespace presence is insufficient. Confirmation
uses the existing bounded authority transaction and must commit successfully.

The API uses the same checksum in `ZASP_AGENT_READ_PROFILE_CHECKSUM` with current
runtime services. An empty value leaves the profile off. A configured but missing,
foreign, drifted or incompatible profile refuses startup/readiness. The Helm
consumer value is `agentRead.profileChecksum`; it never installs SQL or grants
worker permissions. It stays empty by default.

The Agent sessions reader uses scoped source40/41 runtime events and summaries,
with the existing exact agent-event association and summary first-event time.
It excludes unattributed and product-console identity sessions. A session may
contain events from more than one Agent; these references do not assert exclusive
ownership or permit retrieving another resource.

Component/source checks do not establish normal/Audit native permission
acceptance or deployed Stytch, OpenFGA and provider flows. Run the required native
and mounted API/browser checks before treating the profile as production
available. The shell/code-execution and high-impact filter requirement remains
open until its authoritative semantics and real list path are implemented.
