# Kubernetes projected Pod identity component

This standalone standard library module authenticates a projected Pod token with
an operator-selected Kubernetes API, then reads the current service account,
Pod, ReplicaSet, Deployment, Node, and cluster namespace twice. Successful
verification makes exactly 13 HTTPS calls within one five-second context.
The output establishes observed Pod identity; it grants no product permission
and does not establish container or process identity.

The endpoint, explicit CA, CIDRs, issuer, audience, namespace, integration and
cluster UID are operator trust. Every DNS answer must be permitted before one
pinned address is dialed. The token never selects an endpoint. No proxy,
redirect, automatic retry, or positive observation cache is enabled.

The reviewer credential is read anew from an absolute Linux path for every
verification. It must be a current-user-owned regular single-link 0600 file,
without a final symlink. Its parent directory is operator trust. A Kubernetes
projected secret symlink is not accepted directly: a separate secure publisher
that preserves rotation is required. Other operating systems fail closed.
Ready checks local configuration and credential access; it makes no provider
call and does not assert Kubernetes RBAC readiness.

No service configuration or gateway activation is included here. Production
integration still requires native catalog provenance, authorization, current
credential and policy checks, provider RBAC, and deployed end-to-end validation.

`FactsSHA256` binds the observed facts and request metadata as Gateway testimony;
it is not a Kubernetes signature. Sequential reads provide no atomic Kubernetes
or database snapshot. Result validity ends at the earlier of token expiry and
five seconds after the final observation.

## Continuous reviewer-token publisher

The module includes `cmd/gateway-reviewer-publisher`. Build it from this module
with `go build -o gateway-reviewer-publisher ./cmd/gateway-reviewer-publisher`.
It continuously observes the selected Kubernetes projected-volume token and
publishes a regular `credential` file for `ReviewerCredentialFile`:

```sh
gateway-reviewer-publisher \
  -source-directory /var/run/secrets/zasp-reviewer \
  -source-name token \
  -destination-directory /var/run/zasp/reviewer-private
```

Provision the destination as a dedicated current-user-owned 0700 directory.
The publisher and verifier must use the same UID. The projected source remains
read-only; the publisher never changes its permissions or follows links outside
its selected volume. An exclusive private lock prevents concurrent publishers.
Only the reserved output and staging files are eligible for recovery, after
ownership, mode, link and content checks. Recovery expresses the operator's
choice of this private namespace; it does not prove a previous publisher's
identity. Other files are retained.

Publication uses a protected temporary file, file sync, atomic replacement,
directory sync and readback. Source failure or near expiry withdraws only the
pinned owned output. SIGTERM and interruption join cleanup before exit. A crash
may leave the last file until token expiry. Kernel filesystem waits have no
promised duration bound. Errors and command parsing never print token values.

The token's decoded expiration is a local freshness check. It establishes no
signature, identity, Kubernetes permission or product authority. Each verifier
request still requires actual Kubernetes authentication. The three grouped
publisher checks use real temporary files and rotation, alongside the original
five verifier groups. Actual Kubernetes root/fsGroup mounts, reviewer RBAC,
sidecar provisioning, runtime wiring and deployed rotation acceptance remain
required; this component does not activate authenticated Gateway routing.
