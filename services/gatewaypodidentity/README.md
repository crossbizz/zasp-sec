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
