# Authentication and support

Production browser authentication is Stytch B2B OAuth backed by durable, revocable PostgreSQL sessions and `__Host-` secure cookies. Same-origin browser mutations require the exact configured Origin and CSRF token. PATs are bearer credentials with scoped permissions; token secrets are shown only through the bounded reveal-grant workflow and are never stored in browser persistence or logs.

Operators configure Stytch project, public token, organization and secret through secret-manager object references. The public callback origin must equal the ingress TLS origin. Never accept forwarded identity/scope headers from clients; the API deletes them and reconstructs identity from authenticated durable state.

Support may ask for timestamp, affected workflow and correlation ID. Support must not ask for session cookies, bearer tokens, CSRF values, database URLs, secret-manager payloads or full HTTP archives. Revoke a suspected session or PAT immediately, preserve audit records, and use the session-investigation/API-token workflows. Provider dashboards, internal health, metrics and traces remain operator-private.

User-supported workflows are listed in `docs/operations/supported-workflows.md`. Hidden routes and controls are unsupported even if older prototype documentation mentions them.
