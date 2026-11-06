# Associate an existing Device with an Agent

Association is an administrative configuration with three steps. It does not
establish observed workload routing or Agent coverage. The association profile
remains default-off; native and deployed acceptance must pass before rollout.

1. In the Agent view, reauthenticate with Stytch and create an intent for the
   intended Device. Your current permission must allow managing that Agent's
   identity. Copy the public challenge into a protected local input file.
2. On the Device, accept the challenge using one of the credential sources below.
   The CLI writes durable intent before sending acceptance and reports only
   Device acceptance pending separate human approval.
3. Return as the same human, refresh the Agent's current association status,
   reauthenticate if needed, and approve the association before it expires.

For existing enrollment custody:

```sh
agentsecctl gateway accept-agent \
  --custody-file /var/lib/zasp/gateway.custody.json \
  --ca-bundle-file /etc/zasp/gateway-control-ca.pem \
  < /run/zasp/association-challenge.json
```

For an existing runtime credential file:

```sh
agentsecctl gateway accept-agent \
  --credential-file /run/zasp/gateway-credential.json \
  --endpoint https://gateway-control.example.com \
  --association-state-file /var/lib/zasp/agent-association.state.json \
  --ca-bundle-file /etc/zasp/gateway-control-ca.pem \
  --timeout 10s \
  < /run/zasp/association-challenge.json
```

Use your actual gateway-control origin and trusted CA file. Supply either custody
or all three standalone credential options. The endpoint comes from your trusted
configuration. The public challenge does not select an endpoint.

The standalone credential must be the existing owner-only, mode `0600` regular
file containing `credential_id`, `key_id`, and `private_key`. It is read without
rewriting it or creating sibling files. Its parent can be read-only. Use an
existing writable directory for the separate association state; the CLI retains
public identity history and immutable intent and receipt artifacts there. It
does not copy the private key into association state or create enrollment history.

Every standalone invocation makes a fresh signed current-Authority read before
acceptance. The CA-authenticated response binds the current Device scope,
credential generation, public key and expiry. Saved history cannot replace that
read. The one timeout covers both network requests and receipt persistence.

If delivery or confirmation is unknown, retain the original credential, challenge
and state. Deliberately retry with the same options and input while still valid;
the CLI rereads current Authority and resends the exact retained acceptance body.
Do not delete state or recreate enrollment to recover an uncertain response.
Changed keys, generation or scope require a fresh admission with deliberately
chosen state. Expired challenges require a new human intent.

Whole-association revocation invalidates admitted configuration and pending
intents. Device credentials remain separate. Successful Device acceptance does
not activate an association, export credentials, or confirm an earlier enrollment.
