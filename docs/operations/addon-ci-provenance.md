# Verify a skill manifest against a CI commit

A repository maintainer can attach a protected CI job's Ed25519 signature to a complete skill scan. Zasp checks that signature against the public key registered for the repository, Environment, and submitter. An AppSec reviewer can then see whether the CI scan directly attests a version or a local copy has the same manifest. An edit gives the local copy a different digest. Installed and loaded usage keep their own evidence.

## Register the repository signer

1. In **API Access**, create a token with only `submit_addon_scans`. Record its product ID and the Organization, Workspace and Environment IDs. Use one credential per repository trust boundary.
2. Generate an Ed25519 signing key in your protected CI environment. Only the protected signing job should have access to the private key. The PEM file must be an owner-only PKCS8 regular file. The following example prints the 32-byte **public** key as lowercase hexadecimal. Keep the private file outside the checkout and CI artifacts.

   ```sh
   umask 077
   openssl genpkey -algorithm Ed25519 -out ci-private.pem
   openssl pkey -in ci-private.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
   ```

3. Connect to the product database as `zasp_operator`. Set the `psql` variables `org`, `workspace`, `env`, `credential`, `repo` and `public_hex` to the product IDs, lowercase `owner/repository` and public key. Register the key with this parameterized statement. The receipt is the public key's fingerprint. Repeating the same registration is safe.

   ```sql
   SELECT zasp_authorization80.register_addon_ci_key(
     :'org', :'workspace', :'env', :'credential', :'repo', decode(:'public_hex','hex'), false
   );
   ```

The registration scopes authority to a single repository and upload credential. The operator controls this binding. CI credentials can submit and sign their own scans. Review and export use the existing browser permissions.

## Sign a complete skill directory

Run these commands in a protected job using a trusted `zaspctl` build and a local Git clone. Set `ZASP_API_URL`, the registered `ZASP_API_TOKEN`, and the variables used below from trusted CI configuration. Give the signing job a full commit SHA from the validated pipeline event. Keep untrusted pull-request scripts away from the signing key. The `--bundle` value is a relative directory inside the named commit.

```sh
zaspctl addons scan .claude/skills/ticket-helper --local --json > scan.json
zaspctl addons submit scan.json --mode findings-only --origin ci \
  --environment "$ZASP_ENV_ID" --json > receipt.json
zaspctl addons attest receipt.json --environment "$ZASP_ENV_ID" \
  --credential-id "$ZASP_CI_CREDENTIAL_ID" --repository "$ZASP_CI_REPOSITORY" \
  --commit "$ZASP_CI_COMMIT" --bundle .claude/skills/ticket-helper \
  --repo-dir . --key-file "$ZASP_CI_KEY_FILE"
```

The last command re-reads the commit's immutable Git tree and scans the bytes. It rejects unsupported links, submodules, oversized bundles, missing objects and digests that differ from the original receipt. The signed message binds the Environment, credential, immutable scan receipt, key fingerprint, repository, commit, manifest digest, rule set and sorted finding counts. The upload carries repository and commit metadata with the signature. Source, file paths and the signing key stay with CI. The server independently checks the submitted report, current key binding, signature and scope. Repeating an identical attestation returns its receipt.

## Read or retire evidence

`GET /api/v1/addon-versions/{id}/ci-origin` requires browser read access in the selected Environment. `verified` with `direct` identifies a signed CI version. `verified` with `same_manifest` identifies matching bytes observed by a different source. Signing a manifest neither approves the version nor establishes that a local skill ran. `unknown` means the server could not verify a matching signature against a current registered signer.

To rotate a signer, register a new public key and update the protected job. To retire an old key, run the registration statement with the same arguments and the final boolean set to `true`. Retiring a signer is terminal for that key binding. The browser read revalidates current trust. Existing scan and review receipts remain available. Rotating an upload credential also requires a new repository binding.
