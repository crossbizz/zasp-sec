# Optional managed browser coverage

The MV3 package records one local fact per supported origin and UTC day when a top-level document opens in a browser profile with an enabled policy. It requires no endpoint agent. Open **Zasp Browser Guard** from the toolbar to see managed policy health, enabled origins, retention and observations. The popup shows whether collection stays local or an enrolled control plane has acknowledged this profile.

The signed-in employee, tab URL/path, document title, prompt, tool, attachment, session ID and user profile identifier are outside the stored record. The extension registers an isolated content script only for the intersection of the shipped HTTPS origin list and a valid managed policy. Unconfigured, disabled and invalid policies turn collection off. Repeated visits on the same day produce one fact. Private browsing is excluded. Background maintenance runs hourly while Chromium is active and on startup or policy change; opening the popup refreshes retention. Disabling the policy or removing an origin purges the corresponding local records when processed. Closing the browser suspends maintenance until its next start.

## Enroll one managed profile for central reporting

1. Build a separately signed package for your own control plane. Run `node extensions/browser-guard/package-managed.mjs https://zasp.example.org /tmp/zasp-pilot-extension` with a new output directory. Package that directory for your enterprise distribution. Its host permissions and content security policy include that exact destination. The ordinary package keeps its local-only network policy.
2. Enable `Enabled`, approved `AllowedOrigins`, and `CentralReportingEnabled=true` in the managed profile. Open the extension and copy its public key. The signing private key and token encryption key are nonextractable WebCrypto keys stored in this extension profile. A fresh profile has a different key.
3. In **Administration → API access**, create one **Report one managed browser profile** token for the active Environment. Open **Managed browser profiles**, select that token, paste the profile public key, select approved origins and register. Distribute that dedicated token once to the person enrolling this profile using your organization's credential delivery channel.
4. In the profile popup, enter the credential ID, Environment ID and token, then select **Enroll this managed profile**. Its first request is an empty heartbeat. Later syncs send only newly observed origin/day facts from the enabled managed allowlist. The extension encrypts the token at rest. The administrator can refresh profile status, last accepted heartbeat and last observed day in API access. Heartbeats older than two hours show as stale. A closed browser can become stale.
5. Retire the profile from API access to revoke its binding and clear stored origin days. Revoking or expiring its token also prevents additional reporting. A policy change disabling central reporting deletes local enrollment, keys and pending remote facts when processed. A new enrollment then requires a new key and a new token. Data already accepted by the server is visible in its rolling 30-day history until retirement. Rotating a token creates a separate binding.

The profile report signature covers the UTF-8 compact JSON array `["zasp.browser-profile.v1", credential_id, issued_unix_seconds, nonce_hex, [[origin, utc_day], ...]]` using ECDSA P-256 SHA-256. The API accepts IEEE P1363 signatures in standard Base64. Only the registered profile can report for that credential. Seeing the same app in a service audit log supplies independent provenance. The daily browser fact alone cannot establish which employee, session or action generated that log.

## Package and deploy a pilot

1. Package only the contents of the [extension directory](extension/manifest.json) for the approved Chrome Web Store or Microsoft Edge Add-ons enterprise publishing channel. From that directory, run `zip -X ../browser-guard.zip *.json *.js *.mjs *.html *.css`. Obtain the stable extension ID and update URL from the signed distribution for each browser.
2. For Chrome on managed macOS, merge the [force-install example](policy/chrome-forceinstall.plist) into the pilot group's existing `com.google.Chrome` Jamf settings. Replace the ID placeholder with the approved Chrome store ID. Apply the [extension-specific preferences](policy/chrome-extension-settings.plist) to `com.google.Chrome.extensions.<extension-id>` for that same group. Preserve other managed extensions.
3. For Edge, assign Intune’s **Control which extensions are installed silently** setting to the pilot group. Use the approved Edge store ID with `https://edge.microsoft.com/extensionwebstorebase/v1/crx`. Provide the per-extension policy through your managed configuration channel. The [Windows policy template](policy/edge-extension-settings.reg.template) shows the keys and value types. Replace the placeholder before deployment.
4. Use exact origins from `https://claude.ai` or `https://chatgpt.com`. `Enabled=true` and at least one allowed origin are required. Retention defaults to seven UTC calendar days; valid values are 1–30. Review Chrome or Edge’s policy diagnostics and the extension popup. A disabled install is a valid deployment state.
5. Open an allowed origin twice in the managed profile, a disallowed origin, and a private browsing window. The first two opens should yield one local date/origin row. Revoke that origin and confirm the row disappears. Test store update, rollback and extension removal on the actual managed group.



## Managed upload routes

Use a dedicated managed canary profile. The default is observation only. Set `UploadBlockingEnabled` to `true` and supply `UploadBlockingRoutes` as a list of up to eight exact URLs on origins already in `AllowedOrigins`. A wildcard, query, unsupported route or origin mismatch disables the upload rule set. The supported route shapes are ChatGPT `/backend-api/files` and `/backend-api/files/prepare`, and Claude `/api/organizations/<organization-uuid>/upload` or `/api/<organization-uuid>/upload`. Supply the actual approved organization UUID. The Chrome and Edge example settings leave this feature disabled.

```json
{
  "Enabled": true,
  "AllowedOrigins": ["https://chatgpt.com"],
  "UploadBlockingEnabled": true,
  "UploadBlockingRoutes": ["https://chatgpt.com/backend-api/files"]
}
```

The browser blocks POST fetch/XHR requests to the selected exact URL from the provider's initiator domain using Declarative Net Request session rules. Method, endpoint and initiator domain determine the decision. The rule can also block another product operation sharing that request route. The extension never reads a prompt, file, body or upload response. The popup shows the number of rules acknowledged by this browser. Enrollment for central usage reporting remains separate and sends no upload outcomes.

Before claiming provider upload coverage, exercise the exact provider version and flow with a harmless staging file. Confirm the upload completes with policy off, enable the route, confirm the control still allows unrelated work and verify the file is absent on the target. Capture the tenant, tested route, browser version and date through your normal pilot evidence process. Recheck when the provider changes its upload endpoints. To roll back, disable the boolean and confirm the popup shows disabled after policy refresh.

## Verify locally

Run from the repository root with Node 22.23.1 or newer.

```sh
node --test extensions/browser-guard/test/guard.test.mjs
node extensions/browser-guard/test/chromium-smoke.mjs --fixture-ui
node extensions/browser-guard/test/chromium-smoke.mjs
```

For a store-signed build assigned through machine-level managed Chrome or Edge policy, run `BROWSER_GUARD_MANAGED_ID=<installed-id> BROWSER_GUARD_UPLOAD_STATE=active CHROMIUM_BIN=<managed-browser> node extensions/browser-guard/test/chromium-smoke.mjs --managed-profile`. This readback uses the actual applied managed settings and the browser’s installed rules in a fresh profile. After disabling upload blocking, repeat with `BROWSER_GUARD_UPLOAD_STATE=disabled`. The test leaves host policy unchanged.

The `--fixture-ui` check renders the packaged popup HTML and script in a real Chromium window with synthetic health data. It requires no extension installation.

Set `CHROMIUM_BIN` to the test browser executable if needed. The smoke uses Chromium's temporary-profile DevTools pipe to load the local package and check the popup, real script-registration API and cleanup with a synthetic policy. It requires a browser that permits unpacked extensions and supports the DevTools Extensions domain. A profile where the administrator forbids unpacked installations rejects the smoke at the load step. Tests with synthetic managed policy exercise local behavior. A real signed extension, managed policy delivery and browser/version-specific checks are required to verify pilot deployment.
