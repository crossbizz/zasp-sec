# Import signed offline add-on observations

An operator can attach a scanner's observations to an existing add-on version. The importer accepts signed metadata from an independently operated offline scanner. ZASP does not install a scanner, run an uploaded add-on or collect a trace through this interface.

Use a separate signing key and scanner profile for each trusted scanner deployment. Mount the verification key on the importer host independently of the receipt and its signature. The profile digest identifies the reviewed scanner configuration and artifact set. Configure the following variables on the importer host.

| Variable | Value |
|---|---|
| `ZASP_ADDON_SCANNER_VERIFY_KEY_FILE` | Mounted Ed25519 public key in standard base64 |
| `ZASP_ADDON_SCANNER_PROFILE_DIGEST` | Pinned `sha256:` profile digest |
| `ZASP_ADDON_SCANNER_ORGANIZATION_ID`, `ZASP_ADDON_SCANNER_WORKSPACE_ID`, `ZASP_ADDON_SCANNER_ENVIRONMENT_ID` | Three installed target scope IDs |
| `ZASP_ADDON_SCANNER_DATABASE_URL` | Private database connection for the installed operator |

Emit compact JSON in the field order defined by `services/platform/addonsandbox.Receipt`. All fields are required. The scanner signs the ASCII string `zasp-offline-addon-observation.v1`, one zero byte, and the exact JSON bytes using Ed25519. Save the detached signature in standard base64. Times are UTC RFC 3339 values. Evidence expires within seven days of observation. Use the registered version ID, its manifest digest and a fresh product ID for the evidence.

| Scanner | Isolation field | Accepted indicators |
|---|---|---|
| `gvisor_tetragon` | `egress_denied` | `honeytoken_read`, `honeytoken_egress_denied`, `unexpected_process`, `filesystem_write` |
| `cisco_skill_scanner` or `nvidia_skillspector` | `offline_static` | `instruction_override`, `credential_reference`, `network_reference`, `broad_permissions` |

Build or invoke the command from the platform Go module.

```sh
go run ./cmd/zasp-import-addon-receipt --receipt observation.json --signature observation.sig
```

The importer prints the accepted evidence ID. Replaying the same signed observation returns the same receipt. The version detail displays the latest unexpired observation for each scanner. A qualified semantic review can cite the receipt alongside static findings. The receipt never approves a version or deployment.
