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

## Produce observations using local static scanner images

The Linux launcher uses a locally installed Docker Engine and its registered `runsc` runtime. The operator supplies a locally reviewed image that provides either the Cisco `skill-scanner` executable or NVIDIA's `skillspector` executable on the fixed container path. The launcher uses the local image ID and never pulls an image or installs scanner dependencies. Review each image and its licenses before assigning a signing key. The repository's [offline scanner benchmark](local-skill-scanner-benchmark.md) records the upstream CLI profiles previously exercised on benign local fixtures.

Build the Linux launcher from the repository root.

```sh
go build -C cmd/zaspctl -o /tmp/zasp-offline-addon-static ./cmd/zasp-offline-addon-static
```

Configure the three scope variables documented above. Set `ZASP_ADDON_SCANNER_IMAGE_ID` to the inspected local image's immutable `sha256:` ID. Each invocation runs one scanner. The following example runs Cisco on a local directory. Select `nvidia_skillspector` with its own image ID to run NVIDIA. Use the printed profile digest when configuring the receiving importer.

```sh
/tmp/zasp-offline-addon-static --scanner cisco_skill_scanner --print-profile
/tmp/zasp-offline-addon-static --scanner cisco_skill_scanner \
  --skill ./reviewed-skill --addon-version "$ADDON_VERSION_ID" --out ./cisco-observation
```

The launcher copies each verified regular file into a private temporary directory, clears execute permissions and recomputes the native add-on manifest digest on the copied contents. The sandbox sees only this read-only snapshot. Both vendor profiles use the fixed local static scan invocation and SARIF 2.1.0 output. NVIDIA also receives `--no-llm`. Docker runs the scanner as an unprivileged numeric user with network disabled, all capabilities dropped, resource limits, a read-only root filesystem, and a bounded temporary filesystem. The scan times out after 120 seconds. A missing runtime, partial source manifest, failed invocation or invalid report fails the command.

The launcher writes `rule-counts.json` and `observation.json` in a new output directory. Rule counts preserve bounded vendor identifiers from completed scans. Only rule IDs with a reviewed mapping contribute to the signed observation’s indicator list. An empty indicator list can accompany nonzero unmapped findings. Source excerpts and report messages are excluded. To sign at the point of observation, set `ZASP_ADDON_SCANNER_SIGNING_KEY_FILE` to an owner-only file containing the base64 Ed25519 seed. The host writes `observation.sig` alongside the JSON. The signing key stays outside the sandbox. Import the signed observation using the command above.
