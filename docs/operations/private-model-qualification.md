# Private model qualification

The API evaluates an approved snippet only when the caller supplies `content_mode: approved_code_snippet` on a guardrail decision. Use this for code the caller has approved for model review. The organization must allow private code, the environment must permit approved snippets, and Data & Retention must allow extended collection. Production metadata-only environments retain deterministic snippet decisions. Each admitted call reserves its configured maximum cost against the environment’s UTC monthly budget.

## Configure a model deployment

Configure the private service and its TLS certificate in the approved US or EU region. The control plane connects to the configured private IP and validates the certificate for the endpoint hostname. vLLM uses its OpenAI-compatible chat completions endpoint. The ONNX sequence classifier uses the TEI-compatible binary classification endpoint at `/predict`, with a text preprocessing pipeline, a fixed maximum input size, and both model labels returned as probabilities.

A deployment profile is a JSON object. Fill in the actual endpoint, address, SHA-256 of the deployed weights, model identifier, region and operator-approved maximum charge per request.

```json
{
  "endpoint": "https://inference.internal/v1/chat/completions",
  "private_ip": "10.20.30.40",
  "weights_sha256": "<64 lowercase hex digits>",
  "model": "mistralai/Shieldstral-1.0-3B",
  "region": "eu",
  "maximum_nano_credits": 250
}
```

Mount the vLLM profile on the API and set `ZASP_GUARDRAIL_VLLM_PROFILE` to its path. For ONNX use `ZASP_GUARDRAIL_ONNX_PROFILE`, the `/predict` endpoint, a supported classifier identifier and the model’s exact `safe_label` and `malicious_label` values. Private inference requires a separately provisioned service and matching qualification. Updating deployment identity or pricing requires a fresh qualification.

The asynchronous purpose review worker accepts the same model, endpoint, IP, weights digest, region and maximum charge through the `ZASP_INTENT_CLASSIFIER_` variables `MODEL`, `ENDPOINT`, `PRIVATE_IP`, `WEIGHTS_SHA256`, `RESIDENCY` and `MAX_NANO_CREDITS`. Enable it on the scheduler with `ZASP_INTENT_CLASSIFIER_ENABLED=true`.

## Measure a deployment

The trusted release operator reviews weight provenance, deployment region, exact model bytes and the zero-retention agreement. Sign an attestation JSON object containing the deployment profile under `deployment`, the `purpose`, `base_weight_origin` (`us` or `eu`), `zero_retention` (true) and an RFC 3339 `expires_at` within 90 days. Supply a detached Ed25519 signature over the exact manifest bytes. Encode the public key and signature as standard base64.

For `purpose_alignment_check` the runner supplies its fixed suite of 128 synthetic observations. For `heuristic_fp_verify` and `indirect_injection_screen` the attestation must also cover the hex `corpus_sha256` of a release-reviewed JSONL corpus. Each record contains `input`, boolean `positive` and boolean `counterfeit_policy`. Include at least 60 unique negative and 50 unique positive examples and mark the policy-isolation cases. Use sanitized fixtures prepared for offline qualification.

Run from a trusted control-plane host with private endpoint access. Set `ZASP_QUALIFICATION_DATABASE_URL` to an operator connection authorized to write scoped qualification rows. Choose the public key from the trusted issuer’s installation.

```sh
go run -C services/platform ./cmd/zasp-model-qualify \
  -manifest deployment-attestation.json -signature deployment.sig -public-key release.pub \
  -organization "$ORG_ID" -workspace "$WORKSPACE_ID" -environment "$ENV_ID" \
  -corpus qualification.jsonl
```

The command records the measured model, purpose, deployment digest, evidence digest and expiry. Schema adherence, latency and case outcomes appear on stdout. A failed measured run records a failed qualification. The **AI & Models** page lists the result.

## Review a rule

The **Guardrails → Calibration** panel collects analyst labels on recent matches. Select a heuristic rule and enable shadow review. Shadow review retains the original decision. Active mode requires at least 60 labelled shadow observations for the qualified deployment, a reduction in false positives, and preserved serious detections. The decision receipt records the semantic state and retains the original match. A hard rule or a decision with multiple matched rules retains deterministic enforcement.

## Bind an API job to a private provider

The API reads one provider configuration at startup for investigation and one for inventory review. Each configuration binds the provider, region, model, credential reference and per-call budget to a qualified deployment. Configure one provider per job. After rotating credentials, update their scoped reference and digest under **Administration → AI & Models** and restart the API.

| Job | Bedrock variable prefix | Vertex variable prefix |
| --- | --- | --- |
| Session investigation | `ZASP_BEDROCK_TRIAGE_` | `ZASP_VERTEX_TRIAGE_` |
| Inventory review | `ZASP_BEDROCK_INVENTORY_` | `ZASP_VERTEX_INVENTORY_` |

Append `MODEL`, `TOKEN_FILE`, `CREDENTIAL_REFERENCE` and `MAX_NANO_CREDITS` to the selected prefix. Mount the bearer credential in a regular file with write access restricted to its owner. Use the exact reference under `secret_ref_planner/{organization}/{workspace}/{environment}/` and a positive integer upper cost in nano-credits. A short-lived token must remain valid for the request.

For Bedrock, supply `VPCE_HOST` and `VPCE_IP` for the regional Bedrock Runtime interface endpoint. For Vertex, supply `LOCATION`, `PROJECT` and `PSC_IP` for the Google Cloud project and Private Service Connect endpoint. For example, `ZASP_VERTEX_TRIAGE_LOCATION=europe-west4` selects the regional Vertex API in the Netherlands. The API dials the pinned private address with TLS verification of the regional service hostname.

Qualification evidence and policy consent must match the runtime binding before it can serve customer traffic. The no-retention agreement, US or EU hosting and model provenance are operator-signed facts about the real deployment.

## Run qualifications from AI & Models

Start the signed qualification command with the same arguments and the additional `-work` flag for each deployment and purpose. A worker registers its scoped availability for 30 seconds, refreshes it while polling, and runs one job at a time. Select the environment’s exact profile in **Administration → AI & Models**, then select its purpose and run qualification. A fresh browser session and the manage-data-controls permission are required. Progress and the final pass or failure are available in the same view. Each observation reserves the configured upper cost from the monthly environment budget. A stopped worker’s job expires after one hour.

For a customer-hosted vLLM or ONNX deployment, include `provider: byoc_self_hosted` and the exact `organization_id`, `workspace_id` and `environment_id` in the signed profile. The asynchronous intent worker reads these from `ZASP_INTENT_CLASSIFIER_PROVIDER`, `ORGANIZATION_ID`, `WORKSPACE_ID` and `ENVIRONMENT_ID` under the same prefix. These fields bind the deployment and its qualifications to the selected scope.

For Bedrock or Vertex, replace the `deployment` object in the signed attestation with `bedrock` or `vertex`. Both require `private_ip`, `model`, `credential_reference` and `maximum_nano_credits`. Bedrock also requires the regional `vpce_host`, and Vertex requires `location` and `project`. Mount a private credential file and provide its path through `ZASP_QUALIFICATION_BEDROCK_TOKEN_FILE` or `ZASP_QUALIFICATION_VERTEX_TOKEN_FILE`. The release-reviewed JSONL corpus for deep jobs must contain at least 100 distinct synthetic cases, their typed `input`, a purpose-specific `expected` object, and policy-isolation cases marked with `counterfeit_policy`. Include its SHA-256 in the signed manifest.

## Download a calibration snapshot

Configure the compliance export worker and its versioned, KMS-encrypted export bucket. With **View compliance** permission, open **Protect → Guardrails → Calibration** and create an export. It freezes up to 2,048 redacted evaluation records from the previous 30 days. The JSONL starts with a schema and sample-count record. The remaining records contain decision and rule identifiers, evaluation times, probabilities and available analyst labels. The job expires after one day.

Set `ZASP_API_URL` to your HTTPS API origin. Run `zaspctl calibration export --environment ID` to open the calibration page. When the export is ready, issue a single-use grant. To download directly from the CLI, set `ZASP_API_TOKEN` to an API token for the same environment with **View compliance** and run the following command. Paste the grant at the standard-input prompt within one minute. The CLI checks the scope and SHA-256 and writes a new owner-only file.

```sh
zaspctl calibration export --environment ENVIRONMENT_ID --export-id EXPORT_ID --output calibration.jsonl
```
