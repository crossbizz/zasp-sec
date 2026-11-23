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
