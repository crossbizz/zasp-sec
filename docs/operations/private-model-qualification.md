# Private model qualification

The API evaluates an approved snippet only when the caller supplies `content_mode: approved_code_snippet` on a guardrail decision. Use this for code the caller has approved for model review. The organization must allow private code, the environment must permit approved snippets, and Data & Retention must allow extended collection. Production metadata-only environments retain deterministic snippet decisions. Each admitted call reserves its configured maximum cost against the environment’s UTC monthly budget.

## Configure a model deployment

Configure the private service and its TLS certificate in the approved US or EU region. The control plane connects to the configured private IP and validates the certificate for the endpoint hostname. vLLM uses its OpenAI-compatible chat completions endpoint. The ONNX sequence classifier uses the TEI-compatible binary classification endpoint at `/predict`, with a text preprocessing pipeline, a fixed maximum input size, and both model labels returned as probabilities.

For Kubernetes VPC and BYOC installations, install one release of the [private model chart](../../deploy/private-models) per inference profile. The chart is disabled by default. Populate a read-only PVC with the reviewed model weights and tokenizer. Provision a TLS secret for the private service hostname and ensure the API and qualification runner trust the issuing CA. Select reviewed inference and nginx image digests from the installation registry. The ONNX image must implement TEI-compatible classification for the selected model. The vLLM image must include the `vllm serve` command. The deployment mounts local weights without Internet access.

```sh
helm upgrade --install reasoning deploy/private-models -n model-services -f private-values.yaml
```

In the operator values file, set `enabled: true`, `kind` (`onnx` or `vllm`), `model`, `region`, `weightsClaim`, `tlsSecret`, `inferenceImage`, `tlsProxyImage`, and `clientNamespace`. Set resource requests for the measured model. The release exposes a ClusterIP and restricts ingress to labelled API, classifier and qualification pods in the specified namespace. Run in a dedicated namespace with a CNI that enforces NetworkPolicy. Ensure no other policy grants egress or expands ingress to these pods. Record the assigned private IP and verify the weight digest, certificate, region, accelerator capacity and isolation against the installed cluster before enabling the profile.

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

For `purpose_alignment_check` the runner supplies its fixed suite of 128 synthetic observations. For `heuristic_fp_verify` and `indirect_injection_screen` the attestation must also cover the hex `corpus_sha256` of a release-reviewed JSONL corpus. Each record contains `input`, boolean `positive` and boolean `counterfeit_policy`. Include at least 60 unique negative and 50 unique positive examples and mark the policy-isolation cases. Use sanitized fixtures prepared for offline qualification. The repository includes 60 benign heuristic matches at `testdata/v3/benign-heuristic-matches.jsonl`. Combine them with the release operator’s independent positive and policy-isolation cases before signing the corpus digest. The benign subset alone cannot qualify a deployment.

Run from a trusted control-plane host with private endpoint access. Set `ZASP_QUALIFICATION_DATABASE_URL` to an operator connection authorized to write scoped qualification rows. Choose the public key from the trusted issuer’s installation.

```sh
go run -C services/platform ./cmd/zasp-model-qualify \
  -manifest deployment-attestation.json -signature deployment.sig -public-key release.pub \
  -organization "$ORG_ID" -workspace "$WORKSPACE_ID" -environment "$ENV_ID" \
  -corpus qualification.jsonl
```

The command records the measured model, purpose, deployment digest, evidence digest and expiry. Schema adherence, latency and case outcomes appear on stdout. A failed measured run records a failed qualification. The **AI & Models** page lists the result.

## Measure the optional BYOC safeguard candidate

A release operator can measure `openai/gpt-oss-safeguard-20b` for `heuristic_fp_verify` in an isolated batch job. Its output is a local measurement report. The tenant API, alignment classifier and tenant qualification queue reject this model. An offline pass grants no production authority.

Provision a dedicated private vLLM deployment serving that exact model name at the HTTPS path `/v1/chat/completions`. The batch runner must trust the endpoint's TLS certificate. Configure the deployment or its private TLS proxy to require a scoped bearer credential and limit ingress to the qualification runner. Review the weights, tokenizer, serving image, origin, residency and zero-retention controls at installation. Record the SHA-256 of the installed weights. The production Helm profile admits the runtime model list. This candidate requires a separately provisioned evaluation deployment.

Use the deployment profile fields described above, including `provider: byoc_self_hosted`, the three product IDs, endpoint, pinned private address, weights digest, US or EU region and per-call cost ceiling. Mount a regular, owner-only credential file with mode `0600` or `0400`. Compute its SHA-256 over the bearer bytes, omitting the optional final newline. The report binds the release to the credential digest. Rotate the signed manifest when that credential changes.

Build a signed manifest with the following fields. Replace each placeholder with the reviewed value. Use lowercase hexadecimal SHA-256 digests with no prefix. Set the expiration to a UTC timestamp within 90 days.

```json
{
  "qualification_mode": "offline_async_candidate",
  "purpose": "heuristic_fp_verify",
  "deployment": {
    "provider": "byoc_self_hosted",
    "organization_id": "<organization product ID>",
    "workspace_id": "<workspace product ID>",
    "environment_id": "<environment product ID>",
    "endpoint": "https://qualification.customer.internal/v1/chat/completions",
    "private_ip": "10.20.30.40",
    "weights_sha256": "<installed weights digest>",
    "model": "openai/gpt-oss-safeguard-20b",
    "region": "us",
    "maximum_nano_credits": 250
  },
  "base_weight_origin": "us",
  "zero_retention": true,
  "credential_sha256": "<bearer digest>",
  "corpus_sha256": "<reviewed JSONL file digest>",
  "expires_at": "<RFC 3339 timestamp>"
}
```

Have the release issuer sign the exact manifest bytes with Ed25519. Mount the issuer's trusted public key and the detached signature as standard base64 files. Supply a release-reviewed, sanitized JSONL corpus with at least 60 distinct negative cases, 50 distinct positive cases and a policy-isolation case. The batch runner validates every record before contacting the model. Each case contains the three fields described in **Measure a deployment**. The corpus can contain up to 1,024 cases and 8 MiB overall.

```sh
export ZASP_QUALIFICATION_VLLM_TOKEN_FILE=/run/qualification/vllm-token
go run -C services/platform ./cmd/zasp-model-qualify \
  -offline-candidate -manifest safeguard-attestation.json \
  -signature safeguard.sig -public-key release.pub -corpus qualification.jsonl \
  -organization "$ORG_ID" -workspace "$WORKSPACE_ID" -environment "$ENV_ID" \
  > safeguard-measurement.json
```

The command requires no database credentials. The job runs for up to one hour or the signed expiration, whichever comes first. It bounds each completion to 30 seconds and 512 tokens. The report includes the scoped deployment and manifest digests, corpus digest, measured p95 latency, schema adherence, and counts of incorrect and policy-isolation results. It retains the heuristic verifier's 200 ms p95 objective. A completed run that misses the criteria prints its measurements and exits nonzero. The report contains aggregate metrics and excludes corpus content, model responses and the bearer.

## Review a rule

The **Guardrails → Calibration** panel collects analyst labels on recent matches. Select a heuristic rule and enable shadow review. Shadow review retains the original decision. Active mode requires at least 60 labelled shadow observations for the qualified deployment, a reduction in false positives, and preserved serious detections. The decision receipt records the semantic state and retains the original match. A hard rule or a decision with multiple matched rules retains deterministic enforcement.

## Bind an API job to a private provider

The API reads the private provider configurations for investigation, inventory review and remediation advice at startup. Each configuration binds the provider, region, model, credential reference and per-call budget to a qualified deployment. Configure one provider per job. After rotating credentials, update their scoped reference and digest under **Administration → AI & Models** and restart the API.

| Job | Bedrock variable prefix | Vertex variable prefix |
| --- | --- | --- |
| Session investigation | `ZASP_BEDROCK_TRIAGE_` | `ZASP_VERTEX_TRIAGE_` |
| Inventory review | `ZASP_BEDROCK_INVENTORY_` | `ZASP_VERTEX_INVENTORY_` |
| Pending session-isolation advisory | `ZASP_BEDROCK_REMEDIATION_` | `ZASP_VERTEX_REMEDIATION_` |

Append `MODEL`, `TOKEN_FILE`, `CREDENTIAL_REFERENCE` and `MAX_NANO_CREDITS` to the selected prefix. Mount the bearer credential in a regular file with write access restricted to its owner. Use the exact reference under `secret_ref_planner/{organization}/{workspace}/{environment}/` and a positive integer upper cost in nano-credits. For a mounted bearer token, arrange rotation before expiry with the infrastructure credential broker. Mount the refreshed token, update the environment’s SHA-256 credential digest, and roll the API, discovery scheduler and qualification worker that use it. An expired token or mismatched binding suspends optional coverage.

For Bedrock, supply `VPCE_HOST` and `VPCE_IP` for the regional Bedrock Runtime interface endpoint. For Vertex, supply `LOCATION`, `PROJECT` and `PSC_IP` for the Google Cloud project and Private Service Connect endpoint. For example, `ZASP_VERTEX_TRIAGE_LOCATION=europe-west4` selects the regional Vertex API in the Netherlands. The API dials the pinned private address with TLS verification of the regional service hostname.

For `security_agent_remediate`, the signed oracle supplies an array of zero or one already-admitted candidates and up to six evidence IDs. The only supported candidate is a reversible `isolate_session` action with the selected session ID and `ttl_release` rollback. A proposed step must equal that candidate. The oracle must cover recommending it, declining it, and declining on a policy-isolation fixture. Test inference produces advice for human review.

In a Studio containment investigation, open **Find pending approvals** after a cited answer, then select **Request private review** on a matching session-isolation approval. The API reserves one advisory against the shared environment and workflow budgets. The review runs in the background and its status is available when you revisit the thread. Use **Review approval** to make the separate human decision.

Qualification evidence and policy consent must match the runtime binding before it can serve customer traffic. The no-retention agreement, US or EU hosting and model provenance are operator-signed facts about the real deployment.

## Use customer workload identity

For automatic renewal, mount a projected OIDC token and a separate JSON workload identity profile. Set `SUBJECT_TOKEN_FILE` and `WORKLOAD_IDENTITY_FILE` under the job’s provider prefix. Leave `TOKEN_FILE` unset. The signed qualification manifest must contain the same profile under `workload_identity`. Set `ZASP_QUALIFICATION_SUBJECT_TOKEN_FILE` on the qualification worker. At startup the worker prints the credential digest to enter under **AI & Models**. This digest binds the issuer, subject, audience, regional STS private address, and customer role or pool provider.

For AWS, create a workload role whose trust policy fixes the OIDC provider, exact subject and `sts.amazonaws.com` audience. Grant `bedrock:InvokeModel` for the approved model in the selected region. Create a regional STS interface VPC endpoint alongside the Bedrock runtime endpoint. An example workload identity profile follows.

```json
{
  "issuer": "https://issuer.customer.example",
  "subject": "system:serviceaccount:security:analyst",
  "token_audience": "sts.amazonaws.com",
  "sts_private_ip": "10.20.30.41",
  "role_arn": "arn:aws:iam::123456789012:role/zasp-model-reader"
}
```

For Google Cloud, bind the federated subject directly to the approved project and model through a custom role with `aiplatform.endpoints.predict`. Configure the pool’s provider to validate the trusted issuer and the token audience. Supply `workload_provider` as `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` in place of `role_arn`. Use the regional Security Token Service’s Private Service Connect address for `sts_private_ip` and the projected token’s audience for `token_audience`.

Each invocation checks the mounted token’s issuer, subject, audience and expiry. The application sends it only to the configured regional STS over pinned private TLS. AWS issues a 15-minute session for signing Bedrock requests. Google issues a short-lived federated access token. Both providers verify the OIDC signature. A changed projected JWT refreshes the cached session automatically. Changing the configured role, subject, provider, private endpoint or credential reference changes the deployment digest and requires a fresh qualification.

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

## Run the standalone development benchmark

A developer can run three compiled synthetic scope comparisons against OpenRouter using a dedicated development token. The command accepts no input data or model URL. Set `ZASP_DEPLOYMENT_ENV=development`, `ZASP_DEV_MODEL_MODE=dev_openrouter` and `ZASP_DEV_EVAL_OPENROUTER_TOKEN_FILE` to an owner-only file containing the development key, then run `go run -C services/platform ./cmd/zasp-model-dev-eval`. It requests zero retention, disables provider fallback, and prints the count of matching comparisons. Benchmark output stays local and grants no production qualification.
