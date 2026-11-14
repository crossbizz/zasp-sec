# Guardrail decision API

A gateway you already run (LiteLLM, Kong, Apigee, your own proxy) asks Zasp what to do with one model interaction: allow it, redact it, or block it. Nothing of Zasp's is installed in your environment. The gateway makes one HTTPS call per interaction.

## What it does and does not do

- The detectors are deterministic: regular expressions, fixed phrase lists and checksums. No model is called, so the same text always gets the same answer.
- They are heuristics. They catch the common literal forms of prompt injection and of sensitive data. A paraphrased injection, or one split across lines or messages, is not detected. Treat a `block` as a strong signal and an `allow` as "nothing known matched", not as proof that the text is safe.
- The interaction text is used for the request only. It is not logged and not stored. The audit record of a decision holds the decision, the matched rule identifiers with their modes and counts, the size of the text in bytes, its SHA-256 digest, and the optional `agent_id` and `tool_name` you sent. The digest lets you tie a record to an interaction you hold; note that a digest of a short, guessable text can be recomputed by anyone who can guess the text.
- A decision is recorded before it is returned. If the record cannot be written the call fails (`503`) and no decision is returned; decide in the gateway whether that fails open or closed.

## Request

`POST /api/v1/guardrails/decisions`

Authentication: an API token of the Environment whose permissions include `decide_guardrails` (`Authorization: Bearer <token>`). A browser session is not accepted, and a token with `view` alone is refused with `403`.

`decide_guardrails` is a permission of API tokens only. No role holds it and it gives access to nothing but this call: a token created with `decide_guardrails` and nothing else cannot read the Environment's inventory, findings, integrations or the guardrail policy, and cannot change anything. The person who creates the token must be able to view the Environment; if that person loses access, the token stops working. Create one token per gateway:

- In the product: Administration, API Access, choose “Guardrail decisions only” and create the token. Tokens created there expire after 24 hours, like every token created in the product today; for a gateway that runs longer, create the token over the API with the expiry you need.
- Over the API (a browser session with fresh authentication and `manage_api_tokens`): `POST /api/v1/admin/api-tokens` with `"permissions": ["decide_guardrails"]` and `expires_at`.

```json
{
  "direction": "input",
  "text": "…the prompt, the retrieved document, the tool result, or the model's answer…",
  "agent_id": "support-agent",
  "tool_name": "crm.lookup"
}
```

| Member | Required | Meaning |
| --- | --- | --- |
| `direction` | yes | `input` for text on its way into a model, `output` for text a model produced. The same rules apply to both; the direction is recorded. |
| `text` | yes | At most 32,768 bytes of UTF-8. A longer text is refused with `413 interaction_too_large`; split it in the gateway or decide there. |
| `agent_id` | no | Your identifier of the agent. Letters, digits and `._:/-`, at most 128 characters. Recorded with the decision. |
| `tool_name` | no | The tool whose call or result the text is. Same form. Recorded with the decision. |

## Response

```json
{
  "decision_id": "pid_…",
  "decision": "redact",
  "redacted_text": "Send the invoice to [REDACTED:pii.email].",
  "matched_rules": [
    { "id": "pii.email", "category": "sensitive_data", "mode": "redact", "count": 1 }
  ],
  "policy_version": 3
}
```

| `decision` | What the gateway does |
| --- | --- |
| `allow` | Forward the text unchanged. `matched_rules` may still list rules in `monitor` mode. |
| `redact` | Forward `redacted_text` instead of the original. Each match of a redacting rule is replaced by `[REDACTED:<rule id>]`. |
| `block` | Do not forward the text. `redacted_text` is absent. |

Errors: `400` malformed request, `401` token missing, expired or revoked, `403` token without `decide_guardrails` (or its owner can no longer view the Environment), `413` text too large, `503` the decision could not be recorded.

## Rules

| Rule | Default | Matches |
| --- | --- | --- |
| `injection.instruction_override` | block | Text that tells the model to ignore, forget, disregard or override its earlier or system instructions; "new instructions:"; requests to reveal the system prompt. A defence of the instructions ("never ignore your previous instructions") is not matched. |
| `injection.role_switch` | block | Chat-template role markers inside the text (`<|im_start|>system`, `<<SYS>>`, `[INST]`, a line starting with `System:`), and requests to switch into an unrestricted persona. |
| `injection.hidden_text` | block | Zero-width and bidirectional control characters, Unicode tag characters, an instruction inside an HTML comment, and base64 that decodes to an instruction override. |
| `injection.tool_call` | block | A tool or function call in a model's own call syntax inside the text (`<tool_call>`, `"tool_calls": [`, `<invoke name=`), or an imperative to call a named tool. |
| `pii.email` | redact | Email addresses. |
| `pii.phone` | redact | Phone numbers in `+country` form and in North American form. |
| `pii.credit_card` | redact | 13 to 19 digit card numbers that pass the Luhn checksum. |
| `pii.us_ssn` | redact | US Social Security numbers written with dashes, excluding ranges that are never issued. |
| `secret.aws_access_key_id` | redact | AWS access key IDs (`AKIA…`, `ASIA…`). The secret access key itself has no fixed form and is not detected. |
| `secret.private_key` | redact | PEM private key blocks. |
| `secret.bearer_token` | redact | `Bearer <token>` values and JSON Web Tokens. |

## Policy

Each Environment has a guardrail policy: for every rule, one of `block`, `redact`, `monitor` (report the match, change nothing) or `off`. Only the sensitive-data rules can be set to `redact`; an injection rule has no span that could be removed. A rule the policy does not name has its default mode.

```sh
# Read: every rule with its mode and description. The ETag is the version.
curl -sS "$API/api/v1/guardrails/policy" -H "Authorization: Bearer $TOKEN"

# Write: needs manage_workflows. If-Match is the current version ("0" before the first save).
curl -sS -X PUT "$API/api/v1/guardrails/policy" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: guardrail-policy-0001' -H 'If-Match: "0"' \
  -d '{"rules":{"secret.private_key":"block","pii.phone":"monitor","injection.tool_call":"monitor"}}'
```

A change is audited and applies to the next decision. To start in observation mode, set every rule to `monitor`, look at what would have been blocked, then tighten.

## Latency

The detectors take about 9 ms for a 16 KB text that contains matches of every kind, on one core of a 2.1 GHz Xeon (`go test ./guardrail -bench Decision16KB`), and less for ordinary text. The call also makes one database statement and one authorization check; those and the network were not measured here. Set a timeout in the gateway and decide what happens when it expires.

## LiteLLM example

This is an example of a LiteLLM custom guardrail that calls the API. **It has not been run against LiteLLM.** It was written from LiteLLM's documented `CustomGuardrail` interface as remembered; check the hook names and signatures against the LiteLLM version you run before using it.

```python
# zasp_guardrail.py — example, not run against LiteLLM.
import os

import httpx
from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

ZASP_URL = os.environ["ZASP_API_URL"].rstrip("/") + "/api/v1/guardrails/decisions"
ZASP_TOKEN = os.environ["ZASP_GUARDRAIL_TOKEN"]
MAX_BYTES = 32768


async def decide(direction: str, text: str, agent_id: str | None) -> dict:
    body = {"direction": direction, "text": text}
    if agent_id:
        body["agent_id"] = agent_id
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.post(ZASP_URL, json=body, headers={"Authorization": f"Bearer {ZASP_TOKEN}"})
    response.raise_for_status()
    return response.json()


class ZaspGuardrail(CustomGuardrail):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        agent_id = (data.get("metadata") or {}).get("agent_id")
        for message in data.get("messages", []):
            content = message.get("content")
            if not isinstance(content, str) or not content:
                continue
            if len(content.encode()) > MAX_BYTES:
                # Larger than one decision takes: this example fails closed.
                raise HTTPException(status_code=400, detail="Message too large for the guardrail")
            result = await decide("input", content, agent_id)
            if result["decision"] == "block":
                raise HTTPException(status_code=400, detail={"error": "Blocked by guardrail", "rules": [r["id"] for r in result["matched_rules"]]})
            if result["decision"] == "redact":
                message["content"] = result["redacted_text"]
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        agent_id = (data.get("metadata") or {}).get("agent_id")
        for choice in getattr(response, "choices", []):
            content = getattr(choice.message, "content", None)
            if not isinstance(content, str) or not content or len(content.encode()) > MAX_BYTES:
                continue
            result = await decide("output", content, agent_id)
            if result["decision"] == "block":
                raise HTTPException(status_code=400, detail={"error": "Response blocked by guardrail", "rules": [r["id"] for r in result["matched_rules"]]})
            if result["decision"] == "redact":
                choice.message.content = result["redacted_text"]
        return response
```

```yaml
# LiteLLM proxy config (example, not run).
guardrails:
  - guardrail_name: zasp
    litellm_params:
      guardrail: zasp_guardrail.ZaspGuardrail
      mode: [pre_call, post_call]
      default_on: true
```

Things the example leaves to you: streaming responses (the output hook above sees only complete responses), tool-call arguments and tool results (send them as `input` with `tool_name`), a failure policy when the call times out (the example raises, which fails closed), and messages whose content is a list of parts rather than a string.
