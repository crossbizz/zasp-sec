# Reference
## Organization
<details><summary><code>client.organization.<a href="src/zasp/organization/client.py">get_current_principal</a>() -> Principal</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.organization.get_current_principal()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Integrations
<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">list_catalog</a>(...) -> IntegrationCatalogPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.list_catalog()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**q:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**category:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**data_type:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**action:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**auth_mode:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">list</a>(...) -> IntegrationPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">create</a>(...) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.create(
    idempotency_key="Idempotency-Key",
    connector_key="connector_key",
    name="name",
    configuration={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationInput` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get</a>(...) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">delete</a>(...) -> typing.Optional[Integration]</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.delete(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">update</a>(...) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.update(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    name="name",
    configuration={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationUpdateInput` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">sync</a>(...) -> IntegrationSync</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Creates or exactly replays one durable sync, job, outbox record, audit, and browser recovery receipt. BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. Internal job, outbox, credential, cursor, and artifact identifiers are never returned.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.sync(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `EmptyInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">list_syncs</a>(...) -> IntegrationSyncPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.list_syncs(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_sync</a>(...) -> IntegrationSync</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_sync(
    id="id",
    sync_id="syncId",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**sync_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_schedule</a>(...) -> IntegrationSchedule</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_schedule(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">put_schedule</a>(...) -> IntegrationSchedule</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. The server owns next_run_at and accepts only UTC schedules.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.put_schedule(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    cadence_seconds=1,
    state="enabled",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationScheduleInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">delete_schedule</a>(...)</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.delete_schedule(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_freshness</a>(...) -> IntegrationFreshness</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_freshness(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_setup_status</a>(...) -> IntegrationSetupStatus</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Returns only tenant-scoped, redacted setup state. Credential references, provider tokens, installation identifiers, and internal worker authority are never returned.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_setup_status(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_remediation_role</a>(...) -> IntegrationRemediationRole</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Provider remediations (Security Agent actions that change the customer's account) never use the role discovery reads with. They use this separately configured role, and are refused while none is configured.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_remediation_role(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">put_remediation_role</a>(...) -> IntegrationRemediationRole</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. If-Match names the current version ("0" when no role is configured); a request that names a stale version is refused with 409, which also makes a repeated request safe. The role must be an IAM role of the account the integration reads and must not be the role discovery reads with. The change is audited.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.put_remediation_role(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    role_arn="",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**role_arn:** `IntegrationRemediationRoleInputRoleArn` — An IAM role of the account the integration reads, different from the role discovery reads with. The empty string removes the setting.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">test_webhook</a>(...) -> IntegrationWebhookTestStatus</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Uses only the saved destination and signing reference at the expected integration version. Exact retries retain the delivery identifier. A signed succeeded result means Zasp signed the request and the endpoint accepted it with an empty 204 response; it does not attest receiver-side signature verification. Receivers must deduplicate by delivery identifier. Browser mutations require same-origin Origin and CSRF headers; API tokens omit both.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.test_webhook(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `EmptyInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="src/zasp/integrations/client.py">get_webhook_status</a>(...) -> IntegrationWebhookTestStatus</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Tenant-bound and credential-redacted. A missing integration or an integration with no test for its current version returns not_found. Pending delivery is unconfirmed.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.integrations.get_webhook_status(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Sensors
<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">fetch_endpoint_policy</a>(...) -> EndpointBundle</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires a dedicated sync_endpoint token and a fresh device signature over the authenticated scope, operation, nonce, timestamp and exact body digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.fetch_endpoint_policy(
    id="id",
    zasp_device_proof="X-Zasp-Device-Proof",
    zasp_device_signature="X-Zasp-Device-Signature",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_proof:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">exchange_endpoint_enrollment</a>(...) -> EndpointExchangeReceipt</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires a dedicated sync_endpoint token and a fresh device signature over the authenticated scope, operation, nonce, timestamp and exact body digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.exchange_endpoint_enrollment(
    zasp_device_proof="X-Zasp-Device-Proof",
    zasp_device_signature="X-Zasp-Device-Signature",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**zasp_device_proof:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**request:** `EndpointEmpty` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">record_endpoint_heartbeat</a>(...) -> EndpointRecorded</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires a dedicated sync_endpoint token and a fresh device signature over the authenticated scope, operation, nonce, timestamp and exact body digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.record_endpoint_heartbeat(
    id="id",
    zasp_device_proof="X-Zasp-Device-Proof",
    zasp_device_signature="X-Zasp-Device-Signature",
    policy_revision=1,
    policy_status="verified_cache",
    queued_receipts=1,
    dropped_receipts=1,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_proof:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**policy_revision:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**policy_status:** `EndpointHeartbeatPolicyStatus` 
    
</dd>
</dl>

<dl>
<dd>

**queued_receipts:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**dropped_receipts:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**adapter:** `typing.Optional[EndpointHeartbeatAdapter]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">record_endpoint_inventory</a>(...) -> EndpointRecorded</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires a dedicated sync_endpoint token and a fresh device signature over the authenticated scope, operation, nonce, timestamp and exact body digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp
from zasp.sensors import EndpointSnapshotInstallationsItem

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.record_endpoint_inventory(
    id="id",
    zasp_device_proof="X-Zasp-Device-Proof",
    zasp_device_signature="X-Zasp-Device-Signature",
    partition_id="partition_id",
    snapshot_generation=1,
    complete=True,
    installations=[
        EndpointSnapshotInstallationsItem(
            installation_id="installation_id",
        )
    ],
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_proof:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**partition_id:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**snapshot_generation:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**complete:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**installations:** `typing.List[EndpointSnapshotInstallationsItem]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">record_endpoint_observations</a>(...) -> EndpointRecorded</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires a dedicated sync_endpoint token and a fresh device signature over the authenticated scope, operation, nonce, timestamp and exact body digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, EndpointSigned

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.record_endpoint_observations(
    zasp_device_proof="X-Zasp-Device-Proof",
    zasp_device_signature="X-Zasp-Device-Signature",
    receipts=[
        EndpointSigned(
            payload="payload",
            signature="signature",
        )
    ],
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**zasp_device_proof:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_device_signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**receipts:** `typing.List[EndpointSigned]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">list</a>(...) -> SensorPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">create_enrollment</a>(...) -> SensorEnrollment</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require fresh authentication, same-origin Origin, and CSRF. ProductAPIToken requests omit the browser-only headers. Exact replay never reveals token material and returns conflict so the caller can rotate with a new key.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.create_enrollment(
    idempotency_key="Idempotency-Key",
    zasp_fresh_auth="confirmed",
    name="name",
    kind="tetragon",
    mode="metadata_only",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**zasp_fresh_auth:** `CreateEnrollmentSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**name:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**kind:** `SensorKind` 
    
</dd>
</dl>

<dl>
<dd>

**mode:** `SensorMode` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zasp_sensor_enrollment_schema:** `typing.Optional[CreateEnrollmentSensorsRequestXZaspSensorEnrollmentSchema]` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**runtime_sensor_id:** `typing.Optional[ProductId]` — Optional immutable pairing for OTLP only. Must identify an active Tetragon enrollment in the same scope. Omit for an unpaired semantic source. Event payloads cannot select this authority.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">get</a>(...) -> Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">delete</a>(...)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.delete(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">update</a>(...) -> Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.update(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    name="name",
    mode="metadata_only",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**mode:** `SensorMode` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">rotate_token</a>(...) -> SensorEnrollment</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require fresh authentication, same-origin Origin, and CSRF. Exact replay never reveals token material and returns conflict.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.rotate_token(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    zasp_fresh_auth="confirmed",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**zasp_fresh_auth:** `RotateTokenSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**request:** `EmptyInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zasp_sensor_enrollment_schema:** `typing.Optional[RotateTokenSensorsRequestXZaspSensorEnrollmentSchema]` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">get_coverage</a>(...) -> SensorCoverage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.get_coverage(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="src/zasp/sensors/client.py">record_browser_origin_days</a>(...) -> BrowserOriginAck</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, BrowserOriginDay
import datetime

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.sensors.record_browser_origin_days(
    id="id",
    issued_at=1000000,
    nonce="nonce",
    days=[
        BrowserOriginDay(
            origin="https://claude.ai",
            day=datetime.date.fromisoformat("2023-01-15"),
        )
    ],
    signature="signature",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**issued_at:** `int` — UTC Unix seconds.
    
</dd>
</dl>

<dl>
<dd>

**nonce:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**days:** `typing.List[BrowserOriginDay]` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `str` — Base64 P-256 SHA-256 IEEE P1363 signature over the versioned profile envelope.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Guardrails
<details><summary><code>client.guardrails.<a href="src/zasp/guardrails/client.py">decide_action</a>(...) -> WorkloadActionDecision</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

A dedicated token with decide_actions establishes the workload binding. The idempotency key is the action ID. Identical requests return the original receipt. Resource classification comes from the instrumented application.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp
from zasp.guardrails import WorkloadActionRequestResource

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.guardrails.decide_action(
    idempotency_key="Idempotency-Key",
    schema_version="action.v1",
    action_id="action_id",
    action_kind="tool_call",
    operation="operation",
    resource=WorkloadActionRequestResource(
        kind="kind",
        classification="classification",
    ),
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**schema_version:** `WorkloadActionRequestSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**action_id:** `WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**action_kind:** `WorkloadActionRequestActionKind` 
    
</dd>
</dl>

<dl>
<dd>

**operation:** `WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**resource:** `WorkloadActionRequestResource` 
    
</dd>
</dl>

<dl>
<dd>

**source_session_ref:** `typing.Optional[WorkloadActionLabel]` 
    
</dd>
</dl>

<dl>
<dd>

**source_call_ref:** `typing.Optional[WorkloadActionLabel]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="src/zasp/guardrails/client.py">record_action_outcome</a>(...) -> WorkloadOutcomeAck</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The same authenticated workload reports its local observation. Set the idempotency key to the action ID followed by -outcome. Duplicate delivery preserves the initial observation.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.guardrails.record_action_outcome(
    path_action_id="actionId",
    idempotency_key="Idempotency-Key",
    schema_version="action-outcome.v1",
    action_id="action_id",
    decision_id="decision_id",
    status="not_dispatched",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**path_action_id:** `WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**schema_version:** `WorkloadActionOutcomeSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**action_id:** `WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**decision_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `WorkloadActionOutcomeStatus` 
    
</dd>
</dl>

<dl>
<dd>

**context_evidence:** `typing.Optional[WorkloadContextEvidence]`

</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="src/zasp/guardrails/client.py">create_decision</a>(...) -> GuardrailDecision</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

For a gateway the customer already runs (for example a LiteLLM guardrail hook): send the text going into a model (direction input) or coming out of it (direction output) and act on the answer. Authenticate with an API token of the Environment that has the decide_guardrails permission; a browser session is not accepted, and a token with view alone is refused. decide_guardrails is a permission of API tokens only: a token created with it and nothing else can ask for decisions and cannot read anything. The owner of the token must be able to view the Environment. The detectors are deterministic (regular expressions, phrase lists and checksums; no model is called) and are heuristics: see the rule descriptions of the guardrail policy. The interaction text is used for this request only. It is not logged and not stored; the audit record of a decision holds the decision, the matched rule identifiers with their modes and counts, the size of the text and its SHA-256 digest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.guardrails.create_decision(
    direction="input",
    text="text",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**direction:** `GuardrailInteractionDirection` — input is text on its way into a model; output is text a model produced.
    
</dd>
</dl>

<dl>
<dd>

**text:** `str` — The interaction text. At most 32768 bytes of UTF-8; a longer text is refused with 413.
    
</dd>
</dl>

<dl>
<dd>

**agent_id:** `typing.Optional[str]` — Optional identifier of the agent, as the gateway knows it. Recorded with the decision.
    
</dd>
</dl>

<dl>
<dd>

**tool_name:** `typing.Optional[str]` — Optional name of the tool whose call or result the text is. Recorded with the decision.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="src/zasp/guardrails/client.py">get_policy</a>() -> GuardrailPolicy</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Every rule of the catalog with the mode it has in this Environment. Version 0 means no policy was saved and every rule has its default mode.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.guardrails.get_policy()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="src/zasp/guardrails/client.py">put_policy</a>(...) -> GuardrailPolicy</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. If-Match names the current version ("0" when no policy was saved); a stale version is refused with 409, which also makes a repeated request safe. A rule the request does not name has its default mode. The change is audited and applies to the next decision.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.guardrails.put_policy(
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    rules={
        "key": "block"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**rules:** `typing.Dict[str, GuardrailMode]` — Rule identifier to mode. A rule that is not named has its default mode.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tools
<details><summary><code>client.tools.<a href="src/zasp/tools/client.py">attest_addon_scan</a>(...) -> AddonCiReceipt</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires the scan's scoped submission credential and a detached Ed25519 signature from an active registered repository signer. Identical retries reuse the receipt. The protected signing job signs the immutable scan ID, scope, submitter, exact manifest digest, source revision and ordered rule counts.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tools.attest_addon_scan(
    id="id",
    key_id="key_id",
    repository="repository",
    commit="commit",
    signature="signature",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**key_id:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**repository:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**commit:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="src/zasp/tools/client.py">submit_addon_scan</a>(...) -> AddonScanReceipt</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The token must hold submit_addon_scans alone. The report contains rule counts only. The authenticated Environment must match the request body. The server treats the submitted origin as reported. A partial scan has no approvable version.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, AddonFindingCount

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tools.submit_addon_scan(
    idempotency_key="Idempotency-Key",
    environment_id="environment_id",
    schema_version="zasp-addon-findings.v1",
    ruleset="zasp-static.v1",
    manifest_method="addon-manifest.v1",
    completeness="complete",
    origin="local",
    findings=[
        AddonFindingCount(
            rule_id="dependency.unpinned",
            count=1,
        )
    ],
    skipped_count=1,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**environment_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**schema_version:** `AddonScanSubmissionSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**ruleset:** `AddonScanSubmissionRuleset` 
    
</dd>
</dl>

<dl>
<dd>

**manifest_method:** `AddonScanSubmissionManifestMethod` 
    
</dd>
</dl>

<dl>
<dd>

**completeness:** `AddonScanSubmissionCompleteness` 
    
</dd>
</dl>

<dl>
<dd>

**origin:** `AddonScanSubmissionOrigin` 
    
</dd>
</dl>

<dl>
<dd>

**findings:** `typing.List[AddonFindingCount]` 
    
</dd>
</dl>

<dl>
<dd>

**skipped_count:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**private_upload:** `typing.Optional[AddonScanSubmissionPrivateUpload]` 
    
</dd>
</dl>

<dl>
<dd>

**manifest_digest:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="src/zasp/tools/client.py">list</a>(...) -> InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tools.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="src/zasp/tools/client.py">get</a>(...) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tools.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Gateway
<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">get_policy</a>() -> GatewayPolicy</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The policy of the hosted gateway: what happens to an MCP server the MCP registry has no decision for, the risk classes of tools that are hidden and refused, and the rate of one API token. Version 0 means no policy was saved and the defaults apply (unapproved servers allowed, no risk class denied, 600 requests a minute). gateway_enabled says whether this deployment hosts the gateway's traffic routes.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.get_policy()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">put_policy</a>(...) -> GatewayPolicy</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. If-Match names the current version ("0" when no policy was saved); a stale version is refused with 409, which also makes a repeated request safe. The change is audited and applies to the next request through the gateway.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.put_policy(
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    unapproved_servers="allow",
    denied_tool_risks=[
        "execute"
    ],
    requests_per_minute=1,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**unapproved_servers:** `GatewayPolicyInputUnapprovedServers` 
    
</dd>
</dl>

<dl>
<dd>

**denied_tool_risks:** `typing.List[McpToolRiskClass]` 
    
</dd>
</dl>

<dl>
<dd>

**requests_per_minute:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">list_servers</a>() -> McpGatewayServerList</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Each server with the address an agent's configuration names instead of the server's own (gateway_path, under this API's origin), the MCP registry's decision for its host, its per-tool allow and deny lists, and the tools it listed through the gateway (name and risk class only). No credential of an upstream is stored.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.list_servers()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">put_server</a>(...) -> McpGatewayServer</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The caller chooses the identifier of a new server (a product identifier) and sends If-Match "0"; a change sends the version it read. The upstream address is an https URL on the default port with no credentials, query or fragment, and its host must be a public name: the gateway connects to public addresses only, checked at every connection. BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both. The change is audited.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.put_server(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    name="name",
    upstream_url="upstream_url",
    enabled=True,
    allowed_tools=[
        "allowed_tools"
    ],
    denied_tools=[
        "denied_tools"
    ],
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**name:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**upstream_url:** `str` — An https URL on the default port with a public host, no credentials, no query and no fragment.
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**allowed_tools:** `typing.List[McpGatewayToolName]` 
    
</dd>
</dl>

<dl>
<dd>

**denied_tools:** `typing.List[McpGatewayToolName]` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">delete_server</a>(...)</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Removes the server and the tools it listed; its decision records stay. If-Match names the version the caller read. BrowserSession requests require the same-origin Origin and CSRF headers; ProductAPIToken requests omit both.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.delete_server(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="src/zasp/gateway/client.py">list_activity</a>(...) -> GatewayDecisionPage</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The decisions of the MCP gateway and of the model proxy, newest first. A record holds the decision, a reason, the matched rule identifiers with their modes and counts, the size and SHA-256 digest of the request or response body, and identifiers (server, tool, provider, model, agent). It never holds a prompt, an argument, a tool result or an answer.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway.list_activity()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**surface:** `typing.Optional[ListActivityGatewayRequestSurface]` 
    
</dd>
</dl>

<dl>
<dd>

**server_id:** `typing.Optional[ProductId]` 
    
</dd>
</dl>

<dl>
<dd>

**agent_id:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**decision:** `typing.Optional[ListActivityGatewayRequestDecision]` 
    
</dd>
</dl>

<dl>
<dd>

**before:** `typing.Optional[ProductId]` — The next_cursor of the page before.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## GatewayTraffic
<details><summary><code>client.gateway_traffic.<a href="src/zasp/gateway_traffic/client.py">call_mcp</a>(...) -> GatewayJsonrpcMessage</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The MCP Streamable HTTP endpoint of a registered server: an agent's MCP configuration names this address instead of the server's own and sends an API token that has the use_gateway permission. The body is a single JSON-RPC 2.0 message (no batches). The gateway forwards it to the registered upstream with the session and protocol headers of the transport (MCP-Session-Id, MCP-Protocol-Version, Mcp-Method, Mcp-Name) and answers with one JSON-RPC message, a stream of server-sent events, or 202 for a notification. Under the Environment's policy a blocked or (by policy) unapproved server is refused with 403; tools/list hides the tools the policy denies and tools whose description carries an injected instruction; tools/call is refused for a denied tool, and its arguments and result go through the guardrail detectors (a blocked call or result is answered as a failed tool call, isError true). GET is not offered (405), so messages a server starts outside a request are not delivered. Only decisions are recorded, never arguments or results.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway_traffic.call_mcp(
    id="id",
    jsonrpc="2.0",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**request:** `GatewayJsonrpcMessage` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_authorization:** `typing.Optional[str]` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zasp_agent_id:** `typing.Optional[str]` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway_traffic.<a href="src/zasp/gateway_traffic/client.py">close_mcp_session</a>(...)</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Forwards the transport's session end (HTTP DELETE with MCP-Session-Id) to the registered upstream and returns its status.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway_traffic.close_mcp_session(
    id="id",
    mcp_session_id="MCP-Session-Id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**mcp_session_id:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_authorization:** `typing.Optional[str]` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zasp_agent_id:** `typing.Optional[str]` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway_traffic.<a href="src/zasp/gateway_traffic/client.py">create_chat_completion</a>(...) -> GatewayProviderBody</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

A chat completion in the widely used chat completions format: point the SDK's base URL at <origin>/api/v1/gateway/llm/v1, use an API token that has the use_gateway permission as the SDK's key, and send the provider's own key in X-Zasp-Upstream-Authorization. The provider's key is forwarded for this request only and is never stored or logged. The Environment's guardrail policy is applied to the messages (a blocked prompt is refused with 400, code guardrail_blocked; sensitive data is redacted before the provider sees it) and to the answer, streamed answers included: a stream is searched through a window that never releases part of a match, and a blocked stream ends with an error event. The request and the answer are otherwise the provider's. Only decisions are recorded, never text.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway_traffic.create_chat_completion(
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request:** `GatewayProviderBody` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_authorization:** `typing.Optional[str]` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_provider:** `typing.Optional[str]` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_host:** `typing.Optional[str]` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zasp_agent_id:** `typing.Optional[str]` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway_traffic.<a href="src/zasp/gateway_traffic/client.py">create_response</a>(...) -> GatewayProviderBody</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The responses format through the proxy, on the same terms as a chat completion. The input items, function call outputs among them, and the output text and function call arguments go through the guardrail detectors.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway_traffic.create_response(
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request:** `GatewayProviderBody` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_authorization:** `typing.Optional[str]` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_provider:** `typing.Optional[str]` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_host:** `typing.Optional[str]` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zasp_agent_id:** `typing.Optional[str]` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway_traffic.<a href="src/zasp/gateway_traffic/client.py">create_message</a>(...) -> GatewayProviderBody</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The messages format through the proxy: point the SDK's base URL at <origin>/api/v1/gateway/llm, send an API token that has the use_gateway permission as the bearer token, and the provider's own key in X-Zasp-Upstream-Authorization (a plain HTTP client may send it in x-api-key instead). anthropic-version and anthropic-beta are forwarded. The messages, tool results among them, and the answer's text and tool inputs go through the guardrail detectors; thinking blocks are passed unchanged.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.gateway_traffic.create_message(
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request:** `GatewayProviderBody` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_authorization:** `typing.Optional[str]` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zasp_upstream_provider:** `typing.Optional[str]` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zasp_agent_id:** `typing.Optional[str]` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Agents
<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">list</a>(...) -> InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">get</a>(...) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">update</a>(...) -> AgentMutation</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the shared CSRF header and a same-origin Origin. ProductAPIToken requests omit the browser-only header at transport time; OpenAPI cannot conditionally require a parameter by security alternative.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.update(
    id="id",
    if_match="If-Match",
    owner="owner",
    team="team",
    tags=[
        "tags"
    ],
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**owner:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**team:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**tags:** `typing.List[str]` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">list_capabilities</a>(...) -> CapabilityPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.list_capabilities(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">list_relationships</a>(...) -> RelationshipPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.list_relationships(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">get_evidence_pack</a>(...) -> AgentEvidencePackResponse</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

One document with how the agent was found, its findings with their framework references, the Security Agent runs on those findings with their approvals, and the red team definitions and runs that target it, plus a Markdown rendering. The pack is composed from the product's own read operations, each read as the caller, so it holds nothing the caller could not read one request at a time. A part the caller may not read is marked not_permitted, a part read only with a browser session is marked browser_session_required for an API token, and a part that reaches its bound is marked truncated. It is a synchronous read and nothing is stored - there is no retention and no download grant.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.get_evidence_pack(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**format:** `typing.Optional[GetEvidencePackAgentsRequestFormat]` — json (default) returns the document and its rendering; markdown returns the rendering alone as a download.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">list_sessions</a>(...) -> AgentSessionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.list_sessions(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="src/zasp/agents/client.py">get_access</a>(...) -> AgentAccess</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The model and agent actions the policies of the Agent's role grant against the ones the audit log showed in use, the MCP servers it uses with the registry's decision for each, the data stores the identities it runs as reach, and the skills and instruction files of its repository (path and kind only). ai_actions is null when the role's audit log was not read.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.agents.get_access(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Policies
<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">list</a>(...) -> PolicyPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">create</a>(...) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, PolicyCondition

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.create(
    idempotency_key="Idempotency-Key",
    id="id",
    name="name",
    scope="environment",
    trigger="trigger",
    conditions=[
        PolicyCondition(
            field="field",
            operator="equals",
            value="value",
        )
    ],
    action="monitor",
    rollout="draft",
    failure_mode="open",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Policy` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">get</a>(...) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">delete</a>(...)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.delete(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">update</a>(...) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, PolicyCondition

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.update(
    id_="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    id="id",
    name="name",
    scope="environment",
    trigger="trigger",
    conditions=[
        PolicyCondition(
            field="field",
            operator="equals",
            value="value",
        )
    ],
    action="monitor",
    rollout="draft",
    failure_mode="open",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Policy` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">rollout</a>(...) -> PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.rollout(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    state="monitor",
    target_id="target_id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `PolicyRolloutInput` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">simulate</a>(...) -> PolicySimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.simulate(
    id="id",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**request:** `PolicySimulationInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">list_decisions</a>(...) -> RuntimeDecisionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.list_decisions(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="src/zasp/policies/client.py">disable</a>(...) -> PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.policies.disable(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    request={
        "key": "value"
    },
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `PolicyId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `EmptyInput` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## MCP servers
<details><summary><code>client.mcp_servers.<a href="src/zasp/mcp_servers/client.py">list</a>(...) -> McpServerPage</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

One record per MCP server found without installing anything: an AgentCore gateway, a remote server an AWS account's network logs or a gateway target name, a server a repository's configuration declares, a Kubernetes workload that runs one, and a server a SaaS platform lists. Each carries the tools its declaration names, with a risk class from a catalog of name patterns, the agents that use it, and the registry's decision for its identity. No environment value, header, argument, URL path or tool description is stored.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.mcp_servers.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcp_servers.<a href="src/zasp/mcp_servers/client.py">list_registry</a>() -> McpRegistryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.mcp_servers.list_registry()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcp_servers.<a href="src/zasp/mcp_servers/client.py">put_registry_entry</a>(...) -> McpRegistryEntry</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

status unapproved removes the decision. expected_version is the version last read (0 when the identity has no decision). The posture findings of the Environment are refreshed in the same transaction: an agent that uses a blocked or unapproved server has a finding, and an approved one does not.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.mcp_servers.put_registry_entry(
    identity="identity",
    status="approved",
    note="note",
    expected_version=1,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**identity:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `McpRegistryInputStatus` 
    
</dd>
</dl>

<dl>
<dd>

**note:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**expected_version:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Identities
<details><summary><code>client.identities.<a href="src/zasp/identities/client.py">list</a>(...) -> InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.identities.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.identities.<a href="src/zasp/identities/client.py">get</a>(...) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.identities.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Runtimes
<details><summary><code>client.runtimes.<a href="src/zasp/runtimes/client.py">list</a>(...) -> InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.runtimes.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.runtimes.<a href="src/zasp/runtimes/client.py">get</a>(...) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.runtimes.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Assets
<details><summary><code>client.assets.<a href="src/zasp/assets/client.py">get</a>(...) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.assets.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Findings
<details><summary><code>client.findings.<a href="src/zasp/findings/client.py">list</a>(...) -> FindingPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.findings.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="src/zasp/findings/client.py">get</a>(...) -> Finding</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.findings.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="src/zasp/findings/client.py">update</a>(...) -> Finding</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the shared CSRF header and a same-origin Origin. ProductAPIToken requests omit the browser-only header at transport time; OpenAPI cannot conditionally require a parameter by security alternative.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.findings.update(
    id="id",
    if_match="If-Match",
    status="open",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `FindingUpdateInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="src/zasp/findings/client.py">accept_risk</a>(...) -> Finding</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the shared CSRF header and a same-origin Origin. ProductAPIToken requests omit the browser-only header at transport time; OpenAPI cannot conditionally require a parameter by security alternative.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.findings.accept_risk(
    id="id",
    if_match="If-Match",
    reason="reason",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `FindingAcceptanceInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="src/zasp/findings/client.py">create_ticket</a>(...) -> FindingTicket</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

BrowserSession requests require the shared CSRF header and a same-origin Origin. ProductAPIToken requests omit the browser-only header at transport time. The destination comes only from the scope's active Generic Webhook integration.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.findings.create_ticket(
    id="id",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack paths
<details><summary><code>client.attack_paths.<a href="src/zasp/attack_paths/client.py">list</a>(...) -> AttackPathPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_paths.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_paths.<a href="src/zasp/attack_paths/client.py">get</a>(...) -> AttackPath</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_paths.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_paths.<a href="src/zasp/attack_paths/client.py">get_break_options</a>(...) -> BreakOptionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_paths.get_break_options(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Search
<details><summary><code>client.search.<a href="src/zasp/search/client.py">query</a>(...) -> SearchResultPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.search.query(
    q="q",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**q:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agents
<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">list_templates</a>() -> SecurityAgentTemplatePage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.list_templates()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">list_actions</a>() -> SecurityActionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.list_actions()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">list</a>(...) -> SecurityAgentPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[Cursor]` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` — Maximum number of records to return.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">create</a>(...) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.create(
    idempotency_key="Idempotency-Key",
    name="name",
    trigger_kind="finding",
    trigger_source="trigger_source",
    environment_ids=[
        "environment_ids"
    ],
    autonomy="supervised",
    max_steps=1,
    max_duration_seconds=1,
    temporary_policy_seconds=1,
    ai_token_budget=1,
    concurrency_limit=1,
    allowed_actions=[
        "allowed_actions"
    ],
    verification_kind="verification_kind",
    definition_version=1,
    enabled=True,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentInput` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">get</a>(...) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">delete</a>(...)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.delete(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">update</a>(...) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.update(
    id_="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    id="id",
    name="name",
    trigger_kind="finding",
    trigger_source="trigger_source",
    environment_ids=[
        "environment_ids"
    ],
    autonomy="supervised",
    max_steps=1,
    max_duration_seconds=1,
    temporary_policy_seconds=1,
    ai_token_budget=1,
    concurrency_limit=1,
    allowed_actions=[
        "allowed_actions"
    ],
    verification_kind="verification_kind",
    definition_version=1,
    enabled=True,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentDefinition` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">get_activation</a>(...) -> SecurityAgentActivationState</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.get_activation(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">simulate</a>(...) -> SecurityAgentSimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.simulate(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    goal="goal",
    environment_id="environment_id",
    evidence_ids=[
        "evidence_ids"
    ],
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**goal:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**environment_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**evidence_ids:** `typing.List[ProductId]` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agents.<a href="src/zasp/security_agents/client.py">run</a>(...) -> SecurityAgentRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, SecurityAgentLegacyTriggerInput

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agents.run(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    request=SecurityAgentLegacyTriggerInput(
        environment_id="environment_id",
    ),
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentManualRunInput` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent runs
<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">list</a>(...) -> SecurityAgentRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**agent_id:** `typing.Optional[ProductId]` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `typing.Optional[SecurityAgentRunState]` 
    
</dd>
</dl>

<dl>
<dd>

**environment_id:** `typing.Optional[ProductId]` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">get</a>(...) -> SecurityAgentRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_budget_details:** `typing.Optional[str]` — Request optional budget_stop_reason details with v1. Omitted or unsupported values preserve the legacy response shape. Older servers may omit the reason even when requested.
    
</dd>
</dl>

<dl>
<dd>

**zasp_run_context:** `typing.Optional[str]` — Request optional trigger and redacted AI rationale with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit run_context.
    
</dd>
</dl>

<dl>
<dd>

**zasp_action_details:** `typing.Optional[str]` — Request optional persisted action details with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit action_details. Independent of budget and run-context negotiation.
    
</dd>
</dl>

<dl>
<dd>

**zasp_run_lifecycle:** `typing.Optional[str]` — Request the optional stop_reason and closure with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit both. Independent of the other negotiations.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">cancel</a>(...) -> SecurityAgentCancellation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.cancel(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">close</a>(...) -> SecurityAgentRunClosed</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Records that a human reviewed a run in the needs_human state and closed it. Requires manage_workflows on the run. The run keeps its state, version and recorded stop reason; the closure is an immutable record and an audit event. A closed run no longer holds its agent's capacity for a planner request whose usage is still unknown, and that usage stays recorded as unknown, never as zero. A run with an unknown planner outcome can be closed only with the reason usage_unknown_accepted; a run without one only with one of the other reasons. A run with an unfinished effect, cleanup or temporary control cannot be closed. An exact replay returns the first answer; any other request for a closed run conflicts.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.close(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    reason="no_action_required",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**reason:** `SecurityAgentRunCloseReason` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**note:** `typing.Optional[str]` — Optional single-line justification kept with the closure and its audit event.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">get_cleanup_recovery</a>(...) -> SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.get_cleanup_recovery(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_runs.<a href="src/zasp/security_agent_runs/client.py">request_cleanup_recovery</a>(...) -> SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_runs.request_cleanup_recovery(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    definition_version=1,
    input_digest="input_digest",
    diagnostic="history_unavailable",
    stop_original="stop_original",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**definition_version:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**input_digest:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**diagnostic:** `RequestCleanupRecoverySecurityAgentRunsRequestDiagnostic` 
    
</dd>
</dl>

<dl>
<dd>

**stop_original:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent approvals
<details><summary><code>client.security_agent_approvals.<a href="src/zasp/security_agent_approvals/client.py">list</a>(...) -> SecurityAgentApprovalPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_approvals.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**state:** `typing.Optional[ListSecurityAgentApprovalsRequestState]` 
    
</dd>
</dl>

<dl>
<dd>

**run_id:** `typing.Optional[ProductId]` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_approval_context:** `typing.Optional[str]` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.security_agent_approvals.<a href="src/zasp/security_agent_approvals/client.py">get</a>(...) -> SecurityAgentApproval</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.security_agent_approvals.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**zasp_approval_context:** `typing.Optional[str]` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Home
<details><summary><code>client.home.<a href="src/zasp/home/client.py">get_summary</a>() -> HomeSummary</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.home.get_summary()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Recovery
<details><summary><code>client.recovery.<a href="src/zasp/recovery/client.py">start_backup</a>(...) -> RecoveryBackup</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires fresh human authentication or a scoped ProductAPIToken. The accepted job drains only the authenticated organization, workspace, and environment before publishing a signed, version-pinned manifest.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.recovery.start_backup(
    zasp_fresh_auth="confirmed",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    backup_id="backup_id",
    retention_days=1,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**zasp_fresh_auth:** `StartBackupRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**backup_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**retention_days:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="src/zasp/recovery/client.py">get_backup</a>(...) -> RecoveryBackup</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.recovery.get_backup(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="src/zasp/recovery/client.py">start_restore</a>(...) -> RecoveryRestore</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Requires fresh human authentication or a scoped ProductAPIToken. Restore is accepted only into a distinct, non-production target and from the exact signed manifest locator returned by the authenticated tenant's backup authority.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, RecoveryManifestLocator

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.recovery.start_restore(
    zasp_fresh_auth="confirmed",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    restore_id="restore_id",
    target_environment="target_environment",
    manifest=RecoveryManifestLocator(
        reference="reference",
        version_id="version_id",
        sha256="sha256",
        size_bytes=1,
        media_type="application/vnd.zasp.recovery-manifest+json",
        schema="recovery_signed_manifest_v1",
        signing_key_id="signing_key_id",
        signature="signature",
    ),
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**zasp_fresh_auth:** `StartRestoreRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**restore_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**target_environment:** `RecoveryTargetEnvironment` 
    
</dd>
</dl>

<dl>
<dd>

**manifest:** `RecoveryManifestLocator` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="src/zasp/recovery/client.py">get_restore</a>(...) -> RecoveryRestore</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.recovery.get_restore(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tests
<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">list</a>(...) -> TestDefinitionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">create</a>(...) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, SafetyMetadata

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.create(
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    id="id",
    name="name",
    target_id="target_id",
    target_kind="agent_endpoint",
    categories=[
        "prompt_injection"
    ],
    safety=SafetyMetadata(
        environment="development",
        credential_class="read_only",
        expected_side_effects=[
            "expected_side_effects"
        ],
    ),
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**name:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**target_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**target_kind:** `TestDefinitionInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `typing.List[TestDefinitionInputCategoriesItem]` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `SafetyMetadata` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">get</a>(...) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">update</a>(...) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp, SafetyMetadata

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.update(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    name="name",
    target_id="target_id",
    target_kind="agent_endpoint",
    categories=[
        "prompt_injection"
    ],
    safety=SafetyMetadata(
        environment="development",
        credential_class="read_only",
        expected_side_effects=[
            "expected_side_effects"
        ],
    ),
    enabled=True,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**target_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**target_kind:** `TestDefinitionUpdateInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `typing.List[TestDefinitionUpdateInputCategoriesItem]` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `SafetyMetadata` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">get_schedule</a>(...) -> TestSchedule</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

A definition without a saved schedule answers with version 0 and enabled false.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.get_schedule(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">put_schedule</a>(...) -> TestSchedule</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

The schedule re-runs the definition on a cadence, when the inventory record of its target changes, or both. It can be enabled only for an enabled definition that passes the non-production safety rule, which is checked again before every scheduled run. expected_version is the version last read (0 when none was saved).
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.put_schedule(
    id="id",
    expected_version=1,
    enabled=True,
    on_target_change=True,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**expected_version:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**on_target_change:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**cadence_seconds:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">run</a>(...) -> TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.run(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    run_id="run_id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**run_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="src/zasp/tests/client.py">get_probe_catalog</a>() -> TestProbeCatalog</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Counts, techniques and framework tags per category of the reviewed probe library built into this release. Probe text is never returned.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.tests.get_probe_catalog()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## TestRuns
<details><summary><code>client.test_runs.<a href="src/zasp/test_runs/client.py">list</a>(...) -> TestRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.test_runs.list()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.test_runs.<a href="src/zasp/test_runs/client.py">get</a>(...) -> TestRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.test_runs.get(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.test_runs.<a href="src/zasp/test_runs/client.py">cancel</a>(...) -> TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.test_runs.cancel(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack lab
<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">preflight</a>(...) -> AttackLabPreflight</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Returns only redacted source, target, environment, credential class, destination, success criterion, side-effect, and sandbox-limit authority. Run creation independently revalidates the same durable authority and fails closed on drift.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.preflight(
    source_run_id="source_run_id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**source_run_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">list_runs</a>(...) -> AttackLabRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.list_runs()

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**cursor:** `typing.Optional[str]` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `typing.Optional[int]` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">create_run</a>(...) -> AttackLabRun</code></summary>
<dl>
<dd>

#### 📝 Description

<dl>
<dd>

<dl>
<dd>

Target, environment, credential class, destination, success criterion, and sandbox limits are derived from durable tenant authority. BrowserSession requests require the shared CSRF header and a same-origin Origin.
</dd>
</dl>
</dd>
</dl>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.create_run(
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    run_id="run_id",
    source_run_id="source_run_id",
    decision_digest="decision_digest",
    approved=True,
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**run_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**source_run_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**decision_digest:** `str` 
    
</dd>
</dl>

<dl>
<dd>

**approved:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">get_run</a>(...) -> AttackLabRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.get_run(
    id="id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">cancel_run</a>(...) -> AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.cancel_run(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attack_lab.<a href="src/zasp/attack_lab/client.py">rerun_run</a>(...) -> AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```python
from zasp import Zasp

client = Zasp(
    token="<token>",
    base_url="https://yourhost.com/path/to/api",
)

client.attack_lab.rerun_run(
    id="id",
    idempotency_key="Idempotency-Key",
    if_match="If-Match",
    run_id="run_id",
)

```
</dd>
</dl>
</dd>
</dl>

#### ⚙️ Parameters

<dl>
<dd>

<dl>
<dd>

**id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**idempotency_key:** `str` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**if_match:** `str` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**run_id:** `ProductId` 
    
</dd>
</dl>

<dl>
<dd>

**csrf_token:** `typing.Optional[str]` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request_options:** `typing.Optional[RequestOptions]` — Request-specific configuration.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

