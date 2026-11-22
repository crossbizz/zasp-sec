# Reference
## Organization
<details><summary><code>client.organization.<a href="/src/api/resources/organization/client/Client.ts">getCurrentPrincipal</a>() -> Zasp.Principal</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.organization.getCurrentPrincipal();

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

**requestOptions:** `OrganizationClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Integrations
<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">listCatalog</a>({ ...params }) -> Zasp.IntegrationCatalogPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.listCatalog();

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

**request:** `Zasp.ListCatalogIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.Integration, Zasp.IntegrationPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.integrations.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.integrations.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">create</a>({ ...params }) -> Zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.create({
    "Idempotency-Key": "Idempotency-Key",
    body: {
        connector_key: "connector_key",
        name: "name",
        configuration: {
            "key": "value"
        }
    }
});

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

**request:** `Zasp.CreateIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">get</a>({ ...params }) -> Zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.get({
    id: "id"
});

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

**request:** `Zasp.GetIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">delete</a>({ ...params }) -> Zasp.Integration | undefined</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.delete({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeleteIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">update</a>({ ...params }) -> Zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.update({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        name: "name",
        configuration: {
            "key": "value"
        }
    }
});

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

**request:** `Zasp.UpdateIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">sync</a>({ ...params }) -> Zasp.IntegrationSync</code></summary>
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

```typescript
await client.integrations.sync({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.SyncIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">listSyncs</a>({ ...params }) -> core.Page&lt;Zasp.IntegrationSync, Zasp.IntegrationSyncPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.integrations.listSyncs({
    id: "id"
});
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.integrations.listSyncs({
    id: "id"
});
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSyncsIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getSync</a>({ ...params }) -> Zasp.IntegrationSync</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.getSync({
    id: "id",
    syncId: "syncId"
});

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

**request:** `Zasp.GetSyncIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getSchedule</a>({ ...params }) -> Zasp.IntegrationSchedule</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.getSchedule({
    id: "id"
});

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

**request:** `Zasp.GetScheduleIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">putSchedule</a>({ ...params }) -> Zasp.IntegrationSchedule</code></summary>
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

```typescript
await client.integrations.putSchedule({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        cadence_seconds: 1,
        state: "enabled"
    }
});

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

**request:** `Zasp.PutScheduleIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">deleteSchedule</a>({ ...params }) -> void</code></summary>
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

```typescript
await client.integrations.deleteSchedule({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeleteScheduleIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getFreshness</a>({ ...params }) -> Zasp.IntegrationFreshness</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.integrations.getFreshness({
    id: "id"
});

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

**request:** `Zasp.GetFreshnessIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getSetupStatus</a>({ ...params }) -> Zasp.IntegrationSetupStatus</code></summary>
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

```typescript
await client.integrations.getSetupStatus({
    id: "id"
});

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

**request:** `Zasp.GetSetupStatusIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getRemediationRole</a>({ ...params }) -> Zasp.IntegrationRemediationRole</code></summary>
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

```typescript
await client.integrations.getRemediationRole({
    id: "id"
});

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

**request:** `Zasp.GetRemediationRoleIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">putRemediationRole</a>({ ...params }) -> Zasp.IntegrationRemediationRole</code></summary>
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

```typescript
await client.integrations.putRemediationRole({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    role_arn: ""
});

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

**request:** `Zasp.IntegrationRemediationRoleInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">testWebhook</a>({ ...params }) -> Zasp.IntegrationWebhookTestStatus</code></summary>
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

```typescript
await client.integrations.testWebhook({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.TestWebhookIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.<a href="/src/api/resources/integrations/client/Client.ts">getWebhookStatus</a>({ ...params }) -> Zasp.IntegrationWebhookTestStatus</code></summary>
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

```typescript
await client.integrations.getWebhookStatus({
    id: "id"
});

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

**request:** `Zasp.GetWebhookStatusIntegrationsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IntegrationsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Sensors
<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">fetchEndpointPolicy</a>({ ...params }) -> Zasp.EndpointBundle</code></summary>
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

```typescript
await client.sensors.fetchEndpointPolicy({
    "X-Zasp-Device-Proof": "X-Zasp-Device-Proof",
    "X-Zasp-Device-Signature": "X-Zasp-Device-Signature",
    id: "id"
});

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

**request:** `Zasp.FetchEndpointPolicySensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">exchangeEndpointEnrollment</a>({ ...params }) -> Zasp.EndpointExchangeReceipt</code></summary>
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

```typescript
await client.sensors.exchangeEndpointEnrollment({
    "X-Zasp-Device-Proof": "X-Zasp-Device-Proof",
    "X-Zasp-Device-Signature": "X-Zasp-Device-Signature",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.ExchangeEndpointEnrollmentSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">recordEndpointHeartbeat</a>({ ...params }) -> Zasp.EndpointRecorded</code></summary>
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

```typescript
await client.sensors.recordEndpointHeartbeat({
    "X-Zasp-Device-Proof": "X-Zasp-Device-Proof",
    "X-Zasp-Device-Signature": "X-Zasp-Device-Signature",
    id: "id",
    policy_revision: 1,
    policy_status: "verified_cache",
    queued_receipts: 1,
    dropped_receipts: 1
});

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

**request:** `Zasp.EndpointHeartbeat` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">recordEndpointInventory</a>({ ...params }) -> Zasp.EndpointRecorded</code></summary>
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

```typescript
await client.sensors.recordEndpointInventory({
    "X-Zasp-Device-Proof": "X-Zasp-Device-Proof",
    "X-Zasp-Device-Signature": "X-Zasp-Device-Signature",
    id: "id",
    partition_id: "partition_id",
    snapshot_generation: 1,
    complete: true,
    installations: [{
            installation_id: "installation_id"
        }]
});

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

**request:** `Zasp.EndpointSnapshot` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">recordEndpointObservations</a>({ ...params }) -> Zasp.EndpointRecorded</code></summary>
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

```typescript
await client.sensors.recordEndpointObservations({
    "X-Zasp-Device-Proof": "X-Zasp-Device-Proof",
    "X-Zasp-Device-Signature": "X-Zasp-Device-Signature",
    receipts: [{
            payload: "payload",
            signature: "signature"
        }]
});

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

**request:** `Zasp.EndpointObservationBatch` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.Sensor, Zasp.SensorPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.sensors.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.sensors.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">createEnrollment</a>({ ...params }) -> Zasp.SensorEnrollment</code></summary>
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

```typescript
await client.sensors.createEnrollment({
    "Idempotency-Key": "Idempotency-Key",
    "X-Zasp-Fresh-Auth": "confirmed",
    name: "name",
    kind: "tetragon",
    mode: "metadata_only"
});

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

**request:** `Zasp.SensorInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">get</a>({ ...params }) -> Zasp.Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.sensors.get({
    id: "id"
});

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

**request:** `Zasp.GetSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">delete</a>({ ...params }) -> void</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.sensors.delete({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeleteSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">update</a>({ ...params }) -> Zasp.Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.sensors.update({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    name: "name",
    mode: "metadata_only"
});

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

**request:** `Zasp.SensorUpdateInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">rotateToken</a>({ ...params }) -> Zasp.SensorEnrollment</code></summary>
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

```typescript
await client.sensors.rotateToken({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    "X-Zasp-Fresh-Auth": "confirmed",
    id: "id",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.RotateTokenSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">getCoverage</a>({ ...params }) -> Zasp.SensorCoverage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.sensors.getCoverage({
    id: "id"
});

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

**request:** `Zasp.GetCoverageSensorsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.<a href="/src/api/resources/sensors/client/Client.ts">recordBrowserOriginDays</a>({ ...params }) -> Zasp.BrowserOriginAck</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.sensors.recordBrowserOriginDays({
    id: "id",
    issued_at: 1000000,
    nonce: "nonce",
    days: [{
            origin: "https://claude.ai",
            day: "2023-01-15"
        }],
    signature: "signature"
});

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

**request:** `Zasp.BrowserOriginReport` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SensorsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Guardrails
<details><summary><code>client.guardrails.<a href="/src/api/resources/guardrails/client/Client.ts">decideAction</a>({ ...params }) -> Zasp.WorkloadActionDecision</code></summary>
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

```typescript
await client.guardrails.decideAction({
    "Idempotency-Key": "Idempotency-Key",
    schema_version: "action.v1",
    action_id: "action_id",
    action_kind: "tool_call",
    operation: "operation",
    resource: {
        kind: "kind",
        classification: "classification"
    }
});

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

**request:** `Zasp.WorkloadActionRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GuardrailsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="/src/api/resources/guardrails/client/Client.ts">recordActionOutcome</a>({ ...params }) -> Zasp.WorkloadOutcomeAck</code></summary>
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

```typescript
await client.guardrails.recordActionOutcome({
    "Idempotency-Key": "Idempotency-Key",
    pathActionId: "actionId",
    schema_version: "action-outcome.v1",
    action_id: "action_id",
    decision_id: "decision_id",
    status: "not_dispatched"
});

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

**request:** `Zasp.WorkloadActionOutcome` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GuardrailsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="/src/api/resources/guardrails/client/Client.ts">createDecision</a>({ ...params }) -> Zasp.GuardrailDecision</code></summary>
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

```typescript
await client.guardrails.createDecision({
    direction: "input",
    text: "text"
});

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

**request:** `Zasp.GuardrailInteraction` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GuardrailsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="/src/api/resources/guardrails/client/Client.ts">getPolicy</a>() -> Zasp.GuardrailPolicy</code></summary>
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

```typescript
await client.guardrails.getPolicy();

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

**requestOptions:** `GuardrailsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.<a href="/src/api/resources/guardrails/client/Client.ts">putPolicy</a>({ ...params }) -> Zasp.GuardrailPolicy</code></summary>
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

```typescript
await client.guardrails.putPolicy({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    rules: {
        "key": "block"
    }
});

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

**request:** `Zasp.GuardrailPolicyInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GuardrailsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tools
<details><summary><code>client.tools.<a href="/src/api/resources/tools/client/Client.ts">attestAddonScan</a>({ ...params }) -> Zasp.AddonCiReceipt</code></summary>
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

```typescript
await client.tools.attestAddonScan({
    id: "id",
    key_id: "key_id",
    repository: "repository",
    commit: "commit",
    signature: "signature"
});

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

**request:** `Zasp.AddonCiSignature` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `ToolsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="/src/api/resources/tools/client/Client.ts">submitAddonScan</a>({ ...params }) -> Zasp.AddonScanReceipt</code></summary>
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

```typescript
await client.tools.submitAddonScan({
    "Idempotency-Key": "Idempotency-Key",
    environment_id: "environment_id",
    schema_version: "zasp-addon-findings.v1",
    ruleset: "zasp-static.v1",
    manifest_method: "addon-manifest.v1",
    completeness: "complete",
    origin: "local",
    findings: [{
            rule_id: "dependency.unpinned",
            count: 1
        }],
    skipped_count: 1
});

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

**request:** `Zasp.AddonScanSubmission` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `ToolsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="/src/api/resources/tools/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.InventorySummary, Zasp.InventoryPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.tools.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.tools.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListToolsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `ToolsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.<a href="/src/api/resources/tools/client/Client.ts">get</a>({ ...params }) -> Zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.tools.get({
    id: "id"
});

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

**request:** `Zasp.GetToolsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `ToolsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Gateway
<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">getPolicy</a>() -> Zasp.GatewayPolicy</code></summary>
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

```typescript
await client.gateway.getPolicy();

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

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">putPolicy</a>({ ...params }) -> Zasp.GatewayPolicy</code></summary>
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

```typescript
await client.gateway.putPolicy({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    unapproved_servers: "allow",
    denied_tool_risks: ["execute"],
    requests_per_minute: 1
});

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

**request:** `Zasp.GatewayPolicyInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">listServers</a>() -> Zasp.McpGatewayServerList</code></summary>
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

```typescript
await client.gateway.listServers();

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

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">putServer</a>({ ...params }) -> Zasp.McpGatewayServer</code></summary>
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

```typescript
await client.gateway.putServer({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    name: "name",
    upstream_url: "upstream_url",
    enabled: true,
    allowed_tools: ["allowed_tools"],
    denied_tools: ["denied_tools"]
});

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

**request:** `Zasp.McpGatewayServerInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">deleteServer</a>({ ...params }) -> void</code></summary>
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

```typescript
await client.gateway.deleteServer({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeleteServerGatewayRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.<a href="/src/api/resources/gateway/client/Client.ts">listActivity</a>({ ...params }) -> core.Page&lt;Zasp.GatewayDecision, Zasp.GatewayDecisionPage&gt;</code></summary>
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

```typescript
const pageableResponse = await client.gateway.listActivity();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.gateway.listActivity();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListActivityGatewayRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## GatewayTraffic
<details><summary><code>client.gatewayTraffic.<a href="/src/api/resources/gatewayTraffic/client/Client.ts">callMcp</a>({ ...params }) -> Zasp.GatewayJsonrpcMessage</code></summary>
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

```typescript
await client.gatewayTraffic.callMcp({
    id: "id",
    body: {
        jsonrpc: "2.0"
    }
});

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

**request:** `Zasp.CallMcpGatewayTrafficRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayTrafficClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.<a href="/src/api/resources/gatewayTraffic/client/Client.ts">closeMcpSession</a>({ ...params }) -> void</code></summary>
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

```typescript
await client.gatewayTraffic.closeMcpSession({
    "MCP-Session-Id": "MCP-Session-Id",
    id: "id"
});

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

**request:** `Zasp.CloseMcpSessionGatewayTrafficRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayTrafficClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.<a href="/src/api/resources/gatewayTraffic/client/Client.ts">createChatCompletion</a>({ ...params }) -> Zasp.GatewayProviderBody</code></summary>
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

```typescript
await client.gatewayTraffic.createChatCompletion({
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.CreateChatCompletionGatewayTrafficRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayTrafficClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.<a href="/src/api/resources/gatewayTraffic/client/Client.ts">createResponse</a>({ ...params }) -> Zasp.GatewayProviderBody</code></summary>
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

```typescript
await client.gatewayTraffic.createResponse({
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.CreateResponseGatewayTrafficRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayTrafficClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.<a href="/src/api/resources/gatewayTraffic/client/Client.ts">createMessage</a>({ ...params }) -> Zasp.GatewayProviderBody</code></summary>
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

```typescript
await client.gatewayTraffic.createMessage({
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.CreateMessageGatewayTrafficRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `GatewayTrafficClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Agents
<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.InventorySummary, Zasp.InventoryPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.agents.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.agents.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">get</a>({ ...params }) -> Zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.agents.get({
    id: "id"
});

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

**request:** `Zasp.GetAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">update</a>({ ...params }) -> Zasp.AgentMutation</code></summary>
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

```typescript
await client.agents.update({
    "If-Match": "If-Match",
    id: "id",
    owner: "owner",
    team: "team",
    tags: ["tags"]
});

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

**request:** `Zasp.AgentOwnershipInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">listCapabilities</a>({ ...params }) -> core.Page&lt;Zasp.Capability, Zasp.CapabilityPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.agents.listCapabilities({
    id: "id"
});
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.agents.listCapabilities({
    id: "id"
});
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListCapabilitiesAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">listRelationships</a>({ ...params }) -> core.Page&lt;Zasp.Relationship, Zasp.RelationshipPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.agents.listRelationships({
    id: "id"
});
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.agents.listRelationships({
    id: "id"
});
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListRelationshipsAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">getEvidencePack</a>({ ...params }) -> Zasp.AgentEvidencePackResponse</code></summary>
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

```typescript
await client.agents.getEvidencePack({
    id: "id"
});

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

**request:** `Zasp.GetEvidencePackAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">listSessions</a>({ ...params }) -> core.Page&lt;Zasp.AgentSession, Zasp.AgentSessionPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.agents.listSessions({
    id: "id"
});
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.agents.listSessions({
    id: "id"
});
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSessionsAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.<a href="/src/api/resources/agents/client/Client.ts">getAccess</a>({ ...params }) -> Zasp.AgentAccess</code></summary>
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

```typescript
await client.agents.getAccess({
    id: "id"
});

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

**request:** `Zasp.GetAccessAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Policies
<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.Policy, Zasp.PolicyPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.policies.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.policies.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListPoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">create</a>({ ...params }) -> Zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.create({
    "Idempotency-Key": "Idempotency-Key",
    body: {
        id: "id",
        name: "name",
        scope: "environment",
        trigger: "trigger",
        conditions: [{
                field: "field",
                operator: "equals",
                value: "value"
            }],
        action: "monitor",
        rollout: "draft",
        failure_mode: "open"
    }
});

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

**request:** `Zasp.CreatePoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">get</a>({ ...params }) -> Zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.get({
    id: "id"
});

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

**request:** `Zasp.GetPoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">delete</a>({ ...params }) -> void</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.delete({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeletePoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">update</a>({ ...params }) -> Zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.update({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        id: "id",
        name: "name",
        scope: "environment",
        trigger: "trigger",
        conditions: [{
                field: "field",
                operator: "equals",
                value: "value"
            }],
        action: "monitor",
        rollout: "draft",
        failure_mode: "open"
    }
});

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

**request:** `Zasp.UpdatePoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">rollout</a>({ ...params }) -> Zasp.PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.rollout({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        state: "monitor",
        target_id: "target_id"
    }
});

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

**request:** `Zasp.RolloutPoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">simulate</a>({ ...params }) -> Zasp.PolicySimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.simulate({
    id: "id",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.SimulatePoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">listDecisions</a>({ ...params }) -> Zasp.RuntimeDecisionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.listDecisions({
    id: "id"
});

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

**request:** `Zasp.ListDecisionsPoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.<a href="/src/api/resources/policies/client/Client.ts">disable</a>({ ...params }) -> Zasp.PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.policies.disable({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        "key": "value"
    }
});

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

**request:** `Zasp.DisablePoliciesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `PoliciesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## MCP servers
<details><summary><code>client.mcpServers.<a href="/src/api/resources/mcpServers/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.McpServer, Zasp.McpServerPage&gt;</code></summary>
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

```typescript
const pageableResponse = await client.mcpServers.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.mcpServers.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListMcpServersRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `McpServersClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcpServers.<a href="/src/api/resources/mcpServers/client/Client.ts">listRegistry</a>() -> Zasp.McpRegistryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.mcpServers.listRegistry();

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

**requestOptions:** `McpServersClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcpServers.<a href="/src/api/resources/mcpServers/client/Client.ts">putRegistryEntry</a>({ ...params }) -> Zasp.McpRegistryEntry</code></summary>
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

```typescript
await client.mcpServers.putRegistryEntry({
    identity: "identity",
    status: "approved",
    note: "note",
    expected_version: 1
});

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

**request:** `Zasp.McpRegistryInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `McpServersClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Identities
<details><summary><code>client.identities.<a href="/src/api/resources/identities/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.InventorySummary, Zasp.InventoryPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.identities.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.identities.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListIdentitiesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IdentitiesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.identities.<a href="/src/api/resources/identities/client/Client.ts">get</a>({ ...params }) -> Zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.identities.get({
    id: "id"
});

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

**request:** `Zasp.GetIdentitiesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `IdentitiesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Runtimes
<details><summary><code>client.runtimes.<a href="/src/api/resources/runtimes/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.InventorySummary, Zasp.InventoryPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.runtimes.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.runtimes.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListRuntimesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RuntimesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.runtimes.<a href="/src/api/resources/runtimes/client/Client.ts">get</a>({ ...params }) -> Zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.runtimes.get({
    id: "id"
});

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

**request:** `Zasp.GetRuntimesRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RuntimesClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Assets
<details><summary><code>client.assets.<a href="/src/api/resources/assets/client/Client.ts">get</a>({ ...params }) -> Zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.assets.get({
    id: "id"
});

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

**request:** `Zasp.GetAssetsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AssetsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Findings
<details><summary><code>client.findings.<a href="/src/api/resources/findings/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.Finding, Zasp.FindingPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.findings.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.findings.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListFindingsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `FindingsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="/src/api/resources/findings/client/Client.ts">get</a>({ ...params }) -> Zasp.Finding</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.findings.get({
    id: "id"
});

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

**request:** `Zasp.GetFindingsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `FindingsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="/src/api/resources/findings/client/Client.ts">update</a>({ ...params }) -> Zasp.Finding</code></summary>
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

```typescript
await client.findings.update({
    "If-Match": "If-Match",
    id: "id",
    body: {
        status: "open"
    }
});

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

**request:** `Zasp.UpdateFindingsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `FindingsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="/src/api/resources/findings/client/Client.ts">acceptRisk</a>({ ...params }) -> Zasp.Finding</code></summary>
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

```typescript
await client.findings.acceptRisk({
    "If-Match": "If-Match",
    id: "id",
    body: {
        reason: "reason"
    }
});

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

**request:** `Zasp.AcceptRiskFindingsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `FindingsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.<a href="/src/api/resources/findings/client/Client.ts">createTicket</a>({ ...params }) -> Zasp.FindingTicket</code></summary>
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

```typescript
await client.findings.createTicket({
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.CreateTicketFindingsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `FindingsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack paths
<details><summary><code>client.attackPaths.<a href="/src/api/resources/attackPaths/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.AttackPath, Zasp.AttackPathPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.attackPaths.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.attackPaths.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListAttackPathsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackPathsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackPaths.<a href="/src/api/resources/attackPaths/client/Client.ts">get</a>({ ...params }) -> Zasp.AttackPath</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.attackPaths.get({
    id: "id"
});

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

**request:** `Zasp.GetAttackPathsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackPathsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackPaths.<a href="/src/api/resources/attackPaths/client/Client.ts">getBreakOptions</a>({ ...params }) -> Zasp.BreakOptionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.attackPaths.getBreakOptions({
    id: "id"
});

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

**request:** `Zasp.GetBreakOptionsAttackPathsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackPathsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Search
<details><summary><code>client.search.<a href="/src/api/resources/search/client/Client.ts">query</a>({ ...params }) -> Zasp.SearchResultPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.search.query({
    q: "q"
});

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

**request:** `Zasp.QuerySearchRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SearchClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agents
<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">listTemplates</a>() -> Zasp.SecurityAgentTemplatePage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.listTemplates();

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

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">listActions</a>() -> Zasp.SecurityActionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.listActions();

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

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.SecurityAgentDefinition, Zasp.SecurityAgentPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.securityAgents.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.securityAgents.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">create</a>({ ...params }) -> Zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.create({
    "Idempotency-Key": "Idempotency-Key",
    body: {
        name: "name",
        trigger_kind: "finding",
        trigger_source: "trigger_source",
        environment_ids: ["environment_ids"],
        autonomy: "supervised",
        max_steps: 1,
        max_duration_seconds: 1,
        temporary_policy_seconds: 1,
        ai_token_budget: 1,
        concurrency_limit: 1,
        allowed_actions: ["allowed_actions"],
        verification_kind: "verification_kind",
        definition_version: 1,
        enabled: true
    }
});

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

**request:** `Zasp.CreateSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">get</a>({ ...params }) -> Zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.get({
    id: "id"
});

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

**request:** `Zasp.GetSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">delete</a>({ ...params }) -> void</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.delete({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.DeleteSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">update</a>({ ...params }) -> Zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.update({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        id: "id",
        name: "name",
        trigger_kind: "finding",
        trigger_source: "trigger_source",
        environment_ids: ["environment_ids"],
        autonomy: "supervised",
        max_steps: 1,
        max_duration_seconds: 1,
        temporary_policy_seconds: 1,
        ai_token_budget: 1,
        concurrency_limit: 1,
        allowed_actions: ["allowed_actions"],
        verification_kind: "verification_kind",
        definition_version: 1,
        enabled: true
    }
});

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

**request:** `Zasp.UpdateSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">getActivation</a>({ ...params }) -> Zasp.SecurityAgentActivationState</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.getActivation({
    id: "id"
});

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

**request:** `Zasp.GetActivationSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">simulate</a>({ ...params }) -> Zasp.SecurityAgentSimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.simulate({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    goal: "goal",
    environment_id: "environment_id",
    evidence_ids: ["evidence_ids"]
});

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

**request:** `Zasp.SecurityAgentSimulationInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.<a href="/src/api/resources/securityAgents/client/Client.ts">run</a>({ ...params }) -> Zasp.SecurityAgentRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgents.run({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    body: {
        environment_id: "environment_id"
    }
});

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

**request:** `Zasp.RunSecurityAgentsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent runs
<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.SecurityAgentRun, Zasp.SecurityAgentRunPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.securityAgentRuns.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.securityAgentRuns.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSecurityAgentRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">get</a>({ ...params }) -> Zasp.SecurityAgentRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgentRuns.get({
    id: "id"
});

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

**request:** `Zasp.GetSecurityAgentRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">cancel</a>({ ...params }) -> Zasp.SecurityAgentCancellation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgentRuns.cancel({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.CancelSecurityAgentRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">close</a>({ ...params }) -> Zasp.SecurityAgentRunClosed</code></summary>
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

```typescript
await client.securityAgentRuns.close({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    reason: "no_action_required"
});

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

**request:** `Zasp.SecurityAgentRunCloseRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">getCleanupRecovery</a>({ ...params }) -> Zasp.SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgentRuns.getCleanupRecovery({
    id: "id"
});

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

**request:** `Zasp.GetCleanupRecoverySecurityAgentRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.<a href="/src/api/resources/securityAgentRuns/client/Client.ts">requestCleanupRecovery</a>({ ...params }) -> Zasp.SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgentRuns.requestCleanupRecovery({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    definition_version: 1,
    input_digest: "input_digest",
    diagnostic: "history_unavailable",
    stop_original: "stop_original"
});

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

**request:** `Zasp.RequestCleanupRecoverySecurityAgentRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent approvals
<details><summary><code>client.securityAgentApprovals.<a href="/src/api/resources/securityAgentApprovals/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.SecurityAgentApproval, Zasp.SecurityAgentApprovalPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.securityAgentApprovals.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.securityAgentApprovals.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListSecurityAgentApprovalsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentApprovalsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentApprovals.<a href="/src/api/resources/securityAgentApprovals/client/Client.ts">get</a>({ ...params }) -> Zasp.SecurityAgentApproval</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.securityAgentApprovals.get({
    id: "id"
});

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

**request:** `Zasp.GetSecurityAgentApprovalsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `SecurityAgentApprovalsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Home
<details><summary><code>client.home.<a href="/src/api/resources/home/client/Client.ts">getSummary</a>() -> Zasp.HomeSummary</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.home.getSummary();

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

**requestOptions:** `HomeClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Recovery
<details><summary><code>client.recovery.<a href="/src/api/resources/recovery/client/Client.ts">startBackup</a>({ ...params }) -> Zasp.RecoveryBackup</code></summary>
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

```typescript
await client.recovery.startBackup({
    "X-Zasp-Fresh-Auth": "confirmed",
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    backup_id: "backup_id",
    retention_days: 1
});

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

**request:** `Zasp.RecoveryBackupInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RecoveryClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="/src/api/resources/recovery/client/Client.ts">getBackup</a>({ ...params }) -> Zasp.RecoveryBackup</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.recovery.getBackup({
    id: "id"
});

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

**request:** `Zasp.GetBackupRecoveryRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RecoveryClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="/src/api/resources/recovery/client/Client.ts">startRestore</a>({ ...params }) -> Zasp.RecoveryRestore</code></summary>
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

```typescript
await client.recovery.startRestore({
    "X-Zasp-Fresh-Auth": "confirmed",
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    restore_id: "restore_id",
    target_environment: "target_environment",
    manifest: {
        reference: "reference",
        version_id: "version_id",
        sha256: "sha256",
        size_bytes: 1,
        media_type: "application/vnd.zasp.recovery-manifest+json",
        schema: "recovery_signed_manifest_v1",
        signing_key_id: "signing_key_id",
        signature: "signature"
    }
});

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

**request:** `Zasp.RecoveryRestoreInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RecoveryClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.<a href="/src/api/resources/recovery/client/Client.ts">getRestore</a>({ ...params }) -> Zasp.RecoveryRestore</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.recovery.getRestore({
    id: "id"
});

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

**request:** `Zasp.GetRestoreRecoveryRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `RecoveryClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tests
<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.TestDefinition, Zasp.TestDefinitionPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.tests.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.tests.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListTestsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">create</a>({ ...params }) -> Zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.tests.create({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    name: "name",
    target_id: "target_id",
    target_kind: "agent_endpoint",
    categories: ["prompt_injection"],
    safety: {
        environment: "development",
        credential_class: "read_only",
        expected_side_effects: ["expected_side_effects"]
    }
});

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

**request:** `Zasp.TestDefinitionInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">get</a>({ ...params }) -> Zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.tests.get({
    id: "id"
});

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

**request:** `Zasp.GetTestsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">update</a>({ ...params }) -> Zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.tests.update({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    name: "name",
    target_id: "target_id",
    target_kind: "agent_endpoint",
    categories: ["prompt_injection"],
    safety: {
        environment: "development",
        credential_class: "read_only",
        expected_side_effects: ["expected_side_effects"]
    },
    enabled: true
});

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

**request:** `Zasp.TestDefinitionUpdateInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">getSchedule</a>({ ...params }) -> Zasp.TestSchedule</code></summary>
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

```typescript
await client.tests.getSchedule({
    id: "id"
});

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

**request:** `Zasp.GetScheduleTestsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">putSchedule</a>({ ...params }) -> Zasp.TestSchedule</code></summary>
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

```typescript
await client.tests.putSchedule({
    id: "id",
    expected_version: 1,
    enabled: true,
    on_target_change: true
});

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

**request:** `Zasp.TestScheduleInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">run</a>({ ...params }) -> Zasp.TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.tests.run({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    run_id: "run_id"
});

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

**request:** `Zasp.TestRunInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.<a href="/src/api/resources/tests/client/Client.ts">getProbeCatalog</a>() -> Zasp.TestProbeCatalog</code></summary>
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

```typescript
await client.tests.getProbeCatalog();

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

**requestOptions:** `TestsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## TestRuns
<details><summary><code>client.testRuns.<a href="/src/api/resources/testRuns/client/Client.ts">list</a>({ ...params }) -> core.Page&lt;Zasp.TestRun, Zasp.TestRunPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.testRuns.list();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.testRuns.list();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListTestRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.testRuns.<a href="/src/api/resources/testRuns/client/Client.ts">get</a>({ ...params }) -> Zasp.TestRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.testRuns.get({
    id: "id"
});

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

**request:** `Zasp.GetTestRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.testRuns.<a href="/src/api/resources/testRuns/client/Client.ts">cancel</a>({ ...params }) -> Zasp.TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.testRuns.cancel({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.CancelTestRunsRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `TestRunsClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack lab
<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">preflight</a>({ ...params }) -> Zasp.AttackLabPreflight</code></summary>
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

```typescript
await client.attackLab.preflight({
    source_run_id: "source_run_id"
});

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

**request:** `Zasp.PreflightAttackLabRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">listRuns</a>({ ...params }) -> core.Page&lt;Zasp.AttackLabRun, Zasp.AttackLabRunPage&gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
const pageableResponse = await client.attackLab.listRuns();
for await (const item of pageableResponse) {
    console.log(item);
}

// Or you can manually iterate page-by-page
let page = await client.attackLab.listRuns();
while (page.hasNextPage()) {
    page = await page.getNextPage();
}

// You can also access the underlying response
const response = page.response;

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

**request:** `Zasp.ListRunsAttackLabRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">createRun</a>({ ...params }) -> Zasp.AttackLabRun</code></summary>
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

```typescript
await client.attackLab.createRun({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    run_id: "run_id",
    source_run_id: "source_run_id",
    decision_digest: "decision_digest",
    approved: true
});

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

**request:** `Zasp.AttackLabRunInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">getRun</a>({ ...params }) -> Zasp.AttackLabRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.attackLab.getRun({
    id: "id"
});

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

**request:** `Zasp.GetRunAttackLabRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">cancelRun</a>({ ...params }) -> Zasp.AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.attackLab.cancelRun({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id"
});

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

**request:** `Zasp.CancelRunAttackLabRequest` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.<a href="/src/api/resources/attackLab/client/Client.ts">rerunRun</a>({ ...params }) -> Zasp.AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```typescript
await client.attackLab.rerunRun({
    "Idempotency-Key": "Idempotency-Key",
    "If-Match": "If-Match",
    id: "id",
    run_id: "run_id"
});

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

**request:** `Zasp.AttackLabRerunInput` 
    
</dd>
</dl>

<dl>
<dd>

**requestOptions:** `AttackLabClient.RequestOptions` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

