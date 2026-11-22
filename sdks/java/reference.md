# Reference
## Organization
<details><summary><code>client.organization.getCurrentPrincipal() -> Principal</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.organization().getCurrentPrincipal();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Integrations
<details><summary><code>client.integrations.listCatalog() -> IntegrationCatalogPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().listCatalog(
    ListCatalogIntegrationsRequest
        .builder()
        .build()
);
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

**q:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**category:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**dataType:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**action:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**authMode:** `Optional<String>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.list() -> SyncPagingIterable&amp;lt;Integration&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().list(
    ListIntegrationsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.create(request) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().create(
    CreateIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .body(
            IntegrationInput
                .builder()
                .connectorKey("connector_key")
                .name("name")
                .configuration(
                    new HashMap<String, String>() {{
                        put("key", "value");
                    }}
                )
                .build()
        )
        .build()
);
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

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.get(id) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().get(
    "id",
    GetIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.delete(id) -> Optional&amp;lt;Integration&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().delete(
    "id",
    DeleteIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.update(id, request) -> Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().update(
    "id",
    UpdateIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            IntegrationUpdateInput
                .builder()
                .name("name")
                .configuration(
                    new HashMap<String, String>() {{
                        put("key", "value");
                    }}
                )
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationUpdateInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.sync(id, request) -> IntegrationSync</code></summary>
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

```java
client.integrations().sync(
    "id",
    SyncIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.listSyncs(id) -> SyncPagingIterable&amp;lt;IntegrationSync&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().listSyncs(
    "id",
    ListSyncsIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getSync(id, syncId) -> IntegrationSync</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().getSync(
    "id",
    "syncId",
    GetSyncIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**syncId:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getSchedule(id) -> IntegrationSchedule</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().getSchedule(
    "id",
    GetScheduleIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.putSchedule(id, request) -> IntegrationSchedule</code></summary>
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

```java
client.integrations().putSchedule(
    "id",
    PutScheduleIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            IntegrationScheduleInput
                .builder()
                .cadenceSeconds(1)
                .state(IntegrationScheduleInputState.ENABLED)
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**request:** `IntegrationScheduleInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.deleteSchedule(id)</code></summary>
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

```java
client.integrations().deleteSchedule(
    "id",
    DeleteScheduleIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getFreshness(id) -> IntegrationFreshness</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.integrations().getFreshness(
    "id",
    GetFreshnessIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getSetupStatus(id) -> IntegrationSetupStatus</code></summary>
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

```java
client.integrations().getSetupStatus(
    "id",
    GetSetupStatusIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getRemediationRole(id) -> IntegrationRemediationRole</code></summary>
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

```java
client.integrations().getRemediationRole(
    "id",
    GetRemediationRoleIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.putRemediationRole(id, request) -> IntegrationRemediationRole</code></summary>
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

```java
client.integrations().putRemediationRole(
    "id",
    IntegrationRemediationRoleInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .roleArn(
            IntegrationRemediationRoleInputRoleArn.of(IntegrationRemediationRoleInputRoleArnZero.EMPTY)
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**roleArn:** `IntegrationRemediationRoleInputRoleArn` — An IAM role of the account the integration reads, different from the role discovery reads with. The empty string removes the setting.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.testWebhook(id, request) -> IntegrationWebhookTestStatus</code></summary>
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

```java
client.integrations().testWebhook(
    "id",
    TestWebhookIntegrationsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.integrations.getWebhookStatus(id) -> IntegrationWebhookTestStatus</code></summary>
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

```java
client.integrations().getWebhookStatus(
    "id",
    GetWebhookStatusIntegrationsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Sensors
<details><summary><code>client.sensors.fetchEndpointPolicy(id) -> EndpointBundle</code></summary>
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

```java
client.sensors().fetchEndpointPolicy(
    "id",
    FetchEndpointPolicySensorsRequest
        .builder()
        .zaspDeviceProof("X-Zasp-Device-Proof")
        .zaspDeviceSignature("X-Zasp-Device-Signature")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.exchangeEndpointEnrollment(request) -> EndpointExchangeReceipt</code></summary>
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

```java
client.sensors().exchangeEndpointEnrollment(
    ExchangeEndpointEnrollmentSensorsRequest
        .builder()
        .zaspDeviceProof("X-Zasp-Device-Proof")
        .zaspDeviceSignature("X-Zasp-Device-Signature")
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**zaspDeviceProof:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.recordEndpointHeartbeat(id, request) -> EndpointRecorded</code></summary>
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

```java
client.sensors().recordEndpointHeartbeat(
    "id",
    EndpointHeartbeat
        .builder()
        .zaspDeviceProof("X-Zasp-Device-Proof")
        .zaspDeviceSignature("X-Zasp-Device-Signature")
        .policyRevision(1)
        .policyStatus(EndpointHeartbeatPolicyStatus.VERIFIED_CACHE)
        .queuedReceipts(1)
        .droppedReceipts(1)
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**policyRevision:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**policyStatus:** `EndpointHeartbeatPolicyStatus` 
    
</dd>
</dl>

<dl>
<dd>

**queuedReceipts:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**droppedReceipts:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**adapter:** `Optional<EndpointHeartbeatAdapter>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.recordEndpointInventory(id, request) -> EndpointRecorded</code></summary>
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

```java
client.sensors().recordEndpointInventory(
    "id",
    EndpointSnapshot
        .builder()
        .zaspDeviceProof("X-Zasp-Device-Proof")
        .zaspDeviceSignature("X-Zasp-Device-Signature")
        .partitionId("partition_id")
        .snapshotGeneration(1)
        .complete(true)
        .installations(
            Arrays.asList(
                EndpointSnapshotInstallationsItem
                    .builder()
                    .installationId("installation_id")
                    .build()
            )
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**partitionId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**snapshotGeneration:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**complete:** `Boolean` 
    
</dd>
</dl>

<dl>
<dd>

**installations:** `List<EndpointSnapshotInstallationsItem>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.recordEndpointObservations(request) -> EndpointRecorded</code></summary>
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

```java
client.sensors().recordEndpointObservations(
    EndpointObservationBatch
        .builder()
        .zaspDeviceProof("X-Zasp-Device-Proof")
        .zaspDeviceSignature("X-Zasp-Device-Signature")
        .receipts(
            Arrays.asList(
                EndpointSigned
                    .builder()
                    .payload("payload")
                    .signature("signature")
                    .build()
            )
        )
        .build()
);
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

**zaspDeviceProof:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**receipts:** `List<EndpointSigned>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.list() -> SyncPagingIterable&amp;lt;Sensor&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().list(
    ListSensorsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.createEnrollment(request) -> SensorEnrollment</code></summary>
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

```java
client.sensors().createEnrollment(
    SensorInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .zaspFreshAuth(CreateEnrollmentSensorsRequestXZaspFreshAuth.CONFIRMED)
        .name("name")
        .kind(SensorKind.TETRAGON)
        .mode(SensorMode.METADATA_ONLY)
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `CreateEnrollmentSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**zaspSensorEnrollmentSchema:** `Optional<CreateEnrollmentSensorsRequestXZaspSensorEnrollmentSchema>` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**runtimeSensorId:** `Optional<String>` — Optional immutable pairing for OTLP only. Must identify an active Tetragon enrollment in the same scope. Omit for an unpaired semantic source. Event payloads cannot select this authority.
    
</dd>
</dl>

<dl>
<dd>

**name:** `String` 
    
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
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.get(id) -> Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().get(
    "id",
    GetSensorsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.delete(id)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().delete(
    "id",
    DeleteSensorsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.update(id, request) -> Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().update(
    "id",
    SensorUpdateInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .name("name")
        .mode(SensorMode.METADATA_ONLY)
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**mode:** `SensorMode` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.rotateToken(id, request) -> SensorEnrollment</code></summary>
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

```java
client.sensors().rotateToken(
    "id",
    RotateTokenSensorsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .zaspFreshAuth(RotateTokenSensorsRequestXZaspFreshAuth.CONFIRMED)
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `RotateTokenSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**zaspSensorEnrollmentSchema:** `Optional<RotateTokenSensorsRequestXZaspSensorEnrollmentSchema>` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.getCoverage(id) -> SensorCoverage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().getCoverage(
    "id",
    GetCoverageSensorsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.sensors.recordBrowserOriginDays(id, request) -> BrowserOriginAck</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.sensors().recordBrowserOriginDays(
    "id",
    BrowserOriginReport
        .builder()
        .issuedAt(1000000L)
        .nonce("nonce")
        .signature("signature")
        .days(
            Arrays.asList(
                BrowserOriginDay
                    .builder()
                    .origin(BrowserObservedOrigin.HTTPS_CLAUDE_AI)
                    .day("2023-01-15")
                    .build()
            )
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**issuedAt:** `Long` — UTC Unix seconds.
    
</dd>
</dl>

<dl>
<dd>

**nonce:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**days:** `List<BrowserOriginDay>` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `String` — Base64 P-256 SHA-256 IEEE P1363 signature over the versioned profile envelope.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Guardrails
<details><summary><code>client.guardrails.decideAction(request) -> WorkloadActionDecision</code></summary>
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

```java
client.guardrails().decideAction(
    WorkloadActionRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .schemaVersion(WorkloadActionRequestSchemaVersion.ACTION_V1)
        .actionId("action_id")
        .actionKind(WorkloadActionRequestActionKind.TOOL_CALL)
        .operation("operation")
        .resource(
            WorkloadActionRequestResource
                .builder()
                .kind("kind")
                .classification("classification")
                .build()
        )
        .build()
);
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

**idempotencyKey:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `WorkloadActionRequestSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**actionId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**actionKind:** `WorkloadActionRequestActionKind` 
    
</dd>
</dl>

<dl>
<dd>

**operation:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**sourceSessionRef:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**sourceCallRef:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**resource:** `WorkloadActionRequestResource` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.recordActionOutcome(pathActionId, request) -> WorkloadOutcomeAck</code></summary>
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

```java
client.guardrails().recordActionOutcome(
    "actionId",
    WorkloadActionOutcome
        .builder()
        .idempotencyKey("Idempotency-Key")
        .schemaVersion(WorkloadActionOutcomeSchemaVersion.ACTION_OUTCOME_V1)
        .actionId("action_id")
        .decisionId("decision_id")
        .status(WorkloadActionOutcomeStatus.NOT_DISPATCHED)
        .build()
);
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

**pathActionId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `WorkloadActionOutcomeSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**actionId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**decisionId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `WorkloadActionOutcomeStatus` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.createDecision(request) -> GuardrailDecision</code></summary>
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

```java
client.guardrails().createDecision(
    GuardrailInteraction
        .builder()
        .direction(GuardrailInteractionDirection.INPUT)
        .text("text")
        .build()
);
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

**text:** `String` — The interaction text. At most 32768 bytes of UTF-8; a longer text is refused with 413.
    
</dd>
</dl>

<dl>
<dd>

**agentId:** `Optional<String>` — Optional identifier of the agent, as the gateway knows it. Recorded with the decision.
    
</dd>
</dl>

<dl>
<dd>

**toolName:** `Optional<String>` — Optional name of the tool whose call or result the text is. Recorded with the decision.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.getPolicy() -> GuardrailPolicy</code></summary>
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

```java
client.guardrails().getPolicy();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.guardrails.putPolicy(request) -> GuardrailPolicy</code></summary>
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

```java
client.guardrails().putPolicy(
    GuardrailPolicyInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .rules(
            new HashMap<String, GuardrailMode>() {{
                put("key", GuardrailMode.BLOCK);
            }}
        )
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**rules:** `Map<String, GuardrailMode>` — Rule identifier to mode. A rule that is not named has its default mode.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tools
<details><summary><code>client.tools.attestAddonScan(id, request) -> AddonCiReceipt</code></summary>
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

```java
client.tools().attestAddonScan(
    "id",
    AddonCiSignature
        .builder()
        .keyId("key_id")
        .repository("repository")
        .commit("commit")
        .signature("signature")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**keyId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**repository:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**commit:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.submitAddonScan(request) -> AddonScanReceipt</code></summary>
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

```java
client.tools().submitAddonScan(
    AddonScanSubmission
        .builder()
        .idempotencyKey("Idempotency-Key")
        .environmentId("environment_id")
        .schemaVersion(AddonScanSubmissionSchemaVersion.ZASP_ADDON_FINDINGS_V1)
        .ruleset(AddonScanSubmissionRuleset.ZASP_STATIC_V1)
        .manifestMethod(AddonScanSubmissionManifestMethod.ADDON_MANIFEST_V1)
        .completeness(AddonScanSubmissionCompleteness.COMPLETE)
        .origin(AddonScanSubmissionOrigin.LOCAL)
        .skippedCount(1)
        .findings(
            Arrays.asList(
                AddonFindingCount
                    .builder()
                    .ruleId(AddonFindingCountRuleId.DEPENDENCY_UNPINNED)
                    .count(1)
                    .build()
            )
        )
        .build()
);
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

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**privateUpload:** `Optional<AddonScanSubmissionPrivateUpload>` 
    
</dd>
</dl>

<dl>
<dd>

**environmentId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `AddonScanSubmissionSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**ruleset:** `AddonScanSubmissionRuleset` 
    
</dd>
</dl>

<dl>
<dd>

**manifestMethod:** `AddonScanSubmissionManifestMethod` 
    
</dd>
</dl>

<dl>
<dd>

**manifestDigest:** `Optional<String>` 
    
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

**findings:** `List<AddonFindingCount>` 
    
</dd>
</dl>

<dl>
<dd>

**skippedCount:** `Integer` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.list() -> SyncPagingIterable&amp;lt;InventorySummary&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tools().list(
    ListToolsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tools.get(id) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tools().get(
    "id",
    GetToolsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Gateway
<details><summary><code>client.gateway.getPolicy() -> GatewayPolicy</code></summary>
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

```java
client.gateway().getPolicy();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.putPolicy(request) -> GatewayPolicy</code></summary>
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

```java
client.gateway().putPolicy(
    GatewayPolicyInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .unapprovedServers(GatewayPolicyInputUnapprovedServers.ALLOW)
        .requestsPerMinute(1)
        .deniedToolRisks(
            Arrays.asList(McpToolRiskClass.EXECUTE)
        )
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**unapprovedServers:** `GatewayPolicyInputUnapprovedServers` 
    
</dd>
</dl>

<dl>
<dd>

**deniedToolRisks:** `List<McpToolRiskClass>` 
    
</dd>
</dl>

<dl>
<dd>

**requestsPerMinute:** `Integer` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.listServers() -> McpGatewayServerList</code></summary>
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

```java
client.gateway().listServers();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.putServer(id, request) -> McpGatewayServer</code></summary>
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

```java
client.gateway().putServer(
    "id",
    McpGatewayServerInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .name("name")
        .upstreamUrl("upstream_url")
        .enabled(true)
        .allowedTools(
            Arrays.asList("allowed_tools")
        )
        .deniedTools(
            Arrays.asList("denied_tools")
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**name:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**upstreamUrl:** `String` — An https URL on the default port with a public host, no credentials, no query and no fragment.
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `Boolean` 
    
</dd>
</dl>

<dl>
<dd>

**allowedTools:** `List<String>` 
    
</dd>
</dl>

<dl>
<dd>

**deniedTools:** `List<String>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.deleteServer(id)</code></summary>
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

```java
client.gateway().deleteServer(
    "id",
    DeleteServerGatewayRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gateway.listActivity() -> SyncPagingIterable&amp;lt;GatewayDecision&amp;gt;</code></summary>
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

```java
client.gateway().listActivity(
    ListActivityGatewayRequest
        .builder()
        .build()
);
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

**surface:** `Optional<ListActivityGatewayRequestSurface>` 
    
</dd>
</dl>

<dl>
<dd>

**serverId:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**agentId:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**decision:** `Optional<ListActivityGatewayRequestDecision>` 
    
</dd>
</dl>

<dl>
<dd>

**before:** `Optional<String>` — The next_cursor of the page before.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## GatewayTraffic
<details><summary><code>client.gatewayTraffic.callMcp(id, request) -> GatewayJsonrpcMessage</code></summary>
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

```java
client.gatewayTraffic().callMcp(
    "id",
    CallMcpGatewayTrafficRequest
        .builder()
        .body(
            GatewayJsonrpcMessage
                .builder()
                .jsonrpc(GatewayJsonrpcMessageJsonrpc.TWO0)
                .build()
        )
        .build()
);
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

**id:** `String` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamAuthorization:** `Optional<String>` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentId:** `Optional<String>` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `GatewayJsonrpcMessage` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.closeMcpSession(id)</code></summary>
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

```java
client.gatewayTraffic().closeMcpSession(
    "id",
    CloseMcpSessionGatewayTrafficRequest
        .builder()
        .mcpSessionId("MCP-Session-Id")
        .build()
);
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

**id:** `String` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamAuthorization:** `Optional<String>` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentId:** `Optional<String>` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**mcpSessionId:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.createChatCompletion(request) -> Map&amp;lt;String, Object&amp;gt;</code></summary>
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

```java
client.gatewayTraffic().createChatCompletion(
    CreateChatCompletionGatewayTrafficRequest
        .builder()
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**zaspUpstreamAuthorization:** `Optional<String>` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `Optional<String>` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamHost:** `Optional<String>` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentId:** `Optional<String>` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.createResponse(request) -> Map&amp;lt;String, Object&amp;gt;</code></summary>
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

```java
client.gatewayTraffic().createResponse(
    CreateResponseGatewayTrafficRequest
        .builder()
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**zaspUpstreamAuthorization:** `Optional<String>` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `Optional<String>` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamHost:** `Optional<String>` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentId:** `Optional<String>` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.gatewayTraffic.createMessage(request) -> Map&amp;lt;String, Object&amp;gt;</code></summary>
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

```java
client.gatewayTraffic().createMessage(
    CreateMessageGatewayTrafficRequest
        .builder()
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**zaspUpstreamAuthorization:** `Optional<String>` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `Optional<String>` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentId:** `Optional<String>` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Agents
<details><summary><code>client.agents.list() -> SyncPagingIterable&amp;lt;InventorySummary&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.agents().list(
    ListAgentsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.get(id) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.agents().get(
    "id",
    GetAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.update(id, request) -> AgentMutation</code></summary>
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

```java
client.agents().update(
    "id",
    AgentOwnershipInput
        .builder()
        .ifMatch("If-Match")
        .owner("owner")
        .team("team")
        .tags(
            Arrays.asList("tags")
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**owner:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**team:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**tags:** `List<String>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.listCapabilities(id) -> SyncPagingIterable&amp;lt;Capability&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.agents().listCapabilities(
    "id",
    ListCapabilitiesAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.listRelationships(id) -> SyncPagingIterable&amp;lt;Relationship&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.agents().listRelationships(
    "id",
    ListRelationshipsAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.getEvidencePack(id) -> AgentEvidencePackResponse</code></summary>
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

```java
client.agents().getEvidencePack(
    "id",
    GetEvidencePackAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**format:** `Optional<GetEvidencePackAgentsRequestFormat>` — json (default) returns the document and its rendering; markdown returns the rendering alone as a download.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.listSessions(id) -> SyncPagingIterable&amp;lt;AgentSession&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.agents().listSessions(
    "id",
    ListSessionsAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.agents.getAccess(id) -> AgentAccess</code></summary>
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

```java
client.agents().getAccess(
    "id",
    GetAccessAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Policies
<details><summary><code>client.policies.list() -> SyncPagingIterable&amp;lt;Policy&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().list(
    ListPoliciesRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.create(request) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().create(
    CreatePoliciesRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .body(
            Policy
                .builder()
                .id("id")
                .name("name")
                .scope(PolicyScope.ENVIRONMENT)
                .trigger("trigger")
                .action(PolicyAction.MONITOR)
                .rollout(PolicyRolloutState.DRAFT)
                .failureMode(PolicyFailureMode.OPEN)
                .conditions(
                    Arrays.asList(
                        PolicyCondition
                            .builder()
                            .field("field")
                            .operator(PolicyConditionOperator.EQUALS)
                            .value("value")
                            .build()
                    )
                )
                .build()
        )
        .build()
);
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

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Policy` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.get(id) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().get(
    "id",
    GetPoliciesRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.delete(id)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().delete(
    "id",
    DeletePoliciesRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.update(id, request) -> Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().update(
    "id",
    UpdatePoliciesRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            Policy
                .builder()
                .id("id")
                .name("name")
                .scope(PolicyScope.ENVIRONMENT)
                .trigger("trigger")
                .action(PolicyAction.MONITOR)
                .rollout(PolicyRolloutState.DRAFT)
                .failureMode(PolicyFailureMode.OPEN)
                .conditions(
                    Arrays.asList(
                        PolicyCondition
                            .builder()
                            .field("field")
                            .operator(PolicyConditionOperator.EQUALS)
                            .value("value")
                            .build()
                    )
                )
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Policy` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.rollout(id, request) -> PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().rollout(
    "id",
    RolloutPoliciesRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            PolicyRolloutInput
                .builder()
                .state(PolicyRolloutInputState.MONITOR)
                .targetId("target_id")
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `PolicyRolloutInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.simulate(id, request) -> PolicySimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().simulate(
    "id",
    SimulatePoliciesRequest
        .builder()
        .body(
            PolicySimulationInput.of(
                new HashMap<String, Object>() {{
                    put("key", "value");
                }}
            )
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request:** `PolicySimulationInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.listDecisions(id) -> RuntimeDecisionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().listDecisions(
    "id",
    ListDecisionsPoliciesRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.policies.disable(id, request) -> PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.policies().disable(
    "id",
    DisablePoliciesRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            new HashMap<String, Object>() {{
                put("key", "value");
            }}
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `Map<String, Object>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## MCP servers
<details><summary><code>client.mcpServers.list() -> SyncPagingIterable&amp;lt;McpServer&amp;gt;</code></summary>
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

```java
client.mcpServers().list(
    ListMcpServersRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcpServers.listRegistry() -> McpRegistryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.mcpServers().listRegistry();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.mcpServers.putRegistryEntry(request) -> McpRegistryEntry</code></summary>
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

```java
client.mcpServers().putRegistryEntry(
    McpRegistryInput
        .builder()
        .identity("identity")
        .status(McpRegistryInputStatus.APPROVED)
        .note("note")
        .expectedVersion(1)
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**identity:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `McpRegistryInputStatus` 
    
</dd>
</dl>

<dl>
<dd>

**note:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**expectedVersion:** `Integer` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Identities
<details><summary><code>client.identities.list() -> SyncPagingIterable&amp;lt;InventorySummary&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.identities().list(
    ListIdentitiesRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.identities.get(id) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.identities().get(
    "id",
    GetIdentitiesRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Runtimes
<details><summary><code>client.runtimes.list() -> SyncPagingIterable&amp;lt;InventorySummary&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.runtimes().list(
    ListRuntimesRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.runtimes.get(id) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.runtimes().get(
    "id",
    GetRuntimesRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Assets
<details><summary><code>client.assets.get(id) -> InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.assets().get(
    "id",
    GetAssetsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Findings
<details><summary><code>client.findings.list() -> SyncPagingIterable&amp;lt;Finding&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.findings().list(
    ListFindingsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.get(id) -> Finding</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.findings().get(
    "id",
    GetFindingsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.update(id, request) -> Finding</code></summary>
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

```java
client.findings().update(
    "id",
    UpdateFindingsRequest
        .builder()
        .ifMatch("If-Match")
        .body(
            FindingUpdateInput
                .builder()
                .status(FindingUpdateInputStatus.OPEN)
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `FindingUpdateInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.acceptRisk(id, request) -> Finding</code></summary>
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

```java
client.findings().acceptRisk(
    "id",
    AcceptRiskFindingsRequest
        .builder()
        .ifMatch("If-Match")
        .body(
            FindingAcceptanceInput
                .builder()
                .reason("reason")
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `FindingAcceptanceInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.findings.createTicket(id) -> FindingTicket</code></summary>
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

```java
client.findings().createTicket(
    "id",
    CreateTicketFindingsRequest
        .builder()
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack paths
<details><summary><code>client.attackPaths.list() -> SyncPagingIterable&amp;lt;AttackPath&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackPaths().list(
    ListAttackPathsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackPaths.get(id) -> AttackPath</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackPaths().get(
    "id",
    GetAttackPathsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackPaths.getBreakOptions(id) -> BreakOptionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackPaths().getBreakOptions(
    "id",
    GetBreakOptionsAttackPathsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Search
<details><summary><code>client.search.query() -> SearchResultPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.search().query(
    QuerySearchRequest
        .builder()
        .q("q")
        .build()
);
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

**q:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agents
<details><summary><code>client.securityAgents.listTemplates() -> SecurityAgentTemplatePage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().listTemplates();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.listActions() -> SecurityActionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().listActions();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.list() -> SyncPagingIterable&amp;lt;SecurityAgentDefinition&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().list(
    ListSecurityAgentsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.create(request) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().create(
    CreateSecurityAgentsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .body(
            SecurityAgentInput
                .builder()
                .name("name")
                .triggerKind(SecurityAgentInputTriggerKind.FINDING)
                .triggerSource("trigger_source")
                .autonomy(SecurityAgentInputAutonomy.SUPERVISED)
                .maxSteps(1)
                .maxDurationSeconds(1)
                .temporaryPolicySeconds(1)
                .aiTokenBudget(1)
                .concurrencyLimit(1)
                .verificationKind("verification_kind")
                .definitionVersion(1)
                .enabled(true)
                .environmentIds(
                    Arrays.asList("environment_ids")
                )
                .allowedActions(
                    Arrays.asList("allowed_actions")
                )
                .build()
        )
        .build()
);
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

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.get(id) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().get(
    "id",
    GetSecurityAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.delete(id)</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().delete(
    "id",
    DeleteSecurityAgentsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.update(id, request) -> SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().update(
    "id",
    UpdateSecurityAgentsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            SecurityAgentDefinition
                .builder()
                .id("id")
                .name("name")
                .triggerKind(SecurityAgentDefinitionTriggerKind.FINDING)
                .triggerSource("trigger_source")
                .autonomy(SecurityAgentDefinitionAutonomy.SUPERVISED)
                .maxSteps(1)
                .maxDurationSeconds(1)
                .temporaryPolicySeconds(1)
                .aiTokenBudget(1)
                .concurrencyLimit(1)
                .verificationKind("verification_kind")
                .definitionVersion(1)
                .enabled(true)
                .environmentIds(
                    Arrays.asList("environment_ids")
                )
                .allowedActions(
                    Arrays.asList("allowed_actions")
                )
                .build()
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentDefinition` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.getActivation(id) -> SecurityAgentActivationState</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().getActivation(
    "id",
    GetActivationSecurityAgentsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.simulate(id, request) -> SecurityAgentSimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().simulate(
    "id",
    SecurityAgentSimulationInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .goal("goal")
        .environmentId("environment_id")
        .evidenceIds(
            Arrays.asList("evidence_ids")
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**goal:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**environmentId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**evidenceIds:** `List<String>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgents.run(id, request) -> SecurityAgentRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgents().run(
    "id",
    RunSecurityAgentsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .body(
            SecurityAgentManualRunInput.of(
                SecurityAgentLegacyTriggerInput
                    .builder()
                    .environmentId("environment_id")
                    .build()
            )
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `SecurityAgentManualRunInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent runs
<details><summary><code>client.securityAgentRuns.list() -> SyncPagingIterable&amp;lt;SecurityAgentRun&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentRuns().list(
    ListSecurityAgentRunsRequest
        .builder()
        .build()
);
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

**agentId:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `Optional<SecurityAgentRunState>` 
    
</dd>
</dl>

<dl>
<dd>

**environmentId:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.get(id) -> SecurityAgentRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentRuns().get(
    "id",
    GetSecurityAgentRunsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspBudgetDetails:** `Optional<String>` — Request optional budget_stop_reason details with v1. Omitted or unsupported values preserve the legacy response shape. Older servers may omit the reason even when requested.
    
</dd>
</dl>

<dl>
<dd>

**zaspRunContext:** `Optional<String>` — Request optional trigger and redacted AI rationale with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit run_context.
    
</dd>
</dl>

<dl>
<dd>

**zaspActionDetails:** `Optional<String>` — Request optional persisted action details with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit action_details. Independent of budget and run-context negotiation.
    
</dd>
</dl>

<dl>
<dd>

**zaspRunLifecycle:** `Optional<String>` — Request the optional stop_reason and closure with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit both. Independent of the other negotiations.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.cancel(id) -> SecurityAgentCancellation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentRuns().cancel(
    "id",
    CancelSecurityAgentRunsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.close(id, request) -> SecurityAgentRunClosed</code></summary>
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

```java
client.securityAgentRuns().close(
    "id",
    SecurityAgentRunCloseRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .reason(SecurityAgentRunCloseReason.NO_ACTION_REQUIRED)
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**reason:** `SecurityAgentRunCloseReason` 
    
</dd>
</dl>

<dl>
<dd>

**note:** `Optional<String>` — Optional single-line justification kept with the closure and its audit event.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.getCleanupRecovery(id) -> SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentRuns().getCleanupRecovery(
    "id",
    GetCleanupRecoverySecurityAgentRunsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentRuns.requestCleanupRecovery(id, request) -> SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentRuns().requestCleanupRecovery(
    "id",
    RequestCleanupRecoverySecurityAgentRunsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .definitionVersion(1)
        .inputDigest("input_digest")
        .diagnostic(RequestCleanupRecoverySecurityAgentRunsRequestDiagnostic.HISTORY_UNAVAILABLE)
        .stopOriginal("stop_original")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**definitionVersion:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**inputDigest:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**diagnostic:** `RequestCleanupRecoverySecurityAgentRunsRequestDiagnostic` 
    
</dd>
</dl>

<dl>
<dd>

**stopOriginal:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent approvals
<details><summary><code>client.securityAgentApprovals.list() -> SyncPagingIterable&amp;lt;SecurityAgentApproval&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentApprovals().list(
    ListSecurityAgentApprovalsRequest
        .builder()
        .build()
);
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

**state:** `Optional<ListSecurityAgentApprovalsRequestState>` 
    
</dd>
</dl>

<dl>
<dd>

**runId:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>

<dl>
<dd>

**zaspApprovalContext:** `Optional<String>` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.securityAgentApprovals.get(id) -> SecurityAgentApproval</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.securityAgentApprovals().get(
    "id",
    GetSecurityAgentApprovalsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**zaspApprovalContext:** `Optional<String>` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Home
<details><summary><code>client.home.getSummary() -> HomeSummary</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.home().getSummary();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Recovery
<details><summary><code>client.recovery.startBackup(request) -> RecoveryBackup</code></summary>
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

```java
client.recovery().startBackup(
    RecoveryBackupInput
        .builder()
        .zaspFreshAuth(StartBackupRecoveryRequestXZaspFreshAuth.CONFIRMED)
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .backupId("backup_id")
        .retentionDays(1)
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `StartBackupRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**backupId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**retentionDays:** `Integer` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.getBackup(id) -> RecoveryBackup</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.recovery().getBackup(
    "id",
    GetBackupRecoveryRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.startRestore(request) -> RecoveryRestore</code></summary>
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

```java
client.recovery().startRestore(
    RecoveryRestoreInput
        .builder()
        .zaspFreshAuth(StartRestoreRecoveryRequestXZaspFreshAuth.CONFIRMED)
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .restoreId("restore_id")
        .targetEnvironment("target_environment")
        .manifest(
            RecoveryManifestLocator
                .builder()
                .reference("reference")
                .versionId("version_id")
                .sha256("sha256")
                .sizeBytes(1)
                .mediaType(RecoveryManifestLocatorMediaType.APPLICATION_VND_ZASP_RECOVERY_MANIFEST_JSON)
                .schema(RecoveryManifestLocatorSchema.RECOVERY_SIGNED_MANIFEST_V1)
                .signingKeyId("signing_key_id")
                .signature("signature")
                .build()
        )
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `StartRestoreRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**restoreId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**targetEnvironment:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**manifest:** `RecoveryManifestLocator` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.recovery.getRestore(id) -> RecoveryRestore</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.recovery().getRestore(
    "id",
    GetRestoreRecoveryRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tests
<details><summary><code>client.tests.list() -> SyncPagingIterable&amp;lt;TestDefinition&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tests().list(
    ListTestsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.create(request) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tests().create(
    TestDefinitionInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .id("id")
        .name("name")
        .targetId("target_id")
        .targetKind(TestDefinitionInputTargetKind.AGENT_ENDPOINT)
        .safety(
            SafetyMetadata
                .builder()
                .environment(SafetyMetadataEnvironment.DEVELOPMENT)
                .credentialClass(SafetyMetadataCredentialClass.READ_ONLY)
                .expectedSideEffects(
                    Arrays.asList("expected_side_effects")
                )
                .build()
        )
        .categories(
            Arrays.asList(TestDefinitionInputCategoriesItem.PROMPT_INJECTION)
        )
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**name:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**targetId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**targetKind:** `TestDefinitionInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `List<TestDefinitionInputCategoriesItem>` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `SafetyMetadata` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.get(id) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tests().get(
    "id",
    GetTestsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.update(id, request) -> TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tests().update(
    "id",
    TestDefinitionUpdateInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .name("name")
        .targetId("target_id")
        .targetKind(TestDefinitionUpdateInputTargetKind.AGENT_ENDPOINT)
        .safety(
            SafetyMetadata
                .builder()
                .environment(SafetyMetadataEnvironment.DEVELOPMENT)
                .credentialClass(SafetyMetadataCredentialClass.READ_ONLY)
                .expectedSideEffects(
                    Arrays.asList("expected_side_effects")
                )
                .build()
        )
        .enabled(true)
        .categories(
            Arrays.asList(TestDefinitionUpdateInputCategoriesItem.PROMPT_INJECTION)
        )
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**targetId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**targetKind:** `TestDefinitionUpdateInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `List<TestDefinitionUpdateInputCategoriesItem>` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `SafetyMetadata` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `Boolean` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.getSchedule(id) -> TestSchedule</code></summary>
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

```java
client.tests().getSchedule(
    "id",
    GetScheduleTestsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.putSchedule(id, request) -> TestSchedule</code></summary>
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

```java
client.tests().putSchedule(
    "id",
    TestScheduleInput
        .builder()
        .expectedVersion(1)
        .enabled(true)
        .onTargetChange(true)
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**expectedVersion:** `Integer` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `Boolean` 
    
</dd>
</dl>

<dl>
<dd>

**cadenceSeconds:** `Optional<Integer>` 
    
</dd>
</dl>

<dl>
<dd>

**onTargetChange:** `Boolean` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.run(id, request) -> TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.tests().run(
    "id",
    TestRunInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .runId("run_id")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runId:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.tests.getProbeCatalog() -> TestProbeCatalog</code></summary>
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

```java
client.tests().getProbeCatalog();
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## TestRuns
<details><summary><code>client.testRuns.list() -> SyncPagingIterable&amp;lt;TestRun&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.testRuns().list(
    ListTestRunsRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.testRuns.get(id) -> TestRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.testRuns().get(
    "id",
    GetTestRunsRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.testRuns.cancel(id) -> TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.testRuns().cancel(
    "id",
    CancelTestRunsRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack lab
<details><summary><code>client.attackLab.preflight() -> AttackLabPreflight</code></summary>
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

```java
client.attackLab().preflight(
    PreflightAttackLabRequest
        .builder()
        .sourceRunId("source_run_id")
        .build()
);
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

**sourceRunId:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.listRuns() -> SyncPagingIterable&amp;lt;AttackLabRun&amp;gt;</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackLab().listRuns(
    ListRunsAttackLabRequest
        .builder()
        .build()
);
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

**cursor:** `Optional<String>` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `Optional<Integer>` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.createRun(request) -> AttackLabRun</code></summary>
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

```java
client.attackLab().createRun(
    AttackLabRunInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .runId("run_id")
        .sourceRunId("source_run_id")
        .decisionDigest("decision_digest")
        .approved(true)
        .build()
);
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

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**sourceRunId:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**decisionDigest:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**approved:** `Boolean` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.getRun(id) -> AttackLabRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackLab().getRun(
    "id",
    GetRunAttackLabRequest
        .builder()
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.cancelRun(id) -> AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackLab().cancelRun(
    "id",
    CancelRunAttackLabRequest
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.attackLab.rerunRun(id, request) -> AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```java
client.attackLab().rerunRun(
    "id",
    AttackLabRerunInput
        .builder()
        .idempotencyKey("Idempotency-Key")
        .ifMatch("If-Match")
        .runId("run_id")
        .build()
);
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

**id:** `String` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `Optional<String>` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `String` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `String` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runId:** `String` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

