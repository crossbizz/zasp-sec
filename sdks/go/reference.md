# Reference
## Organization
<details><summary><code>client.Organization.GetCurrentPrincipal() -> *zasp.Principal</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
_, err := client.Organization.GetCurrentPrincipal(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Integrations
<details><summary><code>client.Integrations.ListCatalog() -> *zasp.IntegrationCatalogPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListCatalogIntegrationsRequest{}
_, err := client.Integrations.ListCatalog(
    context.TODO(),
    request,
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

**q:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**category:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**dataType:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**action:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**authMode:** `*string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.List() -> *zasp.IntegrationPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListIntegrationsRequest{}
_, err := client.Integrations.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.Create(request) -> *zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CreateIntegrationsRequest{
    IdempotencyKey: "Idempotency-Key",
    Body: &zasp.IntegrationInput{
        ConnectorKey: "connector_key",
        Name: "name",
        Configuration: map[string]string{
            "key": "value",
        },
    },
}
_, err := client.Integrations.Create(
    context.TODO(),
    request,
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

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.IntegrationInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.Get(ID) -> *zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.Delete(ID) -> *zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.DeleteIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
_, err := client.Integrations.Delete(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.Update(ID, request) -> *zasp.Integration</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.UpdateIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.IntegrationUpdateInput{
        Name: "name",
        Configuration: map[string]string{
            "key": "value",
        },
    },
}
_, err := client.Integrations.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.IntegrationUpdateInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.Sync(ID, request) -> *zasp.IntegrationSync</code></summary>
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

```go
request := &zasp.SyncIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.Integrations.Sync(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.EmptyInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.ListSyncs(ID) -> *zasp.IntegrationSyncPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSyncsIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.ListSyncs(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetSync(ID, SyncID) -> *zasp.IntegrationSync</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetSyncIntegrationsRequest{
    ID: "id",
    SyncID: "syncId",
}
_, err := client.Integrations.GetSync(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**syncID:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetSchedule(ID) -> *zasp.IntegrationSchedule</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetScheduleIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.GetSchedule(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.PutSchedule(ID, request) -> *zasp.IntegrationSchedule</code></summary>
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

```go
request := &zasp.PutScheduleIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.IntegrationScheduleInput{
        CadenceSeconds: 1,
        State: zasp.IntegrationScheduleInputStateEnabled,
    },
}
_, err := client.Integrations.PutSchedule(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.IntegrationScheduleInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.DeleteSchedule(ID) -> error</code></summary>
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

```go
request := &zasp.DeleteScheduleIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
err := client.Integrations.DeleteSchedule(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetFreshness(ID) -> *zasp.IntegrationFreshness</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetFreshnessIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.GetFreshness(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetSetupStatus(ID) -> *zasp.IntegrationSetupStatus</code></summary>
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

```go
request := &zasp.GetSetupStatusIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.GetSetupStatus(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetRemediationRole(ID) -> *zasp.IntegrationRemediationRole</code></summary>
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

```go
request := &zasp.GetRemediationRoleIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.GetRemediationRole(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.PutRemediationRole(ID, request) -> *zasp.IntegrationRemediationRole</code></summary>
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

```go
request := &zasp.IntegrationRemediationRoleInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    RoleArn: &zasp.IntegrationRemediationRoleInputRoleArn{
        IntegrationRemediationRoleInputRoleArnZero: zasp.IntegrationRemediationRoleInputRoleArnZeroEmpty,
    },
}
_, err := client.Integrations.PutRemediationRole(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**roleArn:** `*zasp.IntegrationRemediationRoleInputRoleArn` — An IAM role of the account the integration reads, different from the role discovery reads with. The empty string removes the setting.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.TestWebhook(ID, request) -> *zasp.IntegrationWebhookTestStatus</code></summary>
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

```go
request := &zasp.TestWebhookIntegrationsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.Integrations.TestWebhook(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.EmptyInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Integrations.GetWebhookStatus(ID) -> *zasp.IntegrationWebhookTestStatus</code></summary>
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

```go
request := &zasp.GetWebhookStatusIntegrationsRequest{
    ID: "id",
}
_, err := client.Integrations.GetWebhookStatus(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Sensors
<details><summary><code>client.Sensors.FetchEndpointPolicy(ID) -> *zasp.EndpointBundle</code></summary>
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

```go
request := &zasp.FetchEndpointPolicySensorsRequest{
    ID: "id",
    ZaspDeviceProof: "X-Zasp-Device-Proof",
    ZaspDeviceSignature: "X-Zasp-Device-Signature",
}
_, err := client.Sensors.FetchEndpointPolicy(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.ExchangeEndpointEnrollment(request) -> *zasp.EndpointExchangeReceipt</code></summary>
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

```go
request := &zasp.ExchangeEndpointEnrollmentSensorsRequest{
    ZaspDeviceProof: "X-Zasp-Device-Proof",
    ZaspDeviceSignature: "X-Zasp-Device-Signature",
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.Sensors.ExchangeEndpointEnrollment(
    context.TODO(),
    request,
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

**zaspDeviceProof:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.EndpointEmpty` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.RecordEndpointHeartbeat(ID, request) -> *zasp.EndpointRecorded</code></summary>
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

```go
request := &zasp.EndpointHeartbeat{
    ID: "id",
    ZaspDeviceProof: "X-Zasp-Device-Proof",
    ZaspDeviceSignature: "X-Zasp-Device-Signature",
    PolicyRevision: 1,
    PolicyStatus: zasp.EndpointHeartbeatPolicyStatusVerifiedCache,
    QueuedReceipts: 1,
    DroppedReceipts: 1,
}
_, err := client.Sensors.RecordEndpointHeartbeat(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**policyRevision:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**policyStatus:** `zasp.EndpointHeartbeatPolicyStatus` 
    
</dd>
</dl>

<dl>
<dd>

**queuedReceipts:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**droppedReceipts:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**adapter:** `*zasp.EndpointHeartbeatAdapter` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.RecordEndpointInventory(ID, request) -> *zasp.EndpointRecorded</code></summary>
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

```go
request := &zasp.EndpointSnapshot{
    ID: "id",
    ZaspDeviceProof: "X-Zasp-Device-Proof",
    ZaspDeviceSignature: "X-Zasp-Device-Signature",
    PartitionID: "partition_id",
    SnapshotGeneration: 1,
    Complete: true,
    Installations: []*zasp.EndpointSnapshotInstallationsItem{
        &zasp.EndpointSnapshotInstallationsItem{
            InstallationID: "installation_id",
        },
    },
}
_, err := client.Sensors.RecordEndpointInventory(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceProof:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**partitionID:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**snapshotGeneration:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**complete:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**installations:** `[]*zasp.EndpointSnapshotInstallationsItem` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.RecordEndpointObservations(request) -> *zasp.EndpointRecorded</code></summary>
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

```go
request := &zasp.EndpointObservationBatch{
    ZaspDeviceProof: "X-Zasp-Device-Proof",
    ZaspDeviceSignature: "X-Zasp-Device-Signature",
    Receipts: []*zasp.EndpointSigned{
        &zasp.EndpointSigned{
            Payload: "payload",
            Signature: "signature",
        },
    },
}
_, err := client.Sensors.RecordEndpointObservations(
    context.TODO(),
    request,
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

**zaspDeviceProof:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**zaspDeviceSignature:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**receipts:** `[]*zasp.EndpointSigned` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.List() -> *zasp.SensorPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSensorsRequest{}
_, err := client.Sensors.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.CreateEnrollment(request) -> *zasp.SensorEnrollment</code></summary>
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

```go
request := &zasp.SensorInput{
    IdempotencyKey: "Idempotency-Key",
    ZaspFreshAuth: zasp.CreateEnrollmentSensorsRequestXZaspFreshAuthConfirmed,
    Name: "name",
    Kind: zasp.SensorKindTetragon,
    Mode: zasp.SensorModeMetadataOnly,
}
_, err := client.Sensors.CreateEnrollment(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `zasp.CreateEnrollmentSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**zaspSensorEnrollmentSchema:** `*zasp.CreateEnrollmentSensorsRequestXZaspSensorEnrollmentSchema` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**runtimeSensorID:** `*zasp.ProductID` — Optional immutable pairing for OTLP only. Must identify an active Tetragon enrollment in the same scope. Omit for an unpaired semantic source. Event payloads cannot select this authority.
    
</dd>
</dl>

<dl>
<dd>

**name:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**kind:** `zasp.SensorKind` 
    
</dd>
</dl>

<dl>
<dd>

**mode:** `zasp.SensorMode` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.Get(ID) -> *zasp.Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetSensorsRequest{
    ID: "id",
}
_, err := client.Sensors.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.Delete(ID) -> error</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.DeleteSensorsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
err := client.Sensors.Delete(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.Update(ID, request) -> *zasp.Sensor</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.SensorUpdateInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Name: "name",
    Mode: zasp.SensorModeMetadataOnly,
}
_, err := client.Sensors.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**mode:** `zasp.SensorMode` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.RotateToken(ID, request) -> *zasp.SensorEnrollment</code></summary>
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

```go
request := &zasp.RotateTokenSensorsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    ZaspFreshAuth: zasp.RotateTokenSensorsRequestXZaspFreshAuthConfirmed,
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.Sensors.RotateToken(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `zasp.RotateTokenSensorsRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**zaspSensorEnrollmentSchema:** `*zasp.RotateTokenSensorsRequestXZaspSensorEnrollmentSchema` — Select enrollment-binding-v1 to require a scoped installation binding in a successful one-time credential response. Omission preserves the legacy representation. This is not authentication or mutation intent.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.EmptyInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.GetCoverage(ID) -> *zasp.SensorCoverage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetCoverageSensorsRequest{
    ID: "id",
}
_, err := client.Sensors.GetCoverage(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Sensors.RecordBrowserOriginDays(ID, request) -> *zasp.BrowserOriginAck</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.BrowserOriginReport{
    ID: "id",
    IssuedAt: int64(1000000),
    Nonce: "nonce",
    Days: []*zasp.BrowserOriginDay{
        &zasp.BrowserOriginDay{
            Origin: zasp.BrowserObservedOriginHTTPSClaudeAi,
            Day: zasp.MustParseDate(
                "2023-01-15",
            ),
        },
    },
    Signature: "signature",
}
_, err := client.Sensors.RecordBrowserOriginDays(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**issuedAt:** `int64` — UTC Unix seconds.
    
</dd>
</dl>

<dl>
<dd>

**nonce:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**days:** `[]*zasp.BrowserOriginDay` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `string` — Base64 P-256 SHA-256 IEEE P1363 signature over the versioned profile envelope.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Guardrails
<details><summary><code>client.Guardrails.DecideAction(request) -> *zasp.WorkloadActionDecision</code></summary>
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

```go
request := &zasp.WorkloadActionRequest{
    IdempotencyKey: "Idempotency-Key",
    SchemaVersion: zasp.WorkloadActionRequestSchemaVersionActionV1,
    ActionID: "action_id",
    ActionKind: zasp.WorkloadActionRequestActionKindToolCall,
    Operation: "operation",
    Resource: &zasp.WorkloadActionRequestResource{
        Kind: "kind",
        Classification: "classification",
    },
}
_, err := client.Guardrails.DecideAction(
    context.TODO(),
    request,
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

**idempotencyKey:** `zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `zasp.WorkloadActionRequestSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**actionID:** `zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**actionKind:** `zasp.WorkloadActionRequestActionKind` 
    
</dd>
</dl>

<dl>
<dd>

**operation:** `zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**sourceSessionRef:** `*zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**sourceCallRef:** `*zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**resource:** `*zasp.WorkloadActionRequestResource` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Guardrails.RecordActionOutcome(PathActionID, request) -> *zasp.WorkloadOutcomeAck</code></summary>
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

```go
request := &zasp.WorkloadActionOutcome{
    PathActionID: "actionId",
    IdempotencyKey: "Idempotency-Key",
    SchemaVersion: zasp.WorkloadActionOutcomeSchemaVersionActionOutcomeV1,
    ActionID: "action_id",
    DecisionID: "decision_id",
    Status: zasp.WorkloadActionOutcomeStatusNotDispatched,
}
_, err := client.Guardrails.RecordActionOutcome(
    context.TODO(),
    request,
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

**pathActionID:** `zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `zasp.WorkloadActionOutcomeSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**actionID:** `zasp.WorkloadActionLabel` 
    
</dd>
</dl>

<dl>
<dd>

**decisionID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**contextEvidence:** `*zasp.WorkloadContextEvidence`

</dd>
</dl>

<dl>
<dd>

**status:** `zasp.WorkloadActionOutcomeStatus` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Guardrails.CreateDecision(request) -> *zasp.GuardrailDecision</code></summary>
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

```go
request := &zasp.GuardrailInteraction{
    Direction: zasp.GuardrailInteractionDirectionInput,
    Text: "text",
}
_, err := client.Guardrails.CreateDecision(
    context.TODO(),
    request,
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

**direction:** `zasp.GuardrailInteractionDirection` — input is text on its way into a model; output is text a model produced.
    
</dd>
</dl>

<dl>
<dd>

**text:** `string` — The interaction text. At most 32768 bytes of UTF-8; a longer text is refused with 413.
    
</dd>
</dl>

<dl>
<dd>

**agentID:** `*string` — Optional identifier of the agent, as the gateway knows it. Recorded with the decision.
    
</dd>
</dl>

<dl>
<dd>

**toolName:** `*string` — Optional name of the tool whose call or result the text is. Recorded with the decision.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Guardrails.GetPolicy() -> *zasp.GuardrailPolicy</code></summary>
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

```go
_, err := client.Guardrails.GetPolicy(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Guardrails.PutPolicy(request) -> *zasp.GuardrailPolicy</code></summary>
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

```go
request := &zasp.GuardrailPolicyInput{
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Rules: map[string]zasp.GuardrailMode{
        "key": zasp.GuardrailModeBlock,
    },
}
_, err := client.Guardrails.PutPolicy(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**rules:** `map[string]zasp.GuardrailMode` — Rule identifier to mode. A rule that is not named has its default mode.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tools
<details><summary><code>client.Tools.AttestAddonScan(ID, request) -> *zasp.AddonCiReceipt</code></summary>
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

```go
request := &zasp.AddonCiSignature{
    ID: "id",
    KeyID: "key_id",
    Repository: "repository",
    Commit: "commit",
    Signature: "signature",
}
_, err := client.Tools.AttestAddonScan(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**keyID:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**repository:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**commit:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**signature:** `string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tools.SubmitAddonScan(request) -> *zasp.AddonScanReceipt</code></summary>
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

```go
request := &zasp.AddonScanSubmission{
    IdempotencyKey: "Idempotency-Key",
    EnvironmentID: "environment_id",
    SchemaVersion: zasp.AddonScanSubmissionSchemaVersionZaspAddonFindingsV1,
    Ruleset: zasp.AddonScanSubmissionRulesetZaspStaticV1,
    ManifestMethod: zasp.AddonScanSubmissionManifestMethodAddonManifestV1,
    Completeness: zasp.AddonScanSubmissionCompletenessComplete,
    Origin: zasp.AddonScanSubmissionOriginLocal,
    Findings: []*zasp.AddonFindingCount{
        &zasp.AddonFindingCount{
            RuleID: zasp.AddonFindingCountRuleIDDependencyUnpinned,
            Count: 1,
        },
    },
    SkippedCount: 1,
}
_, err := client.Tools.SubmitAddonScan(
    context.TODO(),
    request,
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

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**privateUpload:** `*zasp.AddonScanSubmissionPrivateUpload` 
    
</dd>
</dl>

<dl>
<dd>

**environmentID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**schemaVersion:** `zasp.AddonScanSubmissionSchemaVersion` 
    
</dd>
</dl>

<dl>
<dd>

**ruleset:** `zasp.AddonScanSubmissionRuleset` 
    
</dd>
</dl>

<dl>
<dd>

**manifestMethod:** `zasp.AddonScanSubmissionManifestMethod` 
    
</dd>
</dl>

<dl>
<dd>

**manifestDigest:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**completeness:** `zasp.AddonScanSubmissionCompleteness` 
    
</dd>
</dl>

<dl>
<dd>

**origin:** `zasp.AddonScanSubmissionOrigin` 
    
</dd>
</dl>

<dl>
<dd>

**findings:** `[]*zasp.AddonFindingCount` 
    
</dd>
</dl>

<dl>
<dd>

**skippedCount:** `int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tools.List() -> *zasp.InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListToolsRequest{}
_, err := client.Tools.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tools.Get(ID) -> *zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetToolsRequest{
    ID: "id",
}
_, err := client.Tools.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Gateway
<details><summary><code>client.Gateway.GetPolicy() -> *zasp.GatewayPolicy</code></summary>
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

```go
_, err := client.Gateway.GetPolicy(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Gateway.PutPolicy(request) -> *zasp.GatewayPolicy</code></summary>
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

```go
request := &zasp.GatewayPolicyInput{
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    UnapprovedServers: zasp.GatewayPolicyInputUnapprovedServersAllow,
    DeniedToolRisks: []zasp.McpToolRiskClass{
        zasp.McpToolRiskClassExecute,
    },
    RequestsPerMinute: 1,
}
_, err := client.Gateway.PutPolicy(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**unapprovedServers:** `zasp.GatewayPolicyInputUnapprovedServers` 
    
</dd>
</dl>

<dl>
<dd>

**deniedToolRisks:** `[]zasp.McpToolRiskClass` 
    
</dd>
</dl>

<dl>
<dd>

**requestsPerMinute:** `int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Gateway.ListServers() -> *zasp.McpGatewayServerList</code></summary>
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

```go
_, err := client.Gateway.ListServers(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Gateway.PutServer(ID, request) -> *zasp.McpGatewayServer</code></summary>
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

```go
request := &zasp.McpGatewayServerInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Name: "name",
    UpstreamURL: "upstream_url",
    Enabled: true,
    AllowedTools: []zasp.McpGatewayToolName{
        "allowed_tools",
    },
    DeniedTools: []zasp.McpGatewayToolName{
        "denied_tools",
    },
}
_, err := client.Gateway.PutServer(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>

<dl>
<dd>

**name:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**upstreamURL:** `string` — An https URL on the default port with a public host, no credentials, no query and no fragment.
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**allowedTools:** `[]zasp.McpGatewayToolName` 
    
</dd>
</dl>

<dl>
<dd>

**deniedTools:** `[]zasp.McpGatewayToolName` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Gateway.DeleteServer(ID) -> error</code></summary>
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

```go
request := &zasp.DeleteServerGatewayRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
err := client.Gateway.DeleteServer(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current schedule version, or quoted zero when creating the singleton schedule.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Gateway.ListActivity() -> *zasp.GatewayDecisionPage</code></summary>
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

```go
request := &zasp.ListActivityGatewayRequest{}
_, err := client.Gateway.ListActivity(
    context.TODO(),
    request,
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

**surface:** `*zasp.ListActivityGatewayRequestSurface` 
    
</dd>
</dl>

<dl>
<dd>

**serverID:** `*zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**agentID:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**decision:** `*zasp.ListActivityGatewayRequestDecision` 
    
</dd>
</dl>

<dl>
<dd>

**before:** `*zasp.ProductID` — The next_cursor of the page before.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## GatewayTraffic
<details><summary><code>client.GatewayTraffic.CallMcp(ID, request) -> *zasp.GatewayJsonrpcMessage</code></summary>
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

```go
request := &zasp.CallMcpGatewayTrafficRequest{
    ID: "id",
    Body: &zasp.GatewayJsonrpcMessage{
        Jsonrpc: zasp.GatewayJsonrpcMessageJsonrpcTwo0,
    },
}
_, err := client.GatewayTraffic.CallMcp(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamAuthorization:** `*string` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentID:** `*string` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.GatewayJsonrpcMessage` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.GatewayTraffic.CloseMcpSession(ID) -> error</code></summary>
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

```go
request := &zasp.CloseMcpSessionGatewayTrafficRequest{
    ID: "id",
    McpSessionID: "MCP-Session-Id",
}
err := client.GatewayTraffic.CloseMcpSession(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` — The gateway server.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamAuthorization:** `*string` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentID:** `*string` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**mcpSessionID:** `string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.GatewayTraffic.CreateChatCompletion(request) -> zasp.GatewayProviderBody</code></summary>
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

```go
request := &zasp.CreateChatCompletionGatewayTrafficRequest{
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.GatewayTraffic.CreateChatCompletion(
    context.TODO(),
    request,
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

**zaspUpstreamAuthorization:** `*string` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `*string` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamHost:** `*string` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentID:** `*string` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.GatewayProviderBody` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.GatewayTraffic.CreateResponse(request) -> zasp.GatewayProviderBody</code></summary>
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

```go
request := &zasp.CreateResponseGatewayTrafficRequest{
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.GatewayTraffic.CreateResponse(
    context.TODO(),
    request,
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

**zaspUpstreamAuthorization:** `*string` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `*string` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamHost:** `*string` — For a provider that gives each of its customers a host of their own, the host of the caller's resource. It must lie directly under the provider's own domain.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentID:** `*string` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.GatewayProviderBody` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.GatewayTraffic.CreateMessage(request) -> zasp.GatewayProviderBody</code></summary>
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

```go
request := &zasp.CreateMessageGatewayTrafficRequest{
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.GatewayTraffic.CreateMessage(
    context.TODO(),
    request,
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

**zaspUpstreamAuthorization:** `*string` — The upstream's own credential: for an MCP server the value of the Authorization header the server expects (for example "Bearer <token>"), for a model provider its API key (with or without "Bearer "). It is forwarded for this request only and is never stored or logged. The platform token in Authorization is never sent upstream.
    
</dd>
</dl>

<dl>
<dd>

**zaspUpstreamProvider:** `*string` — The model provider to forward to, by its name in the gateway's catalog (see the hosted gateway guide). Without it the request goes to the provider whose API this route speaks.
    
</dd>
</dl>

<dl>
<dd>

**zaspAgentID:** `*string` — The calling agent, recorded with each decision. Send the agent's identifier in the inventory to have its gateway traffic count as the agent's activity.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.GatewayProviderBody` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Agents
<details><summary><code>client.Agents.List() -> *zasp.InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListAgentsRequest{}
_, err := client.Agents.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.Get(ID) -> *zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetAgentsRequest{
    ID: "id",
}
_, err := client.Agents.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.Update(ID, request) -> *zasp.AgentMutation</code></summary>
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

```go
request := &zasp.AgentOwnershipInput{
    ID: "id",
    IfMatch: "If-Match",
    Owner: "owner",
    Team: "team",
    Tags: []string{
        "tags",
    },
}
_, err := client.Agents.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**owner:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**team:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**tags:** `[]string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.ListCapabilities(ID) -> *zasp.CapabilityPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListCapabilitiesAgentsRequest{
    ID: "id",
}
_, err := client.Agents.ListCapabilities(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.ListRelationships(ID) -> *zasp.RelationshipPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListRelationshipsAgentsRequest{
    ID: "id",
}
_, err := client.Agents.ListRelationships(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.GetEvidencePack(ID) -> *zasp.AgentEvidencePackResponse</code></summary>
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

```go
request := &zasp.GetEvidencePackAgentsRequest{
    ID: "id",
}
_, err := client.Agents.GetEvidencePack(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**format:** `*zasp.GetEvidencePackAgentsRequestFormat` — json (default) returns the document and its rendering; markdown returns the rendering alone as a download.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.ListSessions(ID) -> *zasp.AgentSessionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSessionsAgentsRequest{
    ID: "id",
}
_, err := client.Agents.ListSessions(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Agents.GetAccess(ID) -> *zasp.AgentAccess</code></summary>
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

```go
request := &zasp.GetAccessAgentsRequest{
    ID: "id",
}
_, err := client.Agents.GetAccess(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Policies
<details><summary><code>client.Policies.List() -> *zasp.PolicyPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListPoliciesRequest{}
_, err := client.Policies.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Create(request) -> *zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CreatePoliciesRequest{
    IdempotencyKey: "Idempotency-Key",
    Body: &zasp.Policy{
        ID: "id",
        Name: "name",
        Scope: zasp.PolicyScopeEnvironment,
        Trigger: "trigger",
        Conditions: []*zasp.PolicyCondition{
            &zasp.PolicyCondition{
                Field: "field",
                Operator: zasp.PolicyConditionOperatorEquals,
                Value: "value",
            },
        },
        Action: zasp.PolicyActionMonitor,
        Rollout: zasp.PolicyRolloutStateDraft,
        FailureMode: zasp.PolicyFailureModeOpen,
    },
}
_, err := client.Policies.Create(
    context.TODO(),
    request,
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

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.Policy` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Get(ID) -> *zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetPoliciesRequest{
    ID: "id",
}
_, err := client.Policies.Get(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Delete(ID) -> error</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.DeletePoliciesRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
err := client.Policies.Delete(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Update(ID, request) -> *zasp.Policy</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.UpdatePoliciesRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.Policy{
        ID: "id",
        Name: "name",
        Scope: zasp.PolicyScopeEnvironment,
        Trigger: "trigger",
        Conditions: []*zasp.PolicyCondition{
            &zasp.PolicyCondition{
                Field: "field",
                Operator: zasp.PolicyConditionOperatorEquals,
                Value: "value",
            },
        },
        Action: zasp.PolicyActionMonitor,
        Rollout: zasp.PolicyRolloutStateDraft,
        FailureMode: zasp.PolicyFailureModeOpen,
    },
}
_, err := client.Policies.Update(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.Policy` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Rollout(ID, request) -> *zasp.PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.RolloutPoliciesRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.PolicyRolloutInput{
        State: zasp.PolicyRolloutInputStateMonitor,
        TargetID: "target_id",
    },
}
_, err := client.Policies.Rollout(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.PolicyRolloutInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Simulate(ID, request) -> *zasp.PolicySimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.SimulatePoliciesRequest{
    ID: "id",
    Body: &zasp.PolicySimulationInput{
        StringUnknownMap: map[string]any{
            "key": "value",
        },
    },
}
_, err := client.Policies.Simulate(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.PolicySimulationInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.ListDecisions(ID) -> *zasp.RuntimeDecisionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListDecisionsPoliciesRequest{
    ID: "id",
}
_, err := client.Policies.ListDecisions(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Policies.Disable(ID, request) -> *zasp.PolicyRollout</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.DisablePoliciesRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: map[string]any{
        "key": "value",
    },
}
_, err := client.Policies.Disable(
    context.TODO(),
    request,
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

**id:** `zasp.PolicyID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `zasp.EmptyInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## MCP servers
<details><summary><code>client.McpServers.List() -> *zasp.McpServerPage</code></summary>
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

```go
request := &zasp.ListMcpServersRequest{}
_, err := client.McpServers.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.McpServers.ListRegistry() -> *zasp.McpRegistryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
_, err := client.McpServers.ListRegistry(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.McpServers.PutRegistryEntry(request) -> *zasp.McpRegistryEntry</code></summary>
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

```go
request := &zasp.McpRegistryInput{
    Identity: "identity",
    Status: zasp.McpRegistryInputStatusApproved,
    Note: "note",
    ExpectedVersion: 1,
}
_, err := client.McpServers.PutRegistryEntry(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**identity:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `zasp.McpRegistryInputStatus` 
    
</dd>
</dl>

<dl>
<dd>

**note:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**expectedVersion:** `int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Identities
<details><summary><code>client.Identities.List() -> *zasp.InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListIdentitiesRequest{}
_, err := client.Identities.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Identities.Get(ID) -> *zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetIdentitiesRequest{
    ID: "id",
}
_, err := client.Identities.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Runtimes
<details><summary><code>client.Runtimes.List() -> *zasp.InventoryPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListRuntimesRequest{}
_, err := client.Runtimes.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Runtimes.Get(ID) -> *zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetRuntimesRequest{
    ID: "id",
}
_, err := client.Runtimes.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Assets
<details><summary><code>client.Assets.Get(ID) -> *zasp.InventoryDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetAssetsRequest{
    ID: "id",
}
_, err := client.Assets.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Findings
<details><summary><code>client.Findings.List() -> *zasp.FindingPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListFindingsRequest{}
_, err := client.Findings.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Findings.Get(ID) -> *zasp.Finding</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetFindingsRequest{
    ID: "id",
}
_, err := client.Findings.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Findings.Update(ID, request) -> *zasp.Finding</code></summary>
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

```go
request := &zasp.UpdateFindingsRequest{
    ID: "id",
    IfMatch: "If-Match",
    Body: &zasp.FindingUpdateInput{
        Status: zasp.FindingUpdateInputStatusOpen,
    },
}
_, err := client.Findings.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.FindingUpdateInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Findings.AcceptRisk(ID, request) -> *zasp.Finding</code></summary>
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

```go
request := &zasp.AcceptRiskFindingsRequest{
    ID: "id",
    IfMatch: "If-Match",
    Body: &zasp.FindingAcceptanceInput{
        Reason: "reason",
    },
}
_, err := client.Findings.AcceptRisk(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.FindingAcceptanceInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Findings.CreateTicket(ID) -> *zasp.FindingTicket</code></summary>
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

```go
request := &zasp.CreateTicketFindingsRequest{
    ID: "id",
    IfMatch: "If-Match",
}
_, err := client.Findings.CreateTicket(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack paths
<details><summary><code>client.AttackPaths.List() -> *zasp.AttackPathPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListAttackPathsRequest{}
_, err := client.AttackPaths.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackPaths.Get(ID) -> *zasp.AttackPath</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetAttackPathsRequest{
    ID: "id",
}
_, err := client.AttackPaths.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackPaths.GetBreakOptions(ID) -> *zasp.BreakOptionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetBreakOptionsAttackPathsRequest{
    ID: "id",
}
_, err := client.AttackPaths.GetBreakOptions(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Search
<details><summary><code>client.Search.Query() -> *zasp.SearchResultPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.QuerySearchRequest{
    Q: "q",
}
_, err := client.Search.Query(
    context.TODO(),
    request,
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

**q:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agents
<details><summary><code>client.SecurityAgents.ListTemplates() -> *zasp.SecurityAgentTemplatePage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
_, err := client.SecurityAgents.ListTemplates(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.ListActions() -> *zasp.SecurityActionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
_, err := client.SecurityAgents.ListActions(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.List() -> *zasp.SecurityAgentPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSecurityAgentsRequest{}
_, err := client.SecurityAgents.List(
    context.TODO(),
    request,
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

**cursor:** `*zasp.Cursor` — Opaque cursor returned by the preceding page.
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` — Maximum number of records to return.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Create(request) -> *zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CreateSecurityAgentsRequest{
    IdempotencyKey: "Idempotency-Key",
    Body: &zasp.SecurityAgentInput{
        Name: "name",
        TriggerKind: zasp.SecurityAgentInputTriggerKindFinding,
        TriggerSource: "trigger_source",
        EnvironmentIDs: []zasp.ProductID{
            "environment_ids",
        },
        Autonomy: zasp.SecurityAgentInputAutonomySupervised,
        MaxSteps: 1,
        MaxDurationSeconds: 1,
        TemporaryPolicySeconds: 1,
        AiTokenBudget: 1,
        ConcurrencyLimit: 1,
        AllowedActions: []string{
            "allowed_actions",
        },
        VerificationKind: "verification_kind",
        DefinitionVersion: 1,
        Enabled: true,
    },
}
_, err := client.SecurityAgents.Create(
    context.TODO(),
    request,
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

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.SecurityAgentInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Get(ID) -> *zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetSecurityAgentsRequest{
    ID: "id",
}
_, err := client.SecurityAgents.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Delete(ID) -> error</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.DeleteSecurityAgentsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
err := client.SecurityAgents.Delete(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Update(ID, request) -> *zasp.SecurityAgentDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.UpdateSecurityAgentsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.SecurityAgentDefinition{
        ID: "id",
        Name: "name",
        TriggerKind: zasp.SecurityAgentDefinitionTriggerKindFinding,
        TriggerSource: "trigger_source",
        EnvironmentIDs: []zasp.ProductID{
            "environment_ids",
        },
        Autonomy: zasp.SecurityAgentDefinitionAutonomySupervised,
        MaxSteps: 1,
        MaxDurationSeconds: 1,
        TemporaryPolicySeconds: 1,
        AiTokenBudget: 1,
        ConcurrencyLimit: 1,
        AllowedActions: []string{
            "allowed_actions",
        },
        VerificationKind: "verification_kind",
        DefinitionVersion: 1,
        Enabled: true,
    },
}
_, err := client.SecurityAgents.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.SecurityAgentDefinition` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.GetActivation(ID) -> *zasp.SecurityAgentActivationState</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetActivationSecurityAgentsRequest{
    ID: "id",
}
_, err := client.SecurityAgents.GetActivation(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Simulate(ID, request) -> *zasp.SecurityAgentSimulation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.SecurityAgentSimulationInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Goal: "goal",
    EnvironmentID: "environment_id",
    EvidenceIDs: []zasp.ProductID{
        "evidence_ids",
    },
}
_, err := client.SecurityAgents.Simulate(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**goal:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**environmentID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**evidenceIDs:** `[]zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgents.Run(ID, request) -> *zasp.SecurityAgentRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.RunSecurityAgentsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Body: &zasp.SecurityAgentManualRunInput{
        SecurityAgentLegacyTriggerInput: &zasp.SecurityAgentLegacyTriggerInput{
            EnvironmentID: "environment_id",
        },
    },
}
_, err := client.SecurityAgents.Run(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**request:** `*zasp.SecurityAgentManualRunInput` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent runs
<details><summary><code>client.SecurityAgentRuns.List() -> *zasp.SecurityAgentRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSecurityAgentRunsRequest{}
_, err := client.SecurityAgentRuns.List(
    context.TODO(),
    request,
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

**agentID:** `*zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**status:** `*zasp.SecurityAgentRunState` 
    
</dd>
</dl>

<dl>
<dd>

**environmentID:** `*zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentRuns.Get(ID) -> *zasp.SecurityAgentRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetSecurityAgentRunsRequest{
    ID: "id",
}
_, err := client.SecurityAgentRuns.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**zaspBudgetDetails:** `*string` — Request optional budget_stop_reason details with v1. Omitted or unsupported values preserve the legacy response shape. Older servers may omit the reason even when requested.
    
</dd>
</dl>

<dl>
<dd>

**zaspRunContext:** `*string` — Request optional trigger and redacted AI rationale with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit run_context.
    
</dd>
</dl>

<dl>
<dd>

**zaspActionDetails:** `*string` — Request optional persisted action details with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit action_details. Independent of budget and run-context negotiation.
    
</dd>
</dl>

<dl>
<dd>

**zaspRunLifecycle:** `*string` — Request the optional stop_reason and closure with exactly one v1 value. Omitted, duplicate or unsupported values preserve the legacy shape. Older servers may omit both. Independent of the other negotiations.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentRuns.Cancel(ID) -> *zasp.SecurityAgentCancellation</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CancelSecurityAgentRunsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
_, err := client.SecurityAgentRuns.Cancel(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentRuns.Close(ID, request) -> *zasp.SecurityAgentRunClosed</code></summary>
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

```go
request := &zasp.SecurityAgentRunCloseRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Reason: zasp.SecurityAgentRunCloseReasonNoActionRequired,
}
_, err := client.SecurityAgentRuns.Close(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**reason:** `zasp.SecurityAgentRunCloseReason` 
    
</dd>
</dl>

<dl>
<dd>

**note:** `*string` — Optional single-line justification kept with the closure and its audit event.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentRuns.GetCleanupRecovery(ID) -> *zasp.SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetCleanupRecoverySecurityAgentRunsRequest{
    ID: "id",
}
_, err := client.SecurityAgentRuns.GetCleanupRecovery(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentRuns.RequestCleanupRecovery(ID, request) -> *zasp.SingleTestCleanupRecovery</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.RequestCleanupRecoverySecurityAgentRunsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    DefinitionVersion: 1,
    InputDigest: "input_digest",
    Diagnostic: zasp.RequestCleanupRecoverySecurityAgentRunsRequestDiagnosticHistoryUnavailable,
    StopOriginal: "stop_original",
}
_, err := client.SecurityAgentRuns.RequestCleanupRecovery(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**definitionVersion:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**inputDigest:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**diagnostic:** `zasp.RequestCleanupRecoverySecurityAgentRunsRequestDiagnostic` 
    
</dd>
</dl>

<dl>
<dd>

**stopOriginal:** `string` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Security Agent approvals
<details><summary><code>client.SecurityAgentApprovals.List() -> *zasp.SecurityAgentApprovalPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListSecurityAgentApprovalsRequest{}
_, err := client.SecurityAgentApprovals.List(
    context.TODO(),
    request,
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

**state:** `*zasp.ListSecurityAgentApprovalsRequestState` 
    
</dd>
</dl>

<dl>
<dd>

**runID:** `*zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**cursor:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>

<dl>
<dd>

**zaspApprovalContext:** `*string` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.SecurityAgentApprovals.Get(ID) -> *zasp.SecurityAgentApproval</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetSecurityAgentApprovalsRequest{
    ID: "id",
}
_, err := client.SecurityAgentApprovals.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**zaspApprovalContext:** `*string` — Only one exact v1 value opts into legacy persisted approval context. Validated enriched finding-response approvals always include their complete bound context, regardless of this header; other approvals retain legacy negotiation.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Home
<details><summary><code>client.Home.GetSummary() -> *zasp.HomeSummary</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
_, err := client.Home.GetSummary(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Recovery
<details><summary><code>client.Recovery.StartBackup(request) -> *zasp.RecoveryBackup</code></summary>
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

```go
request := &zasp.RecoveryBackupInput{
    ZaspFreshAuth: zasp.StartBackupRecoveryRequestXZaspFreshAuthConfirmed,
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    BackupID: "backup_id",
    RetentionDays: 1,
}
_, err := client.Recovery.StartBackup(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `zasp.StartBackupRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**backupID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**retentionDays:** `int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Recovery.GetBackup(ID) -> *zasp.RecoveryBackup</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetBackupRecoveryRequest{
    ID: "id",
}
_, err := client.Recovery.GetBackup(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Recovery.StartRestore(request) -> *zasp.RecoveryRestore</code></summary>
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

```go
request := &zasp.RecoveryRestoreInput{
    ZaspFreshAuth: zasp.StartRestoreRecoveryRequestXZaspFreshAuthConfirmed,
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    RestoreID: "restore_id",
    TargetEnvironment: "target_environment",
    Manifest: &zasp.RecoveryManifestLocator{
        Reference: "reference",
        VersionID: "version_id",
        Sha256: "sha256",
        SizeBytes: 1,
        MediaType: zasp.RecoveryManifestLocatorMediaTypeApplicationVndZaspRecoveryManifestJSON,
        Schema: zasp.RecoveryManifestLocatorSchemaRecoverySignedManifestV1,
        SigningKeyID: "signing_key_id",
        Signature: "signature",
    },
}
_, err := client.Recovery.StartRestore(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**zaspFreshAuth:** `zasp.StartRestoreRecoveryRequestXZaspFreshAuth` — Explicit fresh-auth confirmation required for a sensitive approval or connector authorization mutation.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current execution-control version, including quoted zero before the first tenant override.
    
</dd>
</dl>

<dl>
<dd>

**restoreID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**targetEnvironment:** `zasp.RecoveryTargetEnvironment` 
    
</dd>
</dl>

<dl>
<dd>

**manifest:** `*zasp.RecoveryManifestLocator` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Recovery.GetRestore(ID) -> *zasp.RecoveryRestore</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetRestoreRecoveryRequest{
    ID: "id",
}
_, err := client.Recovery.GetRestore(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Tests
<details><summary><code>client.Tests.List() -> *zasp.TestDefinitionPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListTestsRequest{}
_, err := client.Tests.List(
    context.TODO(),
    request,
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

**cursor:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.Create(request) -> *zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.TestDefinitionInput{
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    ID: "id",
    Name: "name",
    TargetID: "target_id",
    TargetKind: zasp.TestDefinitionInputTargetKindAgentEndpoint,
    Categories: []zasp.TestDefinitionInputCategoriesItem{
        zasp.TestDefinitionInputCategoriesItemPromptInjection,
    },
    Safety: &zasp.SafetyMetadata{
        Environment: zasp.SafetyMetadataEnvironmentDevelopment,
        CredentialClass: zasp.SafetyMetadataCredentialClassReadOnly,
        ExpectedSideEffects: []string{
            "expected_side_effects",
        },
    },
}
_, err := client.Tests.Create(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**name:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**targetID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**targetKind:** `zasp.TestDefinitionInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `[]zasp.TestDefinitionInputCategoriesItem` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `*zasp.SafetyMetadata` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.Get(ID) -> *zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetTestsRequest{
    ID: "id",
}
_, err := client.Tests.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.Update(ID, request) -> *zasp.TestDefinition</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.TestDefinitionUpdateInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    Name: "name",
    TargetID: "target_id",
    TargetKind: zasp.TestDefinitionUpdateInputTargetKindAgentEndpoint,
    Categories: []zasp.TestDefinitionUpdateInputCategoriesItem{
        zasp.TestDefinitionUpdateInputCategoriesItemPromptInjection,
    },
    Safety: &zasp.SafetyMetadata{
        Environment: zasp.SafetyMetadataEnvironmentDevelopment,
        CredentialClass: zasp.SafetyMetadataCredentialClassReadOnly,
        ExpectedSideEffects: []string{
            "expected_side_effects",
        },
    },
    Enabled: true,
}
_, err := client.Tests.Update(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**name:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**targetID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**targetKind:** `zasp.TestDefinitionUpdateInputTargetKind` 
    
</dd>
</dl>

<dl>
<dd>

**categories:** `[]zasp.TestDefinitionUpdateInputCategoriesItem` 
    
</dd>
</dl>

<dl>
<dd>

**safety:** `*zasp.SafetyMetadata` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.GetSchedule(ID) -> *zasp.TestSchedule</code></summary>
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

```go
request := &zasp.GetScheduleTestsRequest{
    ID: "id",
}
_, err := client.Tests.GetSchedule(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.PutSchedule(ID, request) -> *zasp.TestSchedule</code></summary>
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

```go
request := &zasp.TestScheduleInput{
    ID: "id",
    ExpectedVersion: 1,
    Enabled: true,
    OnTargetChange: true,
}
_, err := client.Tests.PutSchedule(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**expectedVersion:** `int` 
    
</dd>
</dl>

<dl>
<dd>

**enabled:** `bool` 
    
</dd>
</dl>

<dl>
<dd>

**cadenceSeconds:** `*int` 
    
</dd>
</dl>

<dl>
<dd>

**onTargetChange:** `bool` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.Run(ID, request) -> *zasp.TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.TestRunInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    RunID: "run_id",
}
_, err := client.Tests.Run(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runID:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.Tests.GetProbeCatalog() -> *zasp.TestProbeCatalog</code></summary>
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

```go
_, err := client.Tests.GetProbeCatalog(
    context.TODO(),
)
```
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## TestRuns
<details><summary><code>client.TestRuns.List() -> *zasp.TestRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListTestRunsRequest{}
_, err := client.TestRuns.List(
    context.TODO(),
    request,
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

**cursor:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.TestRuns.Get(ID) -> *zasp.TestRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetTestRunsRequest{
    ID: "id",
}
_, err := client.TestRuns.Get(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.TestRuns.Cancel(ID) -> *zasp.TestRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CancelTestRunsRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
_, err := client.TestRuns.Cancel(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

## Attack lab
<details><summary><code>client.AttackLab.Preflight() -> *zasp.AttackLabPreflight</code></summary>
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

```go
request := &zasp.PreflightAttackLabRequest{
    SourceRunID: "source_run_id",
}
_, err := client.AttackLab.Preflight(
    context.TODO(),
    request,
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

**sourceRunID:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackLab.ListRuns() -> *zasp.AttackLabRunPage</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.ListRunsAttackLabRequest{}
_, err := client.AttackLab.ListRuns(
    context.TODO(),
    request,
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

**cursor:** `*string` 
    
</dd>
</dl>

<dl>
<dd>

**limit:** `*int` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackLab.CreateRun(request) -> *zasp.AttackLabRun</code></summary>
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

```go
request := &zasp.AttackLabRunInput{
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    RunID: "run_id",
    SourceRunID: "source_run_id",
    DecisionDigest: "decision_digest",
    Approved: true,
}
_, err := client.AttackLab.CreateRun(
    context.TODO(),
    request,
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

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**sourceRunID:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**decisionDigest:** `string` 
    
</dd>
</dl>

<dl>
<dd>

**approved:** `bool` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackLab.GetRun(ID) -> *zasp.AttackLabRunDetail</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.GetRunAttackLabRequest{
    ID: "id",
}
_, err := client.AttackLab.GetRun(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackLab.CancelRun(ID) -> *zasp.AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.CancelRunAttackLabRequest{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
}
_, err := client.AttackLab.CancelRun(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

<details><summary><code>client.AttackLab.RerunRun(ID, request) -> *zasp.AttackLabRun</code></summary>
<dl>
<dd>

#### 🔌 Usage

<dl>
<dd>

<dl>
<dd>

```go
request := &zasp.AttackLabRerunInput{
    ID: "id",
    IdempotencyKey: "Idempotency-Key",
    IfMatch: "If-Match",
    RunID: "run_id",
}
_, err := client.AttackLab.RerunRun(
    context.TODO(),
    request,
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

**id:** `zasp.ProductID` 
    
</dd>
</dl>

<dl>
<dd>

**csrfToken:** `*string` — Required for BrowserSession mutations and omitted for ProductAPIToken mutations. The value is bound to the authenticated browser session.
    
</dd>
</dl>

<dl>
<dd>

**idempotencyKey:** `string` — Caller-generated key binding an exact workflow mutation and its durable response.
    
</dd>
</dl>

<dl>
<dd>

**ifMatch:** `string` — Quoted current durable resource version.
    
</dd>
</dl>

<dl>
<dd>

**runID:** `zasp.ProductID` 
    
</dd>
</dl>
</dd>
</dl>


</dd>
</dl>
</details>

