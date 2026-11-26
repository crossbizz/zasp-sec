# Search provider compatibility

Production search currently requires an Amazon OpenSearch Service endpoint. Keep the API, index writers, and schema initializer on the same configured authority. The production endpoint validators require the AWS HTTPS hostname, and the clients sign requests with workload credentials. Plaintext loopback and synthetic credentials belong to evaluation configurations.

| Workload | Current authority and dependency |
| --- | --- |
| Public inventory pages and details | The API calls scoped PostgreSQL functions such as `zasp_inventory_page` and `zasp_inventory_detail`. |
| Inventory search projection | The worker writes `zasp-inventory-v1`. Its OpenSearch driver also provides a scoped search operation, but the public inventory page/detail APIs use the SQL repository. |
| Policy replay and runtime session search | The API constructs the policy history reader, runtime-event schema reader, and configured session index from the same `ZASP_POLICY_HISTORY_ENDPOINT`. |
| Raw events, sessions and schema initialization | The search initializer uses `ZASP_OPENSEARCH_ENDPOINT` to initialize and verify inventory, raw-event and configured session schemas. Writers, queries and readiness must agree on the index generations. |

A self-hosted deployment needs an independently authenticated client on every participating writer, reader and initializer, verified TLS, workload-specific index permissions and a coordinated rebuild or migration. A new inventory writer endpoint alone cannot serve the current policy or session queries. Until a production self-hosted profile is qualified end to end, keep Amazon OpenSearch Service for production search. The local OpenSearch evaluation deployment remains available for synthetic data.
