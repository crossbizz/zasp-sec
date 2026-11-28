# Search provider compatibility

Production search supports Amazon OpenSearch Service with SigV4 and the dedicated VPS OpenSearch service with mutual TLS. Use the same endpoint and index generations across the API, workers and schema initializer.

| Workload | Current authority and dependency |
| --- | --- |
| Public inventory pages and details | The API calls scoped PostgreSQL functions such as `zasp_inventory_page` and `zasp_inventory_detail`. |
| Inventory search projection | The worker writes `zasp-inventory-v1`. Its OpenSearch driver also provides a scoped search operation, but the public inventory page/detail APIs use the SQL repository. |
| Policy replay and runtime session search | The API constructs the policy history reader, runtime-event schema reader, and configured session index from the same `ZASP_POLICY_HISTORY_ENDPOINT`. |
| Raw events, sessions and schema initialization | The search initializer uses `ZASP_OPENSEARCH_ENDPOINT` to initialize and verify inventory, raw-event and configured session schemas. Writers, queries and readiness must agree on the index generations. |

The Production VPS overlay sets `ZASP_OPENSEARCH_AUTH_MODE=mtls` and pins the HTTPS endpoint to `opensearch.opensearch.svc.cluster.local:9200`. Each participating pod mounts its own `ca.crt`, `tls.crt` and `tls.key` at `/var/run/secrets/zasp-opensearch`. The client verifies the service hostname against that CA and reloads the client identity on each new TLS connection. Roll the consuming deployments to load a changed CA bundle. The API reader, inventory writer, runtime writer and initializer receive separate index permissions. [OpenSearch release](../../deploy/vps/opensearch/README.md)

AWS deployments keep the default SigV4 mode. For migrations between providers, plan the index rebuild, check each schema version and verify indexed results against the authoritative records before switching all readers and writers.
