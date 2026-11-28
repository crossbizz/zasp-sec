#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)
scratch=$(mktemp -d)
cluster="zasp-search-drill-$(basename "$scratch" | tr '[:upper:].' '[:lower:]-')"
broker_host=opensearch.opensearch.svc.cluster.local
forward_pid=''
created=false
phase='create-kind-cluster'
detail=''
cleanup() {
  local result=$?
  if (( result != 0 )); then
    if [[ $phase == install-search || $phase == upgrade-search ]]; then
      "${kube[@]}" -n opensearch get pod,pvc,job --ignore-not-found >&2 || true
      for workload in statefulset/opensearch job/opensearch-security-init; do
        "${kube[@]}" -n opensearch logs "$workload" --tail=45 >> "$scratch/server-log" 2>&1 || true
      done
      cat "$scratch/server-log" >&2
      # Publish only recognized exception names or Kubernetes waiting reasons.
      detail=$(grep -Eo '[[:alnum:].]+(Exception|Error)' "$scratch/server-log" | tail -1 || true)
      if [[ -z $detail ]]; then
        detail=$("${kube[@]}" -n opensearch get pods -o jsonpath='{.items[*].status.containerStatuses[*].state.waiting.reason}' || true)
      fi
    fi
    if [[ -n ${GITHUB_OUTPUT:-} ]]; then printf 'failure=%s %s\n' "$phase" "$detail" >> "$GITHUB_OUTPUT"; fi
    printf '::error title=OpenSearch acceptance::%s %s\n' "$phase" "$detail" >&2
  fi
  if [[ -n $forward_pid ]]; then kill "$forward_pid" 2>/dev/null || true; fi
  if [[ $created == true ]]; then kind delete cluster --name "$cluster" >/dev/null || true; fi
  rm -rf -- "$scratch"
  return "$result"
}
trap cleanup EXIT
export KUBECONFIG="$scratch/kubeconfig"
created=true
kind create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" --wait 120s
ctx="kind-$cluster"
kube=(kubectl --context "$ctx")
phase=create-namespace
"${kube[@]}" create namespace opensearch
phase=issue-certificates
openssl req -new -newkey rsa:3072 -x509 -nodes -sha256 -days 2 -subj /CN=Temporary-Search-CA \
  -keyout "$scratch/ca.key" -out "$scratch/ca.crt" >/dev/null 2>&1

issue() {
  local cn=$1 usages=$2
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$scratch/$cn.key" >/dev/null 2>&1
  openssl req -new -key "$scratch/$cn.key" -subj "/CN=$cn" -out "$scratch/$cn.csr"
  cat > "$scratch/$cn.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usages
EXT
  if [[ $cn == opensearch-node ]]; then
    echo "subjectAltName=DNS:$broker_host,DNS:opensearch-0.opensearch-headless.opensearch.svc.cluster.local" >> "$scratch/$cn.ext"
  fi
  openssl x509 -req -days 2 -sha256 -in "$scratch/$cn.csr" -CA "$scratch/ca.crt" -CAkey "$scratch/ca.key" \
    -CAcreateserial -extfile "$scratch/$cn.ext" -out "$scratch/$cn.crt" >/dev/null 2>&1
}
issue opensearch-node serverAuth,clientAuth
for cn in opensearch-security-admin zasp-search-schema zasp-search-inventory zasp-search-runtime zasp-search-api; do
  issue "$cn" clientAuth
done
phase=create-server-secrets
for item in node:opensearch-node security-admin:opensearch-security-admin; do
  cn=${item#*:}
  "${kube[@]}" -n opensearch create secret generic "opensearch-${item%%:*}-tls" \
    --from-file=ca.crt="$scratch/ca.crt" --from-file=tls.crt="$scratch/$cn.crt" --from-file=tls.key="$scratch/$cn.key"
done
phase=install-search
helm --kube-context "$ctx" install opensearch "$root/deploy/vps/opensearch" --namespace opensearch --timeout 10m --wait
phase=verify-persistent-volume
claim_uid=$("${kube[@]}" -n opensearch get pvc data-opensearch-0 -o jsonpath='{.metadata.uid}')
pod_uid=$("${kube[@]}" -n opensearch get pod opensearch-0 -o jsonpath='{.metadata.uid}')
[[ -n $claim_uid && -n $pod_uid ]]
open_tunnel() {
  "${kube[@]}" -n opensearch port-forward --address=127.0.0.1 service/opensearch :9200 >"$scratch/forward" 2>&1 &
  forward_pid=$!
  for _ in {1..100}; do
    if ! kill -0 "$forward_pid" 2>/dev/null; then cat "$scratch/forward" >&2; return 1; fi
    if grep -q 'Forwarding from 127.0.0.1:' "$scratch/forward"; then break; fi
    sleep .1
  done
  port=$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\) ->.*/\1/p' "$scratch/forward" | head -1)
  [[ -n $port ]]
  endpoint="https://$broker_host:$port"
  tls=(curl -sS --max-time 20 --noproxy '*' --resolve "$broker_host:$port:127.0.0.1" --cacert "$scratch/ca.crt")
}
phase=open-private-tunnel
open_tunnel
request() {
  local expected=$1 cert=$2 method=$3 path=$4
  shift 4
  phase="$cert-$method-${path%%\?*}"
  detail=''
  local code media_type=application/json
  if [[ ${path%%\?*} == */_bulk ]]; then media_type=application/x-ndjson; fi
  code=$("${tls[@]}" --cert "$scratch/zasp-search-$cert.crt" --key "$scratch/zasp-search-$cert.key" \
    -X "$method" -H "Content-Type: $media_type" -o "$scratch/response" -w '%{http_code}' "$endpoint/$path" "$@")
  detail="expected-$expected-actual-$code"
  if [[ $code != "$expected" ]]; then
    local forbidden
    forbidden=$(sed -nE 's/.*no permissions for \[([A-Za-z0-9:_/.-]+)\].*/\1/p' "$scratch/response")
    [[ -z $forbidden ]] || detail="$detail $forbidden"
    echo "Expected HTTP $expected, got $code ($cert $method $path)." >&2
    cat "$scratch/response" >&2
    exit 1
  fi
}
request 200 schema PUT zasp-runtime-events-v1 -d '{"settings":{"number_of_replicas":0},"mappings":{"properties":{"fixture":{"type":"keyword"}}}}'
request 200 schema PUT zasp-inventory-v1 -d '{"settings":{"number_of_replicas":0},"mappings":{"properties":{"fixture":{"type":"keyword"}}}}'
request 201 schema PUT 'zasp-runtime-events-v1/_doc/schema-marker?op_type=create&refresh=wait_for' -d '{"fixture":"schema"}'
request 200 schema GET 'zasp-runtime-events-v1/_mapping'
request 201 runtime PUT 'zasp-runtime-events-v1/_doc/event?refresh=true' -d '{"fixture":"runtime"}'
request 200 api GET 'zasp-runtime-events-v1/_doc/event'
grep -q '"fixture":"runtime"' "$scratch/response"
request 201 inventory PUT 'zasp-inventory-v1/_doc/entry' -d '{"fixture":"inventory"}'
request 200 runtime POST 'zasp-runtime-events-v1/_bulk?refresh=wait_for&timeout=10s' \
  --data-binary $'{"create":{"_index":"zasp-runtime-events-v1","_id":"second"}}\n{"fixture":"bulk"}\n'
grep -q '"errors":false' "$scratch/response"
request 200 runtime POST 'zasp-runtime-events-v1/_mget' -d '{"ids":["second"]}'
grep -q '"fixture":"bulk"' "$scratch/response"
request 200 api POST 'zasp-runtime-events-v1/_search' -d '{"query":{"term":{"fixture":"runtime"}}}'
grep -q '"fixture":"runtime"' "$scratch/response"
request 403 schema PUT 'zasp-unrelated-v1' -d '{}'
request 403 api PUT 'zasp-runtime-events-v1/_doc/forbidden' -d '{}'
request 403 inventory PUT 'zasp-runtime-events-v1/_doc/forbidden' -d '{}'
request 403 runtime PUT 'zasp-inventory-v1/_doc/forbidden' -d '{}'
# REQUIRE rejects the TLS exchange itself, before any HTTP authentication.
phase=reject-missing-certificate
detail=''
if "${tls[@]}" -o /dev/null "$endpoint/"; then echo 'TLS accepted a client without a certificate' >&2; exit 1; fi

# Force an actual pod replacement through the same release, then authenticate again.
phase=upgrade-search
detail=''
kill "$forward_pid"
wait "$forward_pid" || true
forward_pid=''
helm --kube-context "$ctx" upgrade opensearch "$root/deploy/vps/opensearch" --namespace opensearch --wait --timeout 6m \
  --set-string 'javaOpts=-Xms1g -Xmx1g -Djava.net.preferIPv4Stack=true'
phase=verify-restored-index
[[ $claim_uid == "$("${kube[@]}" -n opensearch get pvc data-opensearch-0 -o jsonpath='{.metadata.uid}')" ]]
[[ $pod_uid != "$("${kube[@]}" -n opensearch get pod opensearch-0 -o jsonpath='{.metadata.uid}')" ]]
open_tunnel
request 200 api GET 'zasp-runtime-events-v1/_doc/second'
grep -q '"fixture":"bulk"' "$scratch/response"
request 403 api PUT 'zasp-runtime-events-v1/_doc/forbidden' -d '{}'
