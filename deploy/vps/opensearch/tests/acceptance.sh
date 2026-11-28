#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)
scratch=$(mktemp -d)
cluster="zasp-search-drill-$(basename "$scratch" | tr '[:upper:].' '[:lower:]-')"
broker_host=opensearch.opensearch.svc.cluster.local
forward_pid=''
created=false
cleanup() {
  if [[ -n $forward_pid ]]; then kill "$forward_pid" 2>/dev/null || true; fi
  if [[ $created == true ]]; then kind delete cluster --name "$cluster" >/dev/null; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
export KUBECONFIG="$scratch/kubeconfig"
kind create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" --wait 120s
created=true
ctx="kind-$cluster"
kube=(kubectl --context "$ctx")
"${kube[@]}" create namespace opensearch
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
for item in node:opensearch-node security-admin:opensearch-security-admin; do
  cn=${item#*:}
  "${kube[@]}" -n opensearch create secret generic "opensearch-${item%%:*}-tls" \
    --from-file=ca.crt="$scratch/ca.crt" --from-file=tls.crt="$scratch/$cn.crt" --from-file=tls.key="$scratch/$cn.key"
done
helm --kube-context "$ctx" install opensearch "$root/deploy/vps/opensearch" --namespace opensearch --timeout 10m --wait
"${kube[@]}" -n opensearch get pvc data-opensearch-0
"${kube[@]}" -n opensearch port-forward --address=127.0.0.1 service/opensearch :9200 >"$scratch/forward" 2>&1 &
forward_pid=$!
for _ in {1..100}; do
  if grep -q 'Forwarding from 127.0.0.1:' "$scratch/forward"; then break; fi
  sleep .1
done
port=$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\) ->.*/\1/p' "$scratch/forward" | head -1)
[[ -n $port ]]
endpoint="https://$broker_host:$port"
tls=(curl -sS --max-time 20 --noproxy '*' --resolve "$broker_host:$port:127.0.0.1" --cacert "$scratch/ca.crt")
request() {
  local expected=$1 cert=$2 method=$3 path=$4
  shift 4
  local code
  code=$("${tls[@]}" --cert "$scratch/zasp-search-$cert.crt" --key "$scratch/zasp-search-$cert.key" \
    -X "$method" -H 'Content-Type: application/json' -o "$scratch/response" -w '%{http_code}' "$endpoint/$path" "$@")
  [[ $code == "$expected" ]] || { echo "Expected HTTP $expected, got $code ($cert $method $path)." >&2; cat "$scratch/response" >&2; exit 1; }
}
request 200 schema PUT zasp-runtime-events-v1 -d '{"settings":{"number_of_replicas":0}}'
request 200 schema PUT zasp-inventory-v1 -d '{"settings":{"number_of_replicas":0}}'
request 201 runtime PUT 'zasp-runtime-events-v1/_doc/event?refresh=true' -d '{"fixture":"runtime"}'
request 200 api GET 'zasp-runtime-events-v1/_doc/event'
grep -q '"fixture":"runtime"' "$scratch/response"
request 201 inventory PUT 'zasp-inventory-v1/_doc/entry' -d '{"fixture":"inventory"}'
request 403 api PUT 'zasp-runtime-events-v1/_doc/forbidden' -d '{}'
request 403 inventory PUT 'zasp-runtime-events-v1/_doc/forbidden' -d '{}'
request 403 runtime PUT 'zasp-inventory-v1/_doc/forbidden' -d '{}'
if "${tls[@]}" --fail -o /dev/null "$endpoint/"; then echo 'Unauthenticated certificate accepted' >&2; exit 1; fi
