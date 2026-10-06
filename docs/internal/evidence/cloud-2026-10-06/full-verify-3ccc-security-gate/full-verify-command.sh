#!/usr/bin/env bash
set -u
cd /workspace/zasp-sec
export PATH=/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin:/tmp/zasp-cloud-tools/go/bin:/tmp/zasp-cloud-tools/bin:/tmp/zasp-cloud-tools/postgres-18.3/bin:/usr/bin:/bin
export GOROOT=/tmp/zasp-cloud-tools/go
export GOTOOLCHAIN=local
export GOPROXY=direct
export GOFLAGS=-mod=readonly
node --version > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-tools.txt
npm --version >> /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-tools.txt
go version >> /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-tools.txt
/tmp/zasp-cloud-tools/bin/tini --version >> /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-tools.txt
git rev-parse HEAD > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-head-before.txt
umask > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-umask.txt
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
/tmp/zasp-cloud-tools/bin/tini -s -- npm run verify > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06.raw.log 2>&1
verify_code=$?
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git rev-parse HEAD > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-head-after.txt
printf '{"started_utc":"%s","completed_utc":"%s","exit_code":%s}\n' "$start" "$end" "$verify_code" > /tmp/zasp-cloud-evidence/full-verify-after-gateway-3ccc1455-2026-10-06-result.json
printf 'Full verify exit code: %s\n' "$verify_code"
exit "$verify_code"
