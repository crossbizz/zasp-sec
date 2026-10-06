#!/usr/bin/env bash
set -u
cd /workspace/zasp-sec
export PATH=/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin:/tmp/zasp-cloud-tools/go/bin:/tmp/zasp-cloud-tools/bin:/tmp/zasp-cloud-tools/postgres-18.3/bin:/usr/bin:/bin
export GOROOT=/tmp/zasp-cloud-tools/go
export GOTOOLCHAIN=local
export GOPROXY=direct
export GOFLAGS=-mod=readonly
umask 077
git rev-parse HEAD > /tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-head-before.txt
node --version > /tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-tools.txt
npm --version >> /tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-tools.txt
for task in build production:imports:compiled implementation:status:check; do
  /tmp/zasp-cloud-tools/bin/tini -s -- npm run "$task" > "/tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-${task//:/-}.raw.log" 2>&1
  result=$?
  printf '%s %s\n' "$task" "$result" >> /tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-results.txt
  if [ "$result" -ne 0 ]; then exit "$result"; fi
done
git rev-parse HEAD > /tmp/zasp-cloud-evidence/scoped-tail-after-full-verify-3ccc-2026-10-06-head-after.txt
