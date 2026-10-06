#!/usr/bin/env bash
set -u
umask 077
export TMPDIR=/workspace/.zasp-verify-tmp-0b788520-worktree
mkdir -p "$TMPDIR"
chmod 700 "$TMPDIR"
cd /workspace/.zasp-cloud-owned/full-verify-0b788520-IlZxbb
export PATH=/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin:/tmp/zasp-cloud-tools/go/bin:/tmp/zasp-cloud-tools/bin:/tmp/zasp-cloud-tools/postgres-18.3/bin:/usr/bin:/bin
export GOROOT=/tmp/zasp-cloud-tools/go
export GOTOOLCHAIN=local
export GOPROXY=direct
export GOFLAGS=-mod=readonly
node --version > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-tools.txt
npm --version >> /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-tools.txt
go version >> /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-tools.txt
/tmp/zasp-cloud-tools/bin/tini --version >> /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-tools.txt
git rev-parse HEAD > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-head-before.txt
python3 - <<'META'
import os,json
from pathlib import Path
keys=["PATH","GOROOT","GOTOOLCHAIN","GOPROXY","GOFLAGS","TMPDIR"]
Path("/tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-command-metadata.json").write_text(json.dumps({"cwd":"/workspace/.zasp-cloud-owned/full-verify-0b788520-IlZxbb","command":"tini -s -- npm run verify","environment":{k:os.environ.get(k) for k in keys},"umask":"0077","providers_or_pg_optins_added":False},indent=2)+"\n")
META
umask > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-umask.txt
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
/tmp/zasp-cloud-tools/bin/tini -s -- npm run verify > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06.raw.log 2>&1
verify_code=$?
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git rev-parse HEAD > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-head-after.txt
printf '{"started_utc":"%s","completed_utc":"%s","exit_code":%s}\n' "$start" "$end" "$verify_code" > /tmp/zasp-cloud-evidence/full-verify-0b788520-worktree-2026-10-06-result.json
printf 'Full verify exit code: %s\n' "$verify_code"
exit "$verify_code"
