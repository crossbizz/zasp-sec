#!/bin/sh
set -eu
cd /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917
git rev-parse HEAD
git diff --stat
git ls-files --cached --others --exclude-standard services/platform/apiserver services/platform/migrations services/platform/integration | sort -u | while IFS= read -r file; do
  shasum -a 256 "$file"
done
