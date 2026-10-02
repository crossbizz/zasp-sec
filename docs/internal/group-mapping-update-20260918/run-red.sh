#!/bin/bash
set -eu -o pipefail
cd /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache
binary=/private/tmp/zasp-group-mapping-update-red.test
if [ "${1:-}" != "--reuse-binary" ]; then
 GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -C services/platform ./apiserver -c -o "$binary"
fi
shasum -a 256 "$binary"
run_container() {
 /usr/local/bin/docker run --rm --pull=never --name "$1" --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount "type=bind,src=$binary,dst=/mapping.test,readonly" --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /mapping.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba "${@:2}"
}
run_container zasp-group-mapping-red-enumerate -test.list '^TestGroupMappingExpectedVersionUpdateMountedPostgres$'
run_container zasp-group-mapping-red -test.run '^TestGroupMappingExpectedVersionUpdateMountedPostgres$' -test.v -test.timeout 120s
