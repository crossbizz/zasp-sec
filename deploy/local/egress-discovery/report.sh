#!/usr/bin/env bash
# Prints what the node sensors have published for runtime agent discovery:
# one line per workload and token, then totals per token. This is the
# measurement the plan asks for on a first real cluster: compare the list
# with the workloads you know call a model API (misses) and the ones you
# know do not (false positives).
#
# Usage: report.sh [--check-smoke]
#   --check-smoke  exit 1 unless smoke.yaml's egress-smoke is recorded under
#                  "anthropic" and egress-control is not recorded at all.
# Needs kubectl (current context) and jq. Reads ConfigMaps only.
set -euo pipefail
label='zasp.ai/egress-observations=v1'
documents="$(kubectl get configmaps --all-namespaces -l "$label" -o json | jq -c '[.items[].data["observations.json"] | select(. != null) | fromjson]')"
nodes="$(jq 'length' <<<"$documents")"
rows="$(jq -r '.[] as $d | $d.workloads[] | . as $w | .destinations[] | [$w.namespace, $w.kind, $w.name, .token, .last_seen, $d.node] | @tsv' <<<"$documents" | sort -u)"
echo "nodes reporting: $nodes"
if [ -z "$rows" ]; then
  echo "no workload recorded"
else
  printf 'NAMESPACE\tKIND\tNAME\tTOKEN\tLAST_SEEN\tNODE\n%s\n' "$rows"
  echo
  echo "workloads per token:"
  cut -f1-4 <<<"$rows" | sort -u | cut -f4 | sort | uniq -c | sort -rn
fi
if [ "${1:-}" = "--check-smoke" ]; then
  smoke="$(awk -F'\t' '$1=="zasp-egress-smoke" && $3=="egress-smoke" && $4=="anthropic"' <<<"$rows" | wc -l)"
  control="$(awk -F'\t' '$1=="zasp-egress-smoke" && $3=="egress-control"' <<<"$rows" | wc -l)"
  if [ "$smoke" -ge 1 ] && [ "$control" -eq 0 ]; then
    echo "smoke check: passed"
  else
    echo "smoke check: FAILED (egress-smoke recorded: $smoke, egress-control recorded: $control)" >&2
    exit 1
  fi
fi
