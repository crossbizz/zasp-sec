"use client";

import { useState } from "react";
import type { AttackPath, BreakOption } from "../../../apps/web/api/generated";
import { EvidenceGraph, type EvidenceEdge } from "../../components/EvidenceGraph";
import type { PathNode } from "./api";

function pathNodeLabel(node: PathNode): string {
  if (node.kind === "agent") return "Agent";
  if (node.kind === "identity") return "Identity";
  if (node.kind === "runtime") return "Runtime";
  if (node.sourceKind.endsWith("_mcp_tool")) return "MCP tool";
  if (node.sourceKind.endsWith("_mcp_server") || node.sourceKind === "aws_agentcore_gateway") return "MCP server";
  if (node.sourceKind === "aws_data_store") return "Data store";
  return node.kind === "tool" ? "Tool" : "Asset";
}

export function AttackPathEvidence({ path, nodes }: { path: AttackPath; nodes: Readonly<Record<string, PathNode>> }) {
  const [selected, setSelected] = useState(path.entry_id);
  const steps = path.node_ids.map(id => ({
    id, label: nodes[id] ? pathNodeLabel(nodes[id]) + " · " + nodes[id].name : "Object outside your access",
  }));
  const edges: EvidenceEdge[] = path.node_ids.slice(1).map((id, index) => ({
    source: path.node_ids[index], target: id,
    kind: path.state === "blocked" && path.blocked_edge === index ? "blocked" : path.state === "observed" ? "observed" : "inferred",
  }));
  return <>
    <p><span className="label">State</span> {path.state}{path.state === "blocked" && ` · blocked edge ${path.blocked_edge}`}</p>
    <EvidenceGraph label="Attack path" nodes={steps} edges={edges} selectedID={selected} onSelect={setSelected} />
    <p aria-live="polite"><span className="label">Selected object</span> <code>{selected}</code></p>
    <h3>Evidence</h3><ul>{path.evidence_ids.map(id => <li key={id}><code>{id}</code></li>)}</ul>
  </>;
}

export function PathBreakOptions({ options, nodes, error }: {
  options: readonly BreakOption[] | null; nodes: Readonly<Record<string, PathNode>>; error: string | null;
}) {
  return <section aria-label="Break path"><h3>Break path</h3>
    {error ? <p role="alert">{error}</p> : options === null ? <p role="status">Loading break options…</p>
      : options.length === 0 ? <p>No deterministic break options are available.</p>
      : options.map(option => <details key={option.kind + option.target_id}>
        <summary>{option.rank}. {option.kind === "remove_node" ? "Remove node" : "Enforce policy"} at {nodes[option.target_id]?.name ?? option.target_id}</summary>
        <dl><dt>Target</dt><dd><code>{option.target_id}</code></dd><dt>Supporting evidence</dt><dd><code>{option.evidence_id}</code></dd></dl>
      </details>)}
  </section>;
}
