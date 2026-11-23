"use client";

import { lazy, Suspense, useEffect, useRef, useState } from "react";
import "./evidence-graph.css";

export type EvidenceNode = Readonly<{ id: string; label: string; detail?: string }>;
export type EvidenceEdge = Readonly<{ source: string; target: string; kind: "observed" | "inferred" | "blocked" | "configured" }>;
export type EvidenceGraphProps = Readonly<{
  label: string;
  nodes: readonly EvidenceNode[];
  edges: readonly EvidenceEdge[];
  selectedID?: string;
  onSelect?: (id: string) => void;
}>;

const Canvas = lazy(() => import("./EvidenceGraphCanvas"));
const edgeLabels = { observed: "Observed", inferred: "Possible reach", blocked: "Blocked", configured: "Workflow sequence" } as const;

export function EvidenceGraph(props: EvidenceGraphProps) {
  const host = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const kinds = [...new Set(props.edges.map(edge => edge.kind))];

  useEffect(() => {
    if (!host.current || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(host.current);
    return () => observer.disconnect();
  }, []);

  return <section className="evidence-graph" aria-label={props.label}>
    <div className="evidence-graph__legend">{kinds.map(kind => <span key={kind} data-kind={kind}>{edgeLabels[kind]}</span>)}</div>
    <div ref={host}>{width > 0 && <Suspense fallback={null}><Canvas {...props} width={width} /></Suspense>}</div>
    <ol aria-label="Path steps" className="evidence-graph__steps">{props.nodes.map(node => <li key={node.id}>
      {props.onSelect
        ? <button type="button" aria-pressed={props.selectedID === node.id} onClick={() => props.onSelect?.(node.id)}>{node.label}</button>
        : <span>{node.label}</span>}
    </li>)}</ol>
  </section>;
}
