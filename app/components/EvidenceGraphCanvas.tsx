"use client";

import { useMemo } from "react";
import { graphlib, layout } from "@dagrejs/dagre";
import { ReactFlow, Position, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { EvidenceGraphProps } from "./EvidenceGraph";

export default function EvidenceGraphCanvas({ nodes, edges, selectedID, onSelect, width }: EvidenceGraphProps & { width: number }) {
  const vertical = width < 560 || nodes.length > 5;
  const drawing = useMemo(() => {
    const graph = new graphlib.Graph();
    graph.setGraph({ rankdir: vertical ? "TB" : "LR", ranksep: 32, nodesep: 24, marginx: 12, marginy: 16 });
    graph.setDefaultEdgeLabel(() => ({}));
    for (const node of nodes) graph.setNode(node.id, { width: 126, height: 52 });
    for (const edge of edges) graph.setEdge(edge.source, edge.target);
    layout(graph);
    return {
      nodes: nodes.map((node): Node => {
        const { x, y } = graph.node(node.id);
        return { id: node.id, data: { label: node.label }, position: { x: x - 63, y: y - 26 }, width: 126, height: 52,
          className: "evidence-graph__node", selected: node.id === selectedID,
          targetPosition: vertical ? Position.Top : Position.Left, sourcePosition: vertical ? Position.Bottom : Position.Right };
      }),
      edges: edges.map((edge): Edge => ({ id: JSON.stringify([edge.source, edge.target]), ...edge,
        style: { stroke: edge.kind === "blocked" ? "var(--critical)" : "var(--blue)", strokeWidth: 2,
          strokeDasharray: edge.kind === "inferred" ? "5 4" : undefined } })),
      height: Math.max(120, Math.min(420, graph.graph().height ?? 120)),
    };
  }, [nodes, edges, selectedID, vertical]);

  return <div aria-hidden="true" style={{ height: drawing.height }} className="evidence-graph__canvas">
    <ReactFlow key={String(vertical) + JSON.stringify(nodes.map(node => node.id))}
      nodes={drawing.nodes} edges={drawing.edges} fitView fitViewOptions={{ padding: 0.14, maxZoom: 1 }}
      nodesDraggable={false} nodesConnectable={false} nodesFocusable={false} edgesFocusable={false}
      zoomOnScroll={false} zoomOnPinch={false} zoomOnDoubleClick={false} panOnDrag={false} preventScrolling={false}
      onNodeClick={(_, node) => onSelect?.(node.id)} proOptions={{ hideAttribution: true }} />
  </div>;
}
