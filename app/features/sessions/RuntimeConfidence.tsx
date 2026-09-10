import type { RuntimeSessionEvent } from "../../../apps/web/api/generated";
import { Badge } from "../../components/ui";

const display = {
  exact: { label: "Exact", tone: "success", meaning: "Explicit instrumented agent and session association." },
  strong: { label: "Strong", tone: "info", meaning: "A unique observed lineage association." },
  probable: { label: "Probable", tone: "warning", meaning: "Possible association; agent and session are not confirmed." },
  unattributed: { label: "Unattributed", tone: "neutral", meaning: "Unknown agent and session association." },
} as const;

export function RuntimeConfidence({ confidence }: { confidence: RuntimeSessionEvent["confidence"] }) {
  const value = display[confidence];
  return <span data-runtime-confidence={confidence} title={value.meaning}><Badge tone={value.tone}>{value.label}</Badge></span>;
}
