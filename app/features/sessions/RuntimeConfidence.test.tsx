import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RuntimeConfidence } from "./RuntimeConfidence";

describe("canonical confidence display", () => {
  it.each([
    ["exact", "Exact", "success", "instrumented"],
    ["strong", "Strong", "info", "lineage"],
    ["probable", "Probable", "warning", "not confirmed"],
    ["unattributed", "Unattributed", "neutral", "Unknown"],
  ] as const)("renders %s with a distinct label, tone and meaning", (value, label, tone, meaning) => {
    render(<RuntimeConfidence confidence={value} />);
    const badge = screen.getByText(label);
    expect(badge).toHaveClass("badge--" + tone);
    expect(badge.parentElement).toHaveAttribute("data-runtime-confidence", value);
    expect(badge.parentElement?.getAttribute("title")).toContain(meaning);
  });
});
