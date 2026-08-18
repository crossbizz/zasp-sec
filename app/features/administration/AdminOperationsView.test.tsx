import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdminOperationsView } from "./AdminOperationsView";

describe("M7 administration and degraded-state surfaces",()=>{
  it("renders required/optional health and product guidance",()=>{render(<AdminOperationsView surface="health"/>);for(const text of ["System health","Security plane healthy","Remote telemetry degraded","Optional dependency","v1.0.0"] )expect(screen.getByText(text)).toBeVisible()});
  it("enforces retention and external-flow boundaries",()=>{render(<AdminOperationsView surface="external"/>);for(const text of ["External data flows","Identity service","Required","Product analytics","Raw security evidence prohibited"] )expect(screen.getByText(text)).toBeVisible()});
  it("keeps deterministic evidence usable during AI and index outages",async()=>{const user=userEvent.setup();render(<AdminOperationsView surface="audit"/>);expect(screen.getByText("Policy changed")).toBeVisible();await user.click(screen.getByRole("button",{name:"Explain with AI"}));expect(screen.getByText("AI explanation unavailable")).toBeVisible();expect(screen.getByText("Deterministic evidence remains available")).toBeVisible();expect(screen.getByText("Session activity degraded")).toBeVisible()});
});
