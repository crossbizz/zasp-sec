import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import { FrameworkSurfaceReview } from "./FrameworkSurfaceReview";

it("shows the scoped release review without transferring a category's evidence to other adapters", () => {
  render(<FrameworkSurfaceReview applicability="applicable" scope="addon_supply_chain,managed_endpoint" />);
  fireEvent.click(screen.getByText("Applicability by product surface"));
  const row = (surface: string) => within(screen.getByText(surface).closest("tr") as HTMLTableRowElement);
  expect(row("Managed endpoint").getByText("Applicable")).toBeVisible();
  expect(row("Add-on supply chain").getByText("Applicable")).toBeVisible();
  expect(row("Model and data promotion").getByText("Unassessed")).toBeVisible();
  expect(screen.getAllByRole("row")).toHaveLength(7);
});
it("keeps unknown future scope vocabularies unexpanded", () => {
  render(<FrameworkSurfaceReview applicability="applicable" scope="other_surface" />);
  expect(screen.queryByText("Applicability by product surface")).toBeNull();
});
