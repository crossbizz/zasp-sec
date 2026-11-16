import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it } from "vitest";
import { ThemeControl } from "./ThemeControl";
import { Tabs } from "./ui";

afterEach(() => { localStorage.clear(); delete document.documentElement.dataset.theme; });

it("persists theme changes and follows updates from other tabs", async () => {
  document.documentElement.dataset.theme = "light";
  render(<ThemeControl />);
  await userEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
  expect(document.documentElement).toHaveAttribute("data-theme", "dark");
  expect(localStorage.getItem("zasp.theme")).toBe("dark");
  localStorage.setItem("zasp.theme", "light");
  fireEvent(window, new StorageEvent("storage", { key: "zasp.theme", newValue: "light" }));
  expect(screen.getByRole("button", { name: "Switch to dark theme" })).toBeVisible();
  expect(document.documentElement).toHaveAttribute("data-theme", "light");
});

it("moves tab focus and selection with arrow, Home and End keys", async () => {
  const { useState } = await import("react");
  function Example() {
    const [active, setActive] = useState("one");
    return <Tabs tabs={[{ id: "one", label: "One" }, { id: "two", label: "Two" }, { id: "three", label: "Three" }]} active={active} onChange={setActive} />;
  }
  render(<Example />);
  screen.getByRole("tab", { name: "One" }).focus();
  await userEvent.keyboard("{ArrowLeft}");
  expect(screen.getByRole("tab", { name: "Three" })).toHaveFocus();
  expect(screen.getByRole("tab", { name: "Three" })).toHaveAttribute("aria-selected", "true");
  await userEvent.keyboard("{Home}{ArrowRight}");
  expect(screen.getByRole("tab", { name: "Two" })).toHaveFocus();
  await userEvent.keyboard("{End}");
  expect(screen.getByRole("tab", { name: "Three" })).toHaveFocus();
});
