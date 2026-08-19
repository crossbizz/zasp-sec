import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { Drawer, Modal } from "./ui";

function ModalHarness({ closeDisabled = false }: { closeDisabled?: boolean }) {
  const [open, setOpen] = useState(false);
  return <main data-testid="background"><button onClick={() => setOpen(true)}>Open modal</button><a href="#after">Background link</a><Modal open={open} title="Example modal" closeDisabled={closeDisabled} onClose={() => setOpen(false)} footer={<><button>Previous</button><button>Save</button></>}><input aria-label="Name" /></Modal></main>;
}

function DrawerHarness() {
  const [open, setOpen] = useState(false);
  return <main data-testid="background"><button onClick={() => setOpen(true)}>Open drawer</button><Drawer open={open} title="Example drawer" onClose={() => setOpen(false)}><button>Drawer action</button></Drawer></main>;
}

function NestedHarness() {
  const [parentOpen, setParentOpen] = useState(false);
  const [childOpen, setChildOpen] = useState(false);
  return <main data-testid="background"><button onClick={() => setParentOpen(true)}>Open parent</button><Drawer open={parentOpen} title="Parent drawer" onClose={() => setParentOpen(false)}><button onClick={() => setChildOpen(true)}>Open child</button><Modal open={childOpen} title="Child modal" onClose={() => setChildOpen(false)}><button>Child action</button></Modal></Drawer></main>;
}

describe("shared dialogs", () => {
  afterEach(() => {
    expect(document.querySelectorAll("[data-dialog-layer]")).toHaveLength(0);
  });

  it("moves initial focus, traps forward and reverse Tab, hides the background, and restores the invoker", async () => {
    const user = userEvent.setup();
    render(<ModalHarness />);
    const invoker = screen.getByRole("button", { name: "Open modal" });
    await user.click(invoker);

    const dialog = screen.getByRole("dialog", { name: "Example modal" });
    const close = screen.getByRole("button", { name: "Close" });
    const save = screen.getByRole("button", { name: "Save" });
    expect(close).toHaveFocus();
    const backgroundRoot = screen.getByTestId("background").parentElement;
    expect(backgroundRoot).toHaveAttribute("inert");
    expect(backgroundRoot).toHaveAttribute("aria-hidden", "true");

    await user.tab({ shift: true });
    expect(save).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    expect(dialog).toContainElement(document.activeElement as HTMLElement);

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Example modal" })).not.toBeInTheDocument();
    expect(invoker).toHaveFocus();
    expect(backgroundRoot).not.toHaveAttribute("inert");
    expect(backgroundRoot).not.toHaveAttribute("aria-hidden");
  });

  it("keeps a close-disabled dialog active on Escape and cleans up on unmount", async () => {
    const user = userEvent.setup();
    const view = render(<ModalHarness closeDisabled />);
    await user.click(screen.getByRole("button", { name: "Open modal" }));
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Example modal" })).toBeVisible();

    view.unmount();
    expect(document.querySelectorAll("[data-dialog-layer]")).toHaveLength(0);
    expect(document.body.querySelector("[inert]")).toBeNull();
  });

  it("gives drawers the same keyboard and focus behavior", async () => {
    const user = userEvent.setup();
    render(<DrawerHarness />);
    const invoker = screen.getByRole("button", { name: "Open drawer" });
    await user.click(invoker);
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Example drawer" })).not.toBeInTheDocument();
    expect(invoker).toHaveFocus();
  });

  it("keeps only the top nested dialog active and restores focus through the stack", async () => {
    const user = userEvent.setup();
    render(<NestedHarness />);
    const parentInvoker = screen.getByRole("button", { name: "Open parent" });
    await user.click(parentInvoker);
    const childInvoker = screen.getByRole("button", { name: "Open child" });
    await user.click(childInvoker);

    const layers = Array.from(document.querySelectorAll<HTMLElement>("[data-dialog-layer]"));
    expect(layers).toHaveLength(2);
    expect(layers[0]).toHaveAttribute("inert");
    expect(layers[0]).toHaveAttribute("aria-hidden", "true");
    expect(layers[1]).not.toHaveAttribute("inert");
    expect(screen.getByRole("dialog", { name: "Child modal" })).toBeVisible();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(document.querySelectorAll("[data-dialog-layer]")).toHaveLength(1));
    expect(childInvoker).toHaveFocus();
    expect(document.querySelector("[data-dialog-layer]")).not.toHaveAttribute("aria-hidden");

    await user.keyboard("{Escape}");
    expect(parentInvoker).toHaveFocus();
  });
});
