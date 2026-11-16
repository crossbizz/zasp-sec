"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";

const preferenceKey = "zasp.theme";
const changeEvent = "zasp-theme-change";

function subscribe(notify: () => void) {
  const system = window.matchMedia?.("(prefers-color-scheme: dark)");
  const sync = () => {
    let saved: string | null = null;
    try { saved = localStorage.getItem(preferenceKey); } catch { /* Use the system preference when storage is unavailable. */ }
    document.documentElement.dataset.theme = saved === "dark" || saved === "light" ? saved : system?.matches ? "dark" : "light";
    notify();
  };
  window.addEventListener(changeEvent, notify);
  window.addEventListener("storage", sync);
  system?.addEventListener("change", sync);
  return () => {
    window.removeEventListener(changeEvent, notify);
    window.removeEventListener("storage", sync);
    system?.removeEventListener("change", sync);
  };
}

export function ThemeControl() {
  const theme = useSyncExternalStore(subscribe, () => document.documentElement.dataset.theme ?? "light", () => "light");
  const label = `Switch to ${theme === "dark" ? "light" : "dark"} theme`;
  return <button className="icon-button theme-control" type="button" aria-label={label} title={label} onClick={() => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(preferenceKey, next); } catch { /* The current tab can still change theme. */ }
    window.dispatchEvent(new Event(changeEvent));
  }}>{theme === "dark" ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}</button>;
}
