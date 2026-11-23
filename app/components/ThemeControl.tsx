"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { themeCookie } from "../theme";

const changeEvent = "zasp-theme-change";

function subscribe(notify: () => void) {
  const system = window.matchMedia?.("(prefers-color-scheme: dark)");
  const sync = () => {
    let saved: string | undefined;
    try { saved = document.cookie.split("; ").find(cookie => cookie.startsWith(themeCookie + "="))?.split("=")[1]; }
    catch { return; }
    document.documentElement.dataset.theme = saved === "dark" || saved === "light" ? saved : system?.matches ? "dark" : "light";
    notify();
  };
  window.addEventListener(changeEvent, notify);
  window.addEventListener("focus", sync);
  system?.addEventListener("change", sync);
  return () => {
    window.removeEventListener(changeEvent, notify);
    window.removeEventListener("focus", sync);
    system?.removeEventListener("change", sync);
  };
}

export function ThemeControl() {
  const theme = useSyncExternalStore(subscribe, () => document.documentElement.dataset.theme ?? "light", () => "light");
  const label = `Switch to ${theme === "dark" ? "light" : "dark"} theme`;
  return <button className="icon-button theme-control" type="button" aria-label={label} title={label} onClick={() => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { document.cookie = `${themeCookie}=${next}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`; }
    catch { /* The selected appearance still applies to this page. */ }
    window.dispatchEvent(new Event(changeEvent));
  }}>{theme === "dark" ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}</button>;
}
