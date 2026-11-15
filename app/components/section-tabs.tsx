"use client";

import { useState, type ReactNode } from "react";

import { Tabs } from "./ui";

export type PageSection = Readonly<{ id: string; label: string; count?: number; content: ReactNode }>;

// A long page shown one section at a time. Every section stays mounted, so
// what a person typed in one is still there when they come back to it.
// stacked shows every section one after another, for a caller that embeds
// the page whole.
// active and onChange let the page choose the open section itself.
export function SectionTabs({ sections, initial, stacked = false, active: controlled, onChange }: { sections: readonly (PageSection | false | null | undefined)[]; initial?: string; stacked?: boolean; active?: string; onChange?: (id: string) => void }) {
  const shown = sections.filter((section): section is PageSection => Boolean(section));
  const [local, setLocal] = useState(initial ?? shown[0]?.id ?? "");
  const requested = controlled ?? local;
  const setRequested = (id: string) => { setLocal(id); onChange?.(id); };
  if (shown.length === 0) return null;
  if (stacked) return <>{shown.map((section) => <div key={section.id}>{section.content}</div>)}</>;
  if (shown.length === 1) return <>{shown[0].content}</>;
  const active = shown.some((section) => section.id === requested) ? requested : shown[0].id;
  return <>
    <div className="page-tabs"><Tabs active={active} onChange={setRequested} tabs={shown.map(({ id, label, count }) => ({ id, label, count }))} /></div>
    {shown.map((section) => <div key={section.id} role="tabpanel" aria-label={section.label} hidden={section.id !== active}>{section.content}</div>)}
  </>;
}
