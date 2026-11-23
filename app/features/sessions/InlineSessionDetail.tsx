"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { Button, Card } from "../../components/ui";

export function InlineSessionDetail({ title, onClose, children }: { title: string; onClose(): void; children: ReactNode }) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    const previous = document.activeElement;
    panel.current?.focus();
    return () => { if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, []);
  return <section role="dialog" aria-modal={false} aria-label={title} tabIndex={-1} ref={panel}
    onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); onClose(); } }}>
    <Card title={title} action={<Button onClick={onClose}>Close</Button>}>{children}</Card>
  </section>;
}
