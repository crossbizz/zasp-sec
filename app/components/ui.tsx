"use client";

import { X, Search, ChevronDown, Check, AlertTriangle, Inbox, LoaderCircle } from "lucide-react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { forwardRef, useCallback, useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import type { Severity } from "../domain/types";

type DialogStackEntry = {
  layer: HTMLDivElement;
  dialog: HTMLElement;
  invoker: HTMLElement | null;
};

const dialogStack: DialogStackEntry[] = [];
const hiddenBodyChildren = new Map<HTMLElement, { ariaHidden: string | null; inert: boolean }>();
let dialogBodyObserver: MutationObserver | null = null;

function restoreBodyChild(element: HTMLElement) {
  const previous = hiddenBodyChildren.get(element);
  if (!previous) return;
  if (previous.ariaHidden === null) element.removeAttribute("aria-hidden");
  else element.setAttribute("aria-hidden", previous.ariaHidden);
  if (previous.inert) element.setAttribute("inert", "");
  else element.removeAttribute("inert");
  hiddenBodyChildren.delete(element);
}

function hideBodyChild(element: HTMLElement) {
  if (!hiddenBodyChildren.has(element)) hiddenBodyChildren.set(element, { ariaHidden: element.getAttribute("aria-hidden"), inert: element.hasAttribute("inert") });
  element.setAttribute("aria-hidden", "true");
  element.setAttribute("inert", "");
}

function syncDialogLayers() {
  if (typeof document === "undefined") return;
  const active = dialogStack.at(-1);
  const hidden = new Set(Array.from(document.body.children).filter((element): element is HTMLElement => element instanceof HTMLElement && element !== active?.layer));
  for (const element of Array.from(hiddenBodyChildren.keys())) if (!hidden.has(element)) restoreBodyChild(element);
  for (const element of hidden) hideBodyChild(element);
  dialogStack.forEach((entry, index) => { entry.layer.style.zIndex = String(100 + index); });
  if (active) {
    if (!dialogBodyObserver) {
      dialogBodyObserver = new MutationObserver(syncDialogLayers);
      dialogBodyObserver.observe(document.body, { childList: true });
    }
  } else {
    dialogBodyObserver?.disconnect();
    dialogBodyObserver = null;
    for (const element of Array.from(hiddenBodyChildren.keys())) restoreBodyChild(element);
  }
}

function tabbableElements(dialog: HTMLElement) {
  const selector = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";
  return Array.from(dialog.querySelectorAll<HTMLElement>(selector)).filter((element) => element.tabIndex >= 0 && element.getAttribute("aria-hidden") !== "true");
}

function useAccessibleDialog(open: boolean, closeDisabled: boolean, onClose: () => void) {
  const dialogRef = useRef<HTMLElement>(null);
  const layerRef = useRef<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    const layer = layerRef.current;
    const dialog = dialogRef.current;
    if (!open || !layer || !dialog) return;
    const invoker = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const entry: DialogStackEntry = { layer, dialog, invoker };
    dialogStack.push(entry);
    syncDialogLayers();
    queueMicrotask(() => {
      if (dialogStack.at(-1) !== entry || !dialog.isConnected) return;
      (dialog.querySelector<HTMLElement>("[autofocus]") ?? tabbableElements(dialog)[0] ?? dialog).focus();
    });

    return () => {
      const index = dialogStack.indexOf(entry);
      if (index >= 0) dialogStack.splice(index, 1);
      syncDialogLayers();
      queueMicrotask(() => { if (entry.invoker?.isConnected) entry.invoker.focus(); });
    };
  }, [open]);

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    const dialog = dialogRef.current;
    if (!dialog || dialogStack.at(-1)?.dialog !== dialog) return;
    if (event.key === "Escape") {
      if (closeDisabled) return;
      event.preventDefault();
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const tabbable = tabbableElements(dialog);
    if (tabbable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = tabbable[0];
    const last = tabbable.at(-1)!;
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !dialog.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }, [closeDisabled, onClose]);

  useEffect(() => {
    if (!open) return;
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown, open]);

  return { dialogRef, layerRef };
}

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; icon?: ReactNode }>(function Button({ variant = "secondary", icon, children, className = "", ...props }, ref) {
  return <button ref={ref} className={`button button--${variant} ${className}`} {...props}>{icon}{children}</button>;
});

export function Card({ children, className = "", id, title, action }: { children: ReactNode; className?: string; id?: string; title?: ReactNode; action?: ReactNode }) {
  return <section id={id} className={`card ${className}`}>{title && <div className="card__header"><div className="card__title">{title}</div>{action}</div>}{children}</section>;
}

export function PageHeader({ title, description, eyebrow, actions }: { title: string; description?: string; eyebrow?: string; actions?: ReactNode }) {
  return <div className="page-header"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<div className="page-title-row"><h1>{title}</h1><span className="info-dot" aria-label="More information">i</span></div>{description && <p>{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

export function MetricGrid({ metrics, columns = 4 }: { metrics: Array<{ label: string; value: ReactNode; note?: string; tone?: "danger" | "success" | "brand" | "warning"; onClick?: () => void }>; columns?: number }) {
  return <div className="metric-grid" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>{metrics.map((metric) => <button type="button" onClick={metric.onClick} disabled={!metric.onClick} className={`metric metric--${metric.tone ?? "default"}`} key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong>{metric.note && <small>{metric.note}</small>}</button>)}</div>;
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: Severity | "neutral" | "success" | "brand" | "warning" | "info" }) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function Tabs({ tabs, active, onChange }: { tabs: Array<{ id: string; label: string; count?: number }>; active: string; onChange: (id: string) => void }) {
  return <div className="tabs" role="tablist">{tabs.map((tab) => <button key={tab.id} type="button" role="tab" aria-selected={active === tab.id} className={active === tab.id ? "active" : ""} onClick={() => onChange(tab.id)}>{tab.label}{typeof tab.count === "number" && <span>{tab.count}</span>}</button>)}</div>;
}

export function SearchBox({ className = "", ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <label className={`search-box ${className}`}><Search size={16} /><input type="search" {...props} /></label>;
}

export function Select({ label, children, value, onChange, disabled, className = "" }: { label?: string; children: ReactNode; value?: string | number; onChange?: React.ChangeEventHandler<HTMLSelectElement>; disabled?: boolean; className?: string }) {
  return <label className={`field ${className}`}>{label && <span>{label}</span>}<span className="select-wrap"><select value={value} onChange={onChange} disabled={disabled}>{children}</select><ChevronDown size={15} /></span></label>;
}

export function Field({ label, error, hint, multiline, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; error?: string; hint?: string; multiline?: boolean }) {
  return <label className="field"><span>{label}</span>{multiline ? <textarea value={String(props.value ?? "")} placeholder={props.placeholder} onChange={props.onChange as unknown as React.ChangeEventHandler<HTMLTextAreaElement>} /> : <input {...props} />}{hint && <small>{hint}</small>}{error && <small className="field-error">{error}</small>}</label>;
}

export function Drawer({ open, title, children, onClose, closeDisabled = false, width = "wide" }: { open: boolean; title: string; children: ReactNode; onClose: () => void; closeDisabled?: boolean; width?: "medium" | "wide" }) {
  const { dialogRef, layerRef } = useAccessibleDialog(open, closeDisabled, onClose);
  if (!open || typeof document === "undefined") return null;
  return createPortal(<div ref={layerRef} data-dialog-layer style={{ position: "relative" }}><button type="button" tabIndex={-1} aria-label="Close details" className="overlay" disabled={closeDisabled} onClick={onClose} /><aside ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className={`drawer drawer--${width}`}><div className="drawer__header"><h2>{title}</h2><button type="button" className="icon-button" disabled={closeDisabled} onClick={onClose} aria-label="Close"><X /></button></div><div className="drawer__body">{children}</div></aside></div>, document.body);
}

export function Modal({ open, title, children, onClose, closeDisabled = false, footer, size = "medium" }: { open: boolean; title: string; children: ReactNode; onClose: () => void; closeDisabled?: boolean; footer?: ReactNode; size?: "medium" | "large" | "full" }) {
  const { dialogRef, layerRef } = useAccessibleDialog(open, closeDisabled, onClose);
  if (!open || typeof document === "undefined") return null;
  return createPortal(<div ref={layerRef} data-dialog-layer style={{ position: "relative" }}><div className="modal-layer"><button type="button" tabIndex={-1} aria-label="Close modal" className="overlay" disabled={closeDisabled} onClick={onClose} /><section ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className={`modal modal--${size}`}><div className="modal__header"><h2>{title}</h2><button type="button" className="icon-button" disabled={closeDisabled} onClick={onClose} aria-label="Close"><X /></button></div><div className="modal__body">{children}</div>{footer && <div className="modal__footer">{footer}</div>}</section></div></div>, document.body);
}

export function Toast({ message, tone = "success", onClose }: { message: string; tone?: "success" | "danger"; onClose: () => void }) {
  useEffect(() => { const timeout = window.setTimeout(onClose, 3600); return () => window.clearTimeout(timeout); }, [onClose]);
  return <div className={`toast toast--${tone}`} role="status">{tone === "success" ? <Check size={17} /> : <AlertTriangle size={17} />}<span>{message}</span><button aria-label="Dismiss" onClick={onClose}><X size={15} /></button></div>;
}

export function EmptyState({ title = "No results", description = "Try a different search or reset your filters.", action }: { title?: string; description?: string; action?: ReactNode }) {
  return <div className="empty-state"><Inbox /><strong>{title}</strong><p>{description}</p>{action}</div>;
}

export function LoadingState({ label }: { label: string }) {
  return <div className="loading-state"><LoaderCircle className="spin" /><span>{label}</span></div>;
}

export function Sparkline({ values, color = "var(--brand)" }: { values: number[]; color?: string }) {
  const max = Math.max(...values); const min = Math.min(...values); const range = max - min || 1;
  const points = values.map((value, index) => `${(index / (values.length - 1)) * 100},${38 - ((value - min) / range) * 32}`).join(" ");
  return <svg className="sparkline" viewBox="0 0 100 40" preserveAspectRatio="none" aria-label={`Trend values ${values.join(", ")}`}><polyline fill="none" stroke={color} strokeWidth="2.2" points={points} vectorEffect="non-scaling-stroke" /></svg>;
}

export function DonutChart({ segments, center }: { segments: Array<{ label: string; value: number; color: string }>; center?: ReactNode }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  const gradient = segments.reduce(({ offset, stops }, segment) => {
    const nextOffset = offset + (segment.value / total) * 360;
    return { offset: nextOffset, stops: [...stops, `${segment.color} ${offset}deg ${nextOffset}deg`] };
  }, { offset: 0, stops: [] as string[] }).stops.join(", ");
  return <div className="donut-wrap"><div className="donut" style={{ background: `conic-gradient(${gradient})` }}><div>{center}</div></div><div className="chart-legend">{segments.map((segment) => <span key={segment.label}><i style={{ background: segment.color }} />{segment.label}<strong>{segment.value}</strong></span>)}</div></div>;
}

export function ProgressBar({ value }: { value: number }) {
  return <div className="progress"><div style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></div>;
}

export function Kebab() { return <button className="icon-button" aria-label="More actions">•••</button>; }
