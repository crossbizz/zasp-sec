"use client";

import * as Icons from "lucide-react";
import { NAV_GROUPS } from "../domain/routes";
import type { AppRoute } from "../domain/types";
import { Badge } from "./ui";

function Icon({ name, size = 17 }: { name: string; size?: number }) {
  const Component = (Icons as unknown as Record<string, React.ComponentType<{ size?: number }>>)[name] ?? Icons.Circle;
  return <Component size={size} />;
}

function boundedFindingCount(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 999 ? value : null;
}

export function LeftNav({ route, openFindingCount, onNavigate, onClose }: {
  route: AppRoute;
  openFindingCount: unknown;
  onNavigate: (path: string) => void;
  onClose: () => void;
}) {
  const findingCount = boundedFindingCount(openFindingCount);
  const navigate = (path: string) => {
    onNavigate(path);
    onClose();
  };

  return <>
    <button className="mobile-close icon-button" aria-label="Close navigation" onClick={onClose}><Icons.X /></button>
    <button className="account-switcher"><span className="account-logo">N</span><span>Northstar Labs<small>Production</small></span><Icons.ChevronsUpDown size={15} /></button>
    <nav aria-label="Main navigation">
      {NAV_GROUPS.map((group) => <div className="nav-group" key={group.label}>
        <div className="nav-group-label">{group.label}</div>
        {group.items.map((item) => <a
          key={item.path}
          href={item.path}
          aria-label={item.label}
          aria-current={route.path === item.path ? "page" : undefined}
          className={route.path === item.path ? "active" : ""}
          onClick={(event) => {
            event.preventDefault();
            navigate(item.path);
          }}
        ><Icon name={item.icon} /><span>{item.label}</span>{item.path === "/violations" && findingCount !== null && <Badge tone="critical"><span aria-hidden="true" data-testid="open-findings-count">{findingCount}</span></Badge>}</a>)}
      </div>)}
    </nav>
    <div className="sidebar-footer"><div className="coverage-ring">73</div><span><strong>Posture score</strong><small>+6 this month</small></span></div>
  </>;
}
