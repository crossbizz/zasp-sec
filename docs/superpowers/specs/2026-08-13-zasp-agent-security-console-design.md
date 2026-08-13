# Zasp Agent Security Console — Product Design

## Purpose

Build a product-grade interactive prototype for **Zasp**, an agent security platform. The product borrows the proven information hierarchy and interaction density visible in the supplied Akto references while using an original Zasp brand, original product copy, and Zasp-specific data.

This release is a frontend prototype. It demonstrates the complete product surface and its primary security workflows using realistic local data. It does not include a production backend, real customer telemetry, authentication, or third-party API credentials.

## Success Criteria

- Every primary and secondary navigation item opens a relevant, finished screen.
- The interface feels like one coherent security product, not a gallery of disconnected mockups.
- Core workflows are interactive: investigate an identity, inspect and remediate a violation, create a policy, configure a guardrail, run a red-team scan, and connect an integration.
- Created or changed records remain visible after refresh through browser-local persistence.
- The application is implemented primarily in strict TypeScript.
- The interface works at common desktop and tablet widths and remains usable on mobile.
- The application completes a production build and passes automated checks for its critical flows.

## Brand and Visual Direction

The product name is **Zasp**. It must never be expanded to “Zasp Identity.”

The visual system uses a security-console aesthetic:

- A dark violet-to-indigo top bar with the Zasp wordmark, workspace switcher, global search, notifications, settings, and user menu.
- A persistent light sidebar with compact icon-and-label navigation and nested sections.
- A quiet neutral canvas with white cards, restrained borders, subtle shadows, and dense tables.
- Violet as the primary action and selection color.
- Red, coral, amber, blue, and mint status colors for severity and state.
- Clear typographic hierarchy with compact operational copy and realistic security terminology.
- Original icons, content, and layout details; no Akto logo, name, or copied proprietary text.

## Information Architecture

### Overview

The landing dashboard summarizes agent-security posture, critical findings, discovered assets, protected traffic, coverage, risk trends, and recommended actions. Metric cards and charts link into the relevant filtered workspace.

### Discovery

Discovery contains:

- Agentic assets: agents, MCP servers, skills, models, tools, and RAG components.
- Endpoints: observed agent and model endpoints, authentication state, traffic, and risk.
- Sensitive data: detected secrets, PII, credentials, and regulated-data classes.
- Recent changes: new, changed, shadow, and dormant components.
- Asset detail: relationships, endpoints, identities, findings, traffic, and activity.

### Identities

Identity governance contains:

- Summary metrics for total, risky, expiring, and violating identities.
- Searchable, sortable, filterable identity inventory.
- Identity detail drawer with overview, relationship graph, violations, activity, and available actions.
- Credential types including API keys, OAuth tokens, bearer tokens, service accounts, and workload identities.
- Lifecycle status including healthy, rotation due, expired, unused, shared, and unscoped.

### Violations

Violations contains:

- Trend and severity visualizations.
- All, open, under review, fixed, and ignored states.
- Filterable findings table with identity, component, severity, policy, and discovery time.
- Detail drawer with overview, evidence, blast radius, timeline, remediation, and action controls.
- Remediation actions such as rotate token, reduce privilege, block actor, mark fixed, ignore, and create ticket.

### Policies

Policies contains:

- Active, inactive, and draft policy inventory.
- Violation counts, scope, status, and trigger history.
- A guided policy-creation workflow with:
  - Details and scope.
  - Token segregation.
  - Expiration tracking.
  - Rotation enforcement.
  - Review and creation.
- A raw-policy mode with a typed YAML-like editor for advanced users.
- Local draft and activation persistence.

### Guardrails

Guardrails contains:

- Dashboard: protected sessions, blocked events, policies, actors, and severity distribution.
- Activity: active, under-review, and ignored guardrail events.
- Actors: users, services, IPs, and sessions attributed to events.
- Protected components: components currently covered by guardrail policies.
- Policies: configured runtime policies and their enforcement mode.
- Event detail drawer with overview, values, session context, timeline, remediation, and response actions.
- Guardrail creation workflow covering content, language safety, sensitive information, code, custom patterns, usage limits, anomaly detection, and runtime settings.
- Playground for testing example prompts against the in-progress policy.

### Red Teaming

Red Teaming contains:

- Results dashboard with category, severity, coverage, and scan trends.
- Target selection from discovered assets and endpoints.
- Scan-role and test-suite configuration.
- Scan launch, simulated progress, completion summary, and persistent history.
- Finding detail with evidence, reproduction, affected component, and remediation.

### Connectors

Connectors provides a searchable integration catalog grouped by cloud, agent framework, model provider, developer tooling, data platform, security, and notification destination. Each connector supports a setup modal, required-field validation, simulated connection test, and connected/disconnected state.

Representative connectors include AWS, Azure, Google Cloud, Kubernetes, GitHub, Slack, OpenAI, Anthropic, LangChain, LiteLLM, Snowflake, Microsoft Copilot Studio, N8N, and webhooks.

### Prompt Hardening

Prompt Hardening provides a compact workbench for testing prompts against injection, data leakage, unsafe tool use, policy bypass, and sensitive-data filters. It presents the hardened prompt, detected risks, recommended controls, and before/after comparison.

### Reports

Reports contains posture, asset, identity, violation, guardrail, red-team, and compliance summaries. Users can choose a reporting period, export CSV data, configure a simulated scheduled report, and open report details.

## Application Shell and Shared Interaction Model

The shell remains stable while feature content changes:

- Top bar: Zasp brand, environment/workspace selector, global search, notifications, settings, and profile.
- Sidebar: account selector, grouped navigation, collapsible subsections, active state, and responsive mobile drawer.
- Page header: title, supporting context, date range where relevant, secondary actions, and one primary action.
- Tables: sticky header, row selection, sorting, filters, tabs, compact status badges, and row-click detail.
- Drawers: right-side investigation surfaces that preserve table context.
- Modals and wizards: focused create or configure flows with validation and cancel/confirm behavior.
- Feedback: inline validation, loading states, empty states, toasts, and undo where safe.

## Critical User Flows

### Investigate and remediate an identity

1. Open Identities.
2. Filter to risky identities or search for a credential.
3. Open the identity drawer.
4. Inspect ownership, attached agent, permissions, relationship graph, activity, and violations.
5. Open an associated violation.
6. Apply a remediation and observe updated state and summary counts.

### Create an identity policy

1. Open Policies and select Create policy.
2. Define name, description, agent scope, and identity scope.
3. Configure token segregation, expiration tracking, and rotation enforcement.
4. Review the generated policy summary.
5. Save as draft or activate.
6. Return to the table with the new policy visible.

### Configure and test a guardrail

1. Open Guardrails > Policies and select Create guardrail.
2. Define its name, scope, mode, and severity.
3. Configure one or more filter categories.
4. Use quick prompts or a custom prompt in the playground.
5. Review the simulated allow, redact, review, or block result.
6. Save and display the policy in the inventory.

### Run a red-team scan

1. Open Red Teaming and start a scan.
2. Select a discovered target.
3. Select test categories and scan role.
4. Launch the scan and display simulated progress.
5. Open the completed result and inspect a finding.

### Connect an integration

1. Open Connectors and search or filter the catalog.
2. Open a connector.
3. Enter required configuration values.
4. Test the connection.
5. Save it and show its connected state across the catalog and overview.

## Technical Architecture

- React application with strict TypeScript.
- Route-driven feature workspaces under a shared application shell.
- Central typed domain models for assets, identities, violations, policies, guardrails, scans, connectors, reports, and notifications.
- Seed-data modules containing coherent cross-linked records.
- Feature-specific components for pages, tables, drawers, charts, and workflows.
- A small client-side store with local-storage persistence for user-created and mutated prototype state.
- CSS tokens for colors, typography, spacing, radii, elevation, and density.
- Accessible semantic controls, keyboard focus, labels, and dialog behavior.

No backend abstraction will be invented for this prototype. Data access will stay behind simple typed repository functions so a real API can replace local data later without rewriting presentation components.

## Data and State Behavior

Seed data represents a fictional enterprise environment and links all major records. For example, an agent asset references its endpoints, credentials, policies, violations, guardrail events, and scan results through stable typed identifiers.

Browser-local persistence covers:

- Created and edited policies.
- Guardrail policies and playground results.
- Connector connection state.
- Violation status and remediation history.
- Red-team scan runs.
- User display preferences such as date range and compact table density.

A “Reset demo data” control in settings restores the original seeded state.

## Error, Empty, and Loading States

- Required form fields show specific inline errors.
- Simulated connection and scan failures provide retry actions.
- Empty filtered tables explain why no results match and offer filter reset.
- Missing records route back to the relevant list with a non-destructive notice.
- Destructive-looking security actions require confirmation and update only local prototype data.
- Skeletons or concise progress indicators appear for simulated asynchronous work.

## Responsive Behavior

- Desktop: persistent sidebar, full-width dense tables, and contextual right drawers.
- Tablet: narrower sidebar, horizontally scrollable tables, and wider overlay drawers.
- Mobile: sidebar becomes a sheet; data tables collapse into summary rows or cards; drawers become full-screen panels; primary actions remain reachable.

## Verification

Verification will include:

- Type checking and a production build.
- Automated navigation coverage for every primary and secondary menu destination.
- Automated critical-flow checks for identity investigation, violation remediation, policy creation, guardrail testing, scan execution, and connector setup.
- Responsive smoke checks for desktop, tablet, and mobile breakpoints.
- Accessibility checks for named controls, keyboard traversal, visible focus, and dialog semantics.

## Out of Scope

- Production authentication, SSO, SCIM, and role enforcement.
- Real cloud, agent, model, or notification integrations.
- Backend services, durable server persistence, queues, or telemetry ingestion.
- Real scanning, blocking, token rotation, or ticket creation.
- Billing, organization administration, and multi-tenant isolation.
- Reproduction of Akto branding, proprietary copy, or hidden product behavior.

