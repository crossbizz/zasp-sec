# M1-35 Base Web Shell Design

## Decision

M1-35 turns the existing browser-local prototype shell into the exact product
information-architecture boundary selected by the PRD. It keeps the current
working page surfaces and client-side navigation mechanism, extracts a dedicated
`LeftNav` component, and replaces the prototype-only navigation catalog with the
PRD's small MVP catalog.

The task also adds a dependency-free unauthenticated-route guard scaffold. The
scaffold is a pure decision boundary plus a presentational component with
injected session state and redirect handling. It does not import Stytch, read a
cookie or token, call an API, claim that authentication exists, or protect a
server route. M2-01 and M2-02 own the Stytch adapter and real session middleware.

The current browser-local product prototype remains runnable. Existing rich demo
surfaces are reused where their purpose matches an MVP label; future MVP routes
render the shell's bounded placeholder heading until their owning plan tasks
implement the surface. No OSS project or provider dashboard becomes a product
navigation label.

## Exact navigation contract

The left navigation contains these groups and labels, in this exact order:

| Group | Labels |
| --- | --- |
| Home | Overview |
| Inventory | Agents; Tools & MCP; Identities; Runtimes |
| Exposure | Findings; Attack Paths |
| Test | Red Team; Attack Lab |
| Protect | Policies; Security Agents; Approvals |
| Investigate | Sessions |
| Compliance | Evidence |
| Integrations | Connections; Sensors |
| Administration | Identity & Access; Audit Log; Data & Retention; External Data Flows; System Health; API Access |

The exact route registry is:

| Label | Path | Current surface |
| --- | --- | --- |
| Overview | `/` | existing overview |
| Agents | `/discovery/assets` | existing agentic-assets surface |
| Tools & MCP | `/inventory/tools` | bounded placeholder |
| Identities | `/identities` | existing identity surface |
| Runtimes | `/inventory/runtimes` | bounded placeholder |
| Findings | `/violations` | existing finding/violation surface |
| Attack Paths | `/exposure/attack-paths` | bounded placeholder |
| Red Team | `/red-team/results` | existing results surface |
| Attack Lab | `/test/attack-lab` | bounded placeholder |
| Policies | `/policies` | existing policy surface |
| Security Agents | `/protect/security-agents` | bounded placeholder |
| Approvals | `/protect/approvals` | bounded placeholder |
| Sessions | `/investigate/sessions` | bounded placeholder |
| Evidence | `/compliance/evidence` | bounded placeholder |
| Connections | `/connectors` | existing connector surface |
| Sensors | `/integrations/sensors` | bounded placeholder |
| Identity & Access | `/administration/identity-access` | bounded placeholder |
| Audit Log | `/administration/audit-log` | bounded placeholder |
| Data & Retention | `/administration/data-retention` | bounded placeholder |
| External Data Flows | `/administration/external-data-flows` | bounded placeholder |
| System Health | `/administration/system-health` | bounded placeholder |
| API Access | `/administration/api-access` | bounded placeholder |

Paths are unique, absolute, lowercase, and contain only `/` plus ASCII
lowercase letters and hyphens. Labels and group names are unique. The registry
is a deeply immutable literal: consumers receive readonly groups/items and do
not mutate navigation state.

The route fallback remains Overview so an unknown browser-local prototype path
does not create an unbounded dynamic surface. This is a UI fallback only; it is
not an authorization decision.

## Product-only label boundary

The shell and navigation must not render any implementation/vendor label. The
negative catalog is exact and case-insensitive:

- Cartography
- Prowler
- Nango
- Promptfoo
- Neo4j
- Tetragon
- OpenTelemetry
- LocalStack
- Stytch

`Stytch` is included because M1-35 exposes a product sign-in boundary, not a
vendor-branded authentication surface. Future identity work may identify the
selected provider in technical documentation, but product navigation remains
provider-neutral.

## Left-nav component

`app/components/LeftNav.tsx` owns only navigation presentation:

- the mobile close control;
- the fixed Organization/Environment display already used by the prototype;
- exact group headings and links from the immutable registry;
- active-route presentation;
- the open-Findings badge supplied as a bounded nonnegative integer; and
- the existing posture footer.

`AppShell` owns product chrome, local demo search/notifications/settings state,
and mobile overlay state. It passes the current route, navigate callback, close
callback, and open-finding count into `LeftNav`. `LeftNav` does not read the
browser, product store, authentication, provider state, credentials, or
network.

Every link is a real `<a href>` with client navigation enhancement. This keeps
the path visible and keyboard-accessible even though the current prototype
does not yet use generated product API routes.

## Unauthenticated-route guard scaffold

The public route catalog contains only exact `/sign-in`. All other paths,
including unknown paths, are protected by the scaffold.

```ts
type SessionState = "loading" | "unauthenticated" | "authenticated";

type RouteAccess =
  | { action: "pending" }
  | { action: "render" }
  | { action: "redirect"; path: "/" | "/sign-in" };

function resolveRouteAccess(pathname: string, state: SessionState): RouteAccess;
```

The exact state table is:

| Session state | `/sign-in` | every other path |
| --- | --- | --- |
| `loading` | pending | pending |
| `unauthenticated` | render | redirect to `/sign-in` |
| `authenticated` | redirect to `/` | render |

The resolver accepts only a canonical pathname: a nonempty absolute path with
no query, fragment, backslash, control byte, repeated slash, dot segment,
percent encoding, or trailing slash except `/`. Invalid path or session input
fails closed as `pending`; it never constructs a redirect from attacker input.

`UnauthenticatedRouteGuard` consumes the resolver decision. It renders its
children only for `render`, renders one fixed status for `pending`, and invokes
the injected redirect callback for `redirect` while rendering the same fixed
status. Redirect targets are closed literals, so there is no open-redirect
input.

The component is deliberately not wired to a fabricated authenticated state in
M1-35. M2-02 will connect the scaffold to real session middleware. Until then,
the current demo shell remains explicitly browser-local and unauthenticated, as
documented in the repository README.

## Accessibility and responsive behavior

The existing responsive top bar/sidebar CSS remains the visual baseline.
`LeftNav` retains `nav aria-label="Main navigation"`, link semantics, active
state, mobile close label, and deterministic DOM order. The smoke test queries
the rendered navigation by accessible roles and names rather than snapshots or
CSS selectors.

This task does not redesign colors, spacing, typography, page content, search,
notifications, workspace switching, or settings. Those existing prototype
elements remain design input and are not treated as completed production
behavior.

## Verification and completion

Tests first pin:

- the exact nine groups, 22 labels, and paths;
- unique labels/paths and immutable readonly catalog use;
- all 22 accessible links rendered once in exact order;
- active-route and click behavior;
- no negative-catalog OSS/provider label in the registry or rendered nav;
- the complete route-guard state table;
- canonical-path rejection and closed redirect targets;
- guard component render, pending, and redirect behavior;
- preservation of existing Overview, Agents, Identities, Findings, Policies,
  Red Team, and Connections demo surfaces; and
- M1-34 Complete, M1-35 lifecycle status, M1-36a Pending, and exact blockers.

The count is 22 labels including Overview. M1-35 may move to Complete only
after genuine RED/GREEN, six focused passes, full pinned repository
verification, typecheck, lint, production build, production dependency audit,
dependency validation, diff checks, pinned secret scans, zero-finding
whole-range review, push, and exact-SHA Runnable UI success.

M1-36a remains Pending. M2-01/M2-02 own real authentication, and later route
tasks own API-backed page behavior.
