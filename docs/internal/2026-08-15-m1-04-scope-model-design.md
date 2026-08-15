# M1-04 Scope Model Design

## Decision

Add an opaque, comparable `Scope` value to the existing
`services/platform/domain` package. It contains exactly one product-owned
`ProductID` for each hierarchy level:

`Organization -> Workspace -> Environment`

All three levels are required. This is stricter than the minimum acceptance
case naming missing Organization or Environment and matches the PRD hierarchy
and backend authorization requirement to validate all three before side effects.

## Invariants

- `Scope` fields are unexported and can be populated only by `NewScope`.
- Organization, Workspace, and Environment IDs must each be valid nonzero
  `ProductID` values.
- The three IDs must be pairwise distinct; reusing one ID for multiple levels
  fails closed rather than silently collapsing hierarchy.
- The zero `Scope` and every partially populated internal value are invalid.
- `Validate` returns one fixed sentinel and never includes customer identifiers.
- Accessors expose typed `ProductID` values, not raw strings or vendor IDs.
- Scope is comparable by value and contains no mutable collection or pointer.
- This task does not prove parent-child persistence, authorization, tenant
  membership, browser selection, database predicates, or cross-Organization
  isolation; those remain in later M1/M2 tasks.
- No dependency, environment, credential, provider, network, filesystem, or
  persistence behavior is added.

## API

```go
type Scope struct { /* opaque product IDs */ }

func NewScope(organizationID, workspaceID, environmentID ProductID) (Scope, error)
func (Scope) Validate() error
func (Scope) IsZero() bool
func (Scope) OrganizationID() ProductID
func (Scope) WorkspaceID() ProductID
func (Scope) EnvironmentID() ProductID
```

## Verification

Tests must prove:

- one valid exact hierarchy constructs and round trips through accessors;
- missing Organization, Workspace, or Environment fails with `ErrInvalidScope`;
- each pairwise duplicate-level combination fails;
- zero and deliberately partial internal values fail validation;
- rejected construction returns only a zero scope;
- scopes with equal IDs are comparable/equal and different Environments differ;
- raw vendor IDs cannot enter any scope field because every constructor argument
  is a `ProductID`.

Only after focused stability, platform/service/worker/root regressions, full
repository gates, review, audit, scans, and exact-SHA CI may M1-04 become
Complete. M1-05 remains Pending. Existing blockers and R-03/R-11 remain
unchanged.
