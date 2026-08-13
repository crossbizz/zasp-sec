export type Severity = "critical" | "high" | "medium" | "low";
export type AssetType = "AI Agent" | "MCP Server" | "Skill" | "Model" | "RAG";
export type AssetStatus = "active" | "new" | "shadow" | "dormant";
export type IdentityType = "API Key" | "OAuth Token" | "Bearer Token" | "Service Account" | "Workload Identity";
export type IdentityLifecycle = "healthy" | "rotation_due" | "expired" | "unused" | "shared" | "unscoped";
export type ViolationStatus = "open" | "under_review" | "fixed" | "ignored";
export type PolicyStatus = "active" | "inactive" | "draft";
export type ConnectorStatus = "connected" | "disconnected" | "error";
export type ScanStatus = "queued" | "running" | "complete" | "failed";
export type GuardrailDecision = "allow" | "redact" | "review" | "block";

export interface AppRoute {
  path: string;
  label: string;
  title: string;
  icon: string;
  parent?: string;
}

export interface NavGroup {
  label?: string;
  items: AppRoute[];
}

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  provider: string;
  owner: string;
  environment: "Production" | "Staging" | "Development";
  riskScore: number;
  endpoints: number;
  interactions: number;
  violations: number;
  coverage: number;
  status: AssetStatus;
  lastSeen: string;
  discovered: string;
  identityIds: string[];
  tags: string[];
}

export interface Endpoint {
  id: string;
  assetId: string;
  method: "POST" | "GET" | "STREAM";
  path: string;
  hostname: string;
  access: "Public" | "Private" | "Internal";
  auth: "OAuth" | "API key" | "Workload" | "Unauthenticated";
  riskScore: number;
  requests: number;
  sensitiveParams: string[];
  lastSeen: string;
}

export interface SensitiveFinding {
  id: string;
  assetId: string;
  endpointId: string;
  type: "Secret" | "PII" | "Financial" | "Health" | "Source code";
  field: string;
  direction: "Request" | "Response";
  occurrences: number;
  lastSeen: string;
}

export interface ChangeEvent {
  id: string;
  assetId: string;
  kind: "New asset" | "New endpoint" | "Permission change" | "Identity change" | "Traffic spike";
  description: string;
  risk: Severity;
  time: string;
}

export interface Identity {
  id: string;
  name: string;
  provider: string;
  owner: string;
  assetId: string;
  type: IdentityType;
  access: "Read" | "Write" | "Read/Write" | "Admin";
  violationIds: string[];
  lastUsed: string;
  expiry: string;
  lifecycle: IdentityLifecycle;
  created: string;
  resources: string[];
}

export interface Violation {
  id: string;
  title: string;
  identityId?: string;
  assetId: string;
  severity: Severity;
  policyId: string;
  status: ViolationStatus;
  discovered: string;
  lastSeen: string;
  description: string;
  evidence: string;
  whyTriggered: string;
  blastRadius: string[];
  affectedResources: string[];
  remediation?: string;
  timeline: Array<{ time: string; event: string }>;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  status: PolicyStatus;
  severity: Severity;
  scopeAssetIds: string[];
  scopeIdentityIds: string[];
  violationCount: number;
  segregation: boolean;
  expirationTracking: boolean;
  flagExpired: boolean;
  maxAgeDays: number;
  warningDays: number;
  created: string;
  modified: string;
  lastTriggered: string;
  raw: string;
}

export interface GuardrailEvent {
  id: string;
  title: string;
  assetId: string;
  policyId: string;
  actor: string;
  actorType: "User" | "Service" | "IP" | "Session";
  severity: Severity;
  status: "active" | "under_review" | "ignored" | "blocked";
  decision: GuardrailDecision;
  input: string;
  output: string;
  category: string;
  hostname: string;
  time: string;
  details: string;
}

export interface GuardrailPolicy {
  id: string;
  name: string;
  description: string;
  status: PolicyStatus;
  severity: Severity;
  scopeAssetIds: string[];
  mode: "Monitor" | "Review" | "Enforce";
  filters: string[];
  piiTypes: string[];
  customPatterns: string[];
  created: string;
  blocked: number;
  reviewed: number;
}

export interface ScanFinding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  evidence: string;
  reproduction: string;
  remediation: string;
}

export interface ScanRun {
  id: string;
  targetAssetId: string;
  role: string;
  suites: string[];
  status: ScanStatus;
  progress: number;
  started: string;
  completed?: string;
  tests: number;
  findings: ScanFinding[];
}

export interface ConnectorField {
  key: string;
  label: string;
  placeholder: string;
  secret?: boolean;
}

export interface Connector {
  id: string;
  name: string;
  category: "Cloud" | "Framework" | "Model" | "Developer" | "Data" | "Security" | "Notification";
  description: string;
  status: ConnectorStatus;
  accent: string;
  fields: ConnectorField[];
  lastSync?: string;
  assetsDiscovered?: number;
}

export interface Report {
  id: string;
  name: string;
  category: "Posture" | "Discovery" | "Identity" | "Guardrails" | "Red team" | "Compliance";
  description: string;
  updated: string;
  scheduled: boolean;
  frequency?: string;
  recipient?: string;
}

export interface Notification {
  id: string;
  title: string;
  description: string;
  time: string;
  read: boolean;
  severity: Severity;
}

export interface DemoState {
  version: 1;
  assets: Asset[];
  endpoints: Endpoint[];
  sensitiveFindings: SensitiveFinding[];
  changes: ChangeEvent[];
  identities: Identity[];
  violations: Violation[];
  policies: Policy[];
  guardrailEvents: GuardrailEvent[];
  guardrailPolicies: GuardrailPolicy[];
  scans: ScanRun[];
  connectors: Connector[];
  reports: Report[];
  notifications: Notification[];
  preferences: { dateRange: string; compact: boolean };
}

export type DemoAction =
  | { type: "violation.remediate"; violationId: string; remediation: string }
  | { type: "violation.status"; violationId: string; status: ViolationStatus }
  | { type: "policy.create"; policy: Policy }
  | { type: "policy.status"; policyId: string; status: PolicyStatus }
  | { type: "guardrailPolicy.create"; policy: GuardrailPolicy }
  | { type: "guardrailEvent.status"; eventId: string; status: GuardrailEvent["status"] }
  | { type: "connector.connect"; connectorId: string }
  | { type: "connector.disconnect"; connectorId: string }
  | { type: "scan.create"; scan: ScanRun }
  | { type: "scan.complete"; scanId: string; findings: ScanFinding[] }
  | { type: "report.schedule"; reportId: string; frequency: string; recipient: string }
  | { type: "preferences.update"; preferences: Partial<DemoState["preferences"]> }
  | { type: "notifications.read" }
  | { type: "reset" };
