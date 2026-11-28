#!/usr/bin/env node
// Lists the services/platform Go packages with tests that no other CI gate
// runs in full, so the "Platform Go packages" job can run them.
//
// A package counts as covered when a `go test -C services/platform ...`
// command without -run names it (or a `./dir/...` pattern containing it),
// either in a GitHub Actions workflow or in an npm script reachable from
// `npm run verify`. apiserver is never listed: CI runs it in named slices,
// and this job runs the tests of apiserverFeatureTestFiles.
//
// Usage:
//   node scripts/platform-go-test-packages.mjs              # ./pkg per line
//   node scripts/platform-go-test-packages.mjs --apiserver-features
//
// A new package with tests is therefore picked up without editing CI.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repositoryRoot = resolve(import.meta.dirname, "..");
const modulePath = "github.com/zasp-ai/zasp-sec/services/platform";

// apiserver is too large to run whole in CI: much of it is long soak tests
// that dedicated steps run by name, and proof tests that need captured
// evidence or exact tool builds. The Platform Go packages job runs every
// test of these feature test files (agent discovery, MCP, SaaS sign-in,
// guardrails, red team probes and schedules, provider remediation and the
// AI compliance frameworks), so a test added to one runs in CI unchanged.
export const apiserverFeatureTestFiles = [
  "addon_ci_origin_test.go",
  "addon_review_test.go",
  "agent_evidence_pack_test.go",
  "agent_action_analysis_test.go",
  "agent_purpose_test.go",
  "authorization_concurrent_checks_test.go",
  "authorization_missing_object_test.go",
  "authorization_product_statement_test.go",
  "authorization_security_agent_activity_statement_test.go",
  "browser_profile_test.go",
  "cli_login_test.go",
  "completion_ws3_postgres_test.go",
  "compliance_ai_frameworks_test.go",
  "compliance_control_evidence_test.go",
  "compliance_export_baseline_test.go",
  "framework_reporting_test.go",
  "provider_hook_installed_postgres_test.go",
  "connector_reference_revocation_test.go",
  "endpoint_fleet_test.go",
  "guardrail_handler_test.go",
  "guardrail_postgres_test.go",
  "integration_remediation_role_test.go",
  "inventory_activity_test.go",
  "inventory_relationship_ends_test.go",
  "member_lifecycle_installed_postgres_test.go",
  "member_lifecycle_repository_test.go",
  "member_management_http_test.go",
  "organization_rename_installed_postgres_test.go",
  "mcp_inventory_test.go",
  "mcp_postgres_test.go",
  "mcp_test.go",
  "product_mcp_postgres_test.go",
  "runtime_delegation_test.go",
  "policy_public_handler_test.go",
  "private_addon_upload_test.go",
  "production_error_codes_test.go",
  "red_team_probe_library_postgres_test.go",
  "red_team_probes_test.go",
  "red_team_standalone_installed_postgres_test.go",
  "red_team_statement_gate_test.go",
  "risk_frameworks_test.go",
  "saas_generic_provider_test.go",
  "saas_provider_postgres_test.go",
  "saas_reference_providers_test.go",
  "saas_sign_in_postgres_test.go",
  "saas_sign_in_test.go",
  "security_agent_remediation_installed_postgres_test.go",
  "security_agent_remediation_postgres_test.go",
  "security_agent_remediation_test.go",
  "ticket_cohort_test.go",
  "ticket_proof_test.go",
  "workflow_telemetry_test.go",
  "workload_action_test.go",
  "workload_context_test.go",
  "workload_binding_test.go",
];

// Test function names declared in Go source.
export function goTestNames(source) {
  return [...source.matchAll(/^func (Test\w*)\(\w+ \*testing\.T\)/gm)].map((match) => match[1]);
}

// The -run expression selecting exactly the tests of the feature files.
export function apiserverFeatureRun(root = repositoryRoot) {
  const names = new Set();
  for (const file of apiserverFeatureTestFiles) {
    const found = goTestNames(readFileSync(join(root, "services/platform/apiserver", file), "utf8"));
    if (found.length === 0) throw new Error(`${file} declares no test`);
    for (const name of found) names.add(name);
  }
  return `^(${[...names].sort().join("|")})$`;
}

// Splits shell text into the platform `go test` commands it contains.
export function platformGoTestCommands(text) {
  const commands = [];
  for (const line of text.split(/\r?\n/)) {
    for (const segment of line.split(/&&|\|\||;|\|/)) {
      const trimmed = segment.trim();
      if (/^go test\b/.test(trimmed) && /(^|\s)-C\s+services\/platform(\s|$)/.test(trimmed)) commands.push(trimmed);
    }
  }
  return commands;
}

// Returns the package patterns ("dir" or "dir/...") that commands run in
// full. A command with -run selects a subset and covers nothing.
export function fullyRunPatterns(commands) {
  const patterns = new Set();
  for (const command of commands) {
    const words = command.split(/\s+/);
    if (words.some((word) => word === "-run" || word.startsWith("-run=") || word === "-c")) continue;
    for (const word of words) {
      const match = /^\.\/([A-Za-z0-9_./-]+?)\/?$/.exec(word.replace(/^["']|["']$/g, ""));
      if (match) patterns.add(match[1]);
    }
  }
  return patterns;
}

export function coveredBy(patterns, pkg) {
  for (const pattern of patterns) {
    if (pattern === pkg) return true;
    if (pattern === "...") return true;
    if (pattern.endsWith("/...")) {
      const base = pattern.slice(0, -4);
      if (pkg === base || pkg.startsWith(base + "/")) return true;
    }
  }
  return false;
}

// Collects the npm scripts reachable from `name` through `npm run`.
export function reachableScripts(scripts, name) {
  const seen = new Set();
  const texts = [];
  const visit = (current) => {
    if (seen.has(current) || typeof scripts[current] !== "string") return;
    seen.add(current);
    texts.push(scripts[current]);
    for (const match of scripts[current].matchAll(/npm run ([\w:.-]+)/g)) visit(match[1]);
  };
  visit(name);
  return texts;
}

export function uncoveredPackages(packagesWithTests, sources) {
  const patterns = fullyRunPatterns(sources.flatMap(platformGoTestCommands));
  return packagesWithTests.filter((pkg) => pkg !== "apiserver" && !coveredBy(patterns, pkg)).sort();
}

function ciSources(root) {
  const workflows = join(root, ".github/workflows");
  const texts = readdirSync(workflows).filter((name) => /\.ya?ml$/.test(name)).map((name) => readFileSync(join(workflows, name), "utf8"));
  const scripts = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts ?? {};
  return [...texts, ...reachableScripts(scripts, "verify")];
}

function packagesWithTests(root) {
  const output = execFileSync("go", ["list", "-C", join(root, "services/platform"), "-f", "{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}", "./..."], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  return output.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    if (line === modulePath) return ".";
    if (!line.startsWith(modulePath + "/")) throw new Error(`unexpected package ${line}`);
    return line.slice(modulePath.length + 1);
  });
}

export function main(argv, root = repositoryRoot) {
  if (argv.includes("--apiserver-features")) return apiserverFeatureRun(root);
  const packages = uncoveredPackages(packagesWithTests(root), ciSources(root));
  if (packages.length === 0) throw new Error("no platform packages left to test; the job would test nothing");
  return packages.map((pkg) => `./${pkg}`).join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  process.stdout.write(main(process.argv.slice(2)) + "\n");
}
