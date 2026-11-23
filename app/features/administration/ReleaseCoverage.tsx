import "../admin-surface-layout.css";
import { Card } from "../../components/ui";

// These describe tests shipped with this build. Live availability comes from the
// selected Environment's services, device acknowledgments and scoped receipts.
const releaseChecks = [
  ["Local skill scan", "Offline CLI, manifest drift, partial scans and findings-only submission", "Selected roots on the user's device"],
  ["Managed tool hook", "Signed policy, allowed and denied ticket calls, queued receipts and expiry", "Exact OS, package, managed settings and harness build"],
  ["Python tool integration", "Bound admission, real tool dispatch, denial and outcome persistence", "Instrumented workload and governed tool"],
  ["Browser visibility", "Managed origin allowlist, private-profile exclusion and local retention", "Managed browser profile, approved origin and delivery channel"],
  ["Guardrail recommendations", "Versioned purpose, scoped historical replay and draft review", "Agent evidence, sampling window and applied policy revision"],
  ["Staging ticket verification", "Correlated decision, independent target readback and recorder failure", "Authorized staging target and run-specific evidence"],
] as const;

export function ReleaseCoverage({ version }: { version: string }) {
  return (
    <Card title="Release test coverage">
      <p>Build {version}. Use the fleet and run records to verify a deployment against these tests.</p>
      <div className="table-scroll">
        <table className="data-table release-checks-table">
          <caption>Test scope and evidence needed for a live deployment</caption>
          <thead><tr><th scope="col">Surface</th><th scope="col">Covered by release tests</th><th scope="col">Verify in this Environment</th></tr></thead>
          <tbody>{releaseChecks.map(([surface, tests, proof]) =>
            <tr key={surface}><th scope="row">{surface}</th><td>{tests}</td><td>{proof}</td></tr>)}</tbody>
        </table>
      </div>
    </Card>
  );
}
