import type { SecurityAgentOrderedDetail } from "../../../apps/web/api/generated";

export function OrderedExecution({ value }: { value: SecurityAgentOrderedDetail }) {
  return <section aria-label="Ordered execution"><h3>Ordered execution</h3>
    <p>Receipt, settlement, and cleanup are separate server reports. Missing or pending reports do not confirm an outcome.</p>
    {value.steps.length === 0 && <p>No ordered steps have been admitted.</p>}
    {value.steps.map((step) => <section key={step.step_id} aria-label={`Ordered step ${step.index + 1}`}>
      <h4>Step {step.index + 1}: {step.step_id}</h4>
      <dl>
        <dt>Action</dt><dd>{step.action}</dd><dt>State</dt><dd>{step.state}</dd><dt>Version</dt><dd>{step.version}</dd>
        <dt>Predecessor</dt><dd>{step.dependency.predecessor_step_id ?? "None"}</dd>
        <dt>Required receipt kind</dt><dd>{step.dependency.required_receipt_kind ?? "None"}</dd>
        <dt>Dependency satisfied</dt><dd>{String(step.dependency.satisfied)}</dd>
        <dt>Dependency blocked</dt><dd>{String(step.dependency.blocked)}</dd>
        <dt>Dependency ready</dt><dd>{String(step.dependency.ready)}</dd>
        <dt>Authorization</dt><dd>{step.authorization}</dd>
        <dt>Approval state</dt><dd>{step.approval.state}</dd><dt>Approval version</dt><dd>{step.approval.version}</dd>
        <dt>Approval ID</dt><dd>{step.approval.approval_id ?? "None"}</dd>
        {step.receipt ? <><dt>Receipt kind</dt><dd>{step.receipt.kind}</dd><dt>Receipt version</dt><dd>{step.receipt.version}</dd><dt>Receipt digest</dt><dd>{step.receipt.digest}</dd><dt>Receipt reference</dt><dd>{step.receipt.reference}</dd></> : <><dt>Receipt</dt><dd>No receipt reported</dd></>}
        <dt>Settlement</dt><dd>{step.settlement}</dd>
        <dt>Cleanup state</dt><dd>{step.cleanup.state}</dd><dt>Cleanup version</dt><dd>{step.cleanup.version}</dd>
        <dt>Cleanup attempt</dt><dd>{step.cleanup.attempt}</dd><dt>Cleanup partial</dt><dd>{String(step.cleanup.partial)}</dd>
        <dt>Cleanup cleaned</dt><dd>{String(step.cleanup.cleaned)}</dd>
      </dl>
    </section>)}
  </section>;
}
