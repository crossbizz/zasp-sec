import assert from 'node:assert/strict';
import { id } from './fixtures.mjs';

// This response is generated inside the browser test context. It never invokes a model.
export function investigationStream(route) {
  const request = route.request();
  assert(request.headers()['x-csrf-token'] && request.headers()['x-zasp-expected-scope']);
  const frames = [
    { type: 'start', messageId: id(805) }, { type: 'text-start', id: 'review' },
    { type: 'text-delta', id: 'review', delta: 'The recorded receipt confirms the block.' },
    { type: 'text-end', id: 'review' }, { type: 'finish', finishReason: 'stop' },
  ];
  return route.fulfill({ status: 200, headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'x-vercel-ai-ui-message-stream': 'v1' },
    body: frames.map(frame => 'data: ' + JSON.stringify(frame) + '\n\n').join('') + 'data: [DONE]\n\n' });
}

export async function reviewModelWorkflows(page, open, capture) {
  await open('/protect/guardrails');
  await page.getByRole('tab', { name: 'Calibration' }).click();
  await page.getByText('Detection reliability', { exact: true }).waitFor();
  await page.locator('[_echarts_instance_]').first().waitFor();
  await page.getByText('Confidence bins', { exact: true }).click();
  await page.getByRole('columnheader', { name: 'Observed rate' }).waitFor();
  await capture('Calibration confidence bins', '/protect/guardrails', 'Model review');

  await open('/protect/security-agents');
  await page.getByRole('tab', { name: 'Workflow Studio' }).click();
  await page.getByRole('button', { name: 'Session review' }).click();
  await page.getByLabel('Runtime session ID').fill(id(802));
  await page.getByRole('button', { name: 'Investigate session' }).click();
  await page.getByRole('button', { name: /Investigation from/ }).click();
  await page.getByText('The reviewed session has one blocked action.', { exact: true }).waitFor();
  await page.getByLabel('Question about this session').fill('Which outcome was recorded?');
  await page.getByRole('button', { name: 'Send question' }).click();
  await page.getByText('The recorded receipt confirms the block.', { exact: true }).waitFor();
  await capture('Saved workflow investigation', '/protect/security-agents', 'Model review');
}

export async function reviewQualification(page, open, capture, fixture) {
  const group = '**/api/v1/organization/ai-controls', controls = '**/api/v1/settings/ai-controls', jobs = '**/api/v1/ai/qualifications**';
  const model = 'review-model', provider = 'zasp_vpc_slm', purpose = 'indirect_injection_screen';
  const at = '2026-11-01T00:00:00Z', record = {id:id(810),environment_id:id(3),purpose,provider,model,requested_at:at};
  let passed = false;
  const reads = (route, patch) => route.fulfill({ json: { ...fixture(new URL(route.request().url())), ...patch }, headers: { 'Cache-Control': 'no-store' } });
  await page.route(group, route => reads(route, { ai_enabled:true, allowed_residency:'us_eu', allowed_modes:['deterministic_only',provider] }));
  await page.route(controls, route => reads(route, {mode:provider,effective_mode:provider,tier2_profile:model}));
  await page.route(jobs, async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (request.method() === 'POST' && path.endsWith('/run')) {
      assert.equal(request.headers()['x-zasp-expected-scope'], [id(1), id(2), id(3)].join('/'));
      assert(request.headers()['idempotency-key'] && request.headers()['x-csrf-token']);
      assert.deepEqual(request.postDataJSON(), {purpose,provider,model});
      return route.fulfill({status:202,json:{...record,status:'queued',finished_at:null}});
    }
    assert.equal(request.method(),'GET');
    if (path.endsWith('/runs/' + record.id)) { passed=true; return route.fulfill({json:{...record,status:'passed',finished_at:at}}); }
    return route.fulfill({json:{items:passed?[{purpose,provider,model,qualified:true,checked_at:at,evidence_digest:'sha256:'+'a'.repeat(64)}]:[]}});
  });
  try {
    await open('/administration/ai-controls');
    await page.getByRole('button', {name:'Run qualification'}).click();
    await page.getByText(/Qualification passed/).waitFor();
    await page.getByRole('cell', {name:'Qualified',exact:true}).waitFor();
    await capture('Qualified model job', '/administration/ai-controls','Model review');
  } finally { await page.unroute(group); await page.unroute(controls); await page.unroute(jobs); }
}
