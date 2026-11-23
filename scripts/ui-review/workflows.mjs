import assert from 'node:assert/strict';
import { id } from './fixtures.mjs';

// These examples stop at the review action. No mutation leaves the browser.
export async function captureWorkflows({page, open, capture}) {
  async function readyButton(title, route, name, context = []) {
    const action = page.getByRole('button', {name, exact: true});
    await action.waitFor({state:'visible'});
    assert(await action.isEnabled(), `Expected a reviewable action: ${name}`);
    await capture(title, route, 'Ready to submit', action, context);
  }

  await open('/policies');
  await page.getByRole('button', {name:'Review agent purpose', exact:true}).click();
  await page.getByRole('combobox', {name:/^Agent(?: |$)/}).selectOption(id(100));
  await page.getByLabel('Filter tools by name', {exact:true}).fill('Platform tool 2');
  const selection = page.getByRole('checkbox', {name:'Platform tool 2', exact:true});
  await selection.check();
  await readyButton('Retain a revised purpose declaration', '/policies', 'Save agent purpose',
    [selection.locator('..'), page.getByText('Purpose revision 2', {exact:true})]);

  await open('/policies');
  await page.getByRole('button', {name:'Open Review unapproved tool calls', exact:true}).click();
  await page.getByLabel('Replay agent ID', {exact:true}).fill(id(100));
  await page.getByLabel('Replay from (UTC)', {exact:true}).fill('2026-11-15T11:00');
  await page.getByLabel('Replay to (UTC, exclusive)', {exact:true}).fill('2026-11-15T12:00');
  await readyButton('Scope a policy replay', '/policies', 'Replay revision 1', [
    page.getByLabel('Replay agent ID', {exact:true}).locator('..'),
    page.getByLabel('Replay from (UTC)', {exact:true}).locator('..'),
    page.getByLabel('Replay to (UTC, exclusive)', {exact:true}).locator('..'),
  ]);

  await open('/integrations/sensors?device=' + id(701));
  await page.getByRole('button', {name:'Rotate device credential', exact:true}).click();
  await page.getByLabel('Replacement endpoint credential ID', {exact:true}).fill(id(711));
  await page.getByLabel('Replacement device public key', {exact:true}).fill(Buffer.alloc(32, 1).toString('base64'));
  await readyButton('Rotate device credential · review', '/integrations/sensors', 'Confirm credential rotation', [
    page.getByLabel('Replacement endpoint credential ID', {exact:true}).locator('..'),
    page.getByLabel('Replacement device public key', {exact:true}).locator('..'),
  ]);

  await open('/administration/api-access');
  await page.getByRole('combobox', {name:/^Workload credential/}).selectOption(id(715));
  const bound = page.getByLabel('Credential binding', {exact:true}), run = page.getByLabel('Security Agent run ID'), step = page.getByLabel('Approved isolation step ID');
  await bound.waitFor();
  assert((await bound.innerText()).includes(id(100)) && (await bound.innerText()).includes(id(716)), 'Expected selected agent and governed session');
  await run.fill(id(717));
  await step.fill(id(718));
  await readyButton('Bind workload identity to supervised action', '/administration/api-access', 'Apply approved isolation', [bound,run.locator('..'),step.locator('..')]);
}
