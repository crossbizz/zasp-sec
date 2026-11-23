import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { bootstrap, id } from './fixtures.mjs';
import { inspectLayout } from './shell-audit.mjs';
import { captureViewport } from './viewport-capture.mjs';

const origin = process.env.ZASP_UI_REVIEW_ORIGIN || 'http://localhost:3000';
const output = process.env.ZASP_UI_REVIEW_OUTPUT || 'outputs/aegis-review';
const { chromium } = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright-core');
const browser = await chromium.launch({ executablePath: process.env.ZASP_CHROMIUM || '/usr/bin/chromium', args: ['--no-sandbox'] });
const audit = [], errors = [];
await mkdir(path.join(output, 'authorization'), { recursive: true });

try {
  for (const [width, height] of [[1920,1080], [1440,1000], [1024,768], [390,844]]) {
    for (const theme of ['light', 'dark']) {
      const context = await browser.newContext({ viewport: { width, height } });
      await context.addCookies([{ name: 'zasp.theme', value: theme, url: origin }]);
      const page = await context.newPage();
      page.on('pageerror', e => errors.push(e.message));
      let fresh = false;
      const approvals = [];
      await page.route('**/*', route => {
        const request = route.request(), url = new URL(request.url());
        if (url.origin !== new URL(origin).origin) return route.abort();
        if (!url.pathname.startsWith('/api/v1/')) return route.continue();
        if (request.method() === 'GET' && url.pathname === '/api/v1/session/bootstrap') {
          return route.fulfill({ json: {
            ...bootstrap, capabilities: [...bootstrap.capabilities, 'addon-scans.share'],
            fresh_auth_expires_at: fresh ? bootstrap.fresh_auth_expires_at : '2000-01-01T00:00:00Z',
          } });
        }
        if (request.method() === 'POST' && url.pathname === '/api/v1/cli/auth/approve') {
          approvals.push({ headers: request.headers(), body: request.postDataJSON() });
          return route.fulfill({ json: { approved: true } });
        }
        errors.push('Unexpected authorization fixture request ' + request.method() + ' ' + url.pathname);
        return route.abort();
      });
      async function visit(route, fragment = '') {
        const response = await page.goto(origin + route + fragment);
        assert(response?.ok(), 'Authorization route failed: ' + route);
      }
      async function inspect(route, state) {
        const layout = await inspectLayout(page, []);
        assert.deepEqual(layout.problems, [], route + ' ' + state);
        const alternative = theme === 'light' ? 'dark' : 'light';
        const toggle = page.getByRole('button', { name: 'Switch to ' + alternative + ' theme' });
        await toggle.click();
        await page.getByRole('button', { name: 'Switch to ' + theme + ' theme' }).click();
        assert.equal(await page.locator('html').getAttribute('data-theme'), theme);
        audit.push({ route, state, theme, width, controls: layout.controls });
      }

      await visit('/cli/authorize');
      await page.getByRole('alert').filter({ hasText: 'login link is invalid' }).waitFor();
      await inspect('/cli/authorize', 'Invalid request');
      await visit('/sign-in');
      await page.getByRole('link', { name: 'Continue to sign in' }).waitFor();
      await inspect('/sign-in', 'Sign in');
      await visit('/auth/callback');
      await page.getByRole('alert').filter({ hasText: 'invalid or expired' }).waitFor();
      await inspect('/auth/callback', 'Missing callback parameters');

      const params = { request_id: id(81), environment_id: bootstrap.environment_id, code_challenge: 'X'.repeat(43),
        request_proof: Math.floor(Date.now() / 1000 + 300) + '.' + 'Y'.repeat(43) };
      const fragment = '#' + new URLSearchParams(params);
      await visit('/cli/authorize', fragment);
      const signIn = page.getByRole('link', { name: 'Sign in to Zasp', exact: true });
      await signIn.waitFor();
      assert.equal(await signIn.getAttribute('target'), '_blank');
      assert.equal(new URL(page.url()).hash, '');
      await inspect('/cli/authorize', 'Fresh sign-in required');
      fresh = true;
      await page.getByRole('button', { name: 'Check session' }).click();
      const approve = page.getByRole('button', { name: 'Approve CLI access' });
      await approve.waitFor();
      assert(await approve.isDisabled());
      const terminalCode = page.getByRole('textbox', { name: /eight-character code/ });
      await terminalCode.fill('zzzzzzzz');
      assert(await approve.isDisabled());
      await terminalCode.fill('AABBCCDD');
      assert(await approve.isEnabled());
      await inspect('/cli/authorize', 'Consent');
      await captureViewport(page, path.join(output, 'authorization', theme + '-' + width + '.png'),
        approve, [terminalCode, page.getByRole('button', { name: 'Dismiss' })]);
      assert.equal(approvals.length, 0, 'Authentication or entering the code unexpectedly submitted consent');
      await approve.click();
      await page.getByRole('status').filter({ hasText: 'Approved. Return to your terminal' }).waitFor();
      assert.equal(approvals.length, 1);
      assert.deepEqual(approvals[0].body, { ...params, client_id: 'zaspctl', comparison_code: 'aabbccdd' });
      assert.equal(approvals[0].headers['x-zasp-expected-scope'], [bootstrap.organization_id, bootstrap.workspace_id, bootstrap.environment_id].join('/'));
      assert.equal(approvals[0].headers['x-csrf-token'], bootstrap.csrf_token);
      await inspect('/cli/authorize', 'Approved');
      // Reload the document so the one-shot fragment consumer mounts for a new request.
      await visit('/sign-in');
      await visit('/cli/authorize', fragment);
      await page.getByRole('button', { name: 'Dismiss' }).click();
      await page.getByText('Request dismissed.', { exact: false }).waitFor();
      assert.equal(approvals.length, 1, 'Dismissing a request submitted it');
      await inspect('/cli/authorize', 'Dismissed');
      await context.close();
    }
  }
  assert.deepEqual(errors, []);
  await writeFile(path.join(output, 'authorization-audit.json'), JSON.stringify({ audit, errors }, null, 2));
  console.log('Verified', audit.length, 'browser authorization states across three routes, four viewports and both themes.');
} finally {
  await browser.close();
}
