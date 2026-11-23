/** Run against the local development app. API fixtures stay in this browser context. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { fixture, fixtureStatus } from './fixtures.mjs';
import { captureViewport } from './viewport-capture.mjs';
import { captureWorkflows } from './workflows.mjs';
import { buildWalkthrough } from './walkthrough.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const output = process.env.ZASP_UI_REVIEW_OUTPUT || path.join(root, 'outputs/aegis-review');
const workflowsOnly = process.argv.includes('--workflows-only');
await mkdir(path.join(output, 'screenshots'), { recursive: true });
const { chromium } = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({ executablePath: process.env.ZASP_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const origin = process.env.ZASP_UI_REVIEW_ORIGIN || 'http://localhost:3000';
const source = await readFile(path.join(root, 'app/components/ZaspProductionApp.tsx'), 'utf8');
const routes = [...source.matchAll(/\{ path: "([^"]+)", label: "([^"]+)"/g)].map(match => ({ route: match[1], title: match[2] }));
assert.equal(routes.length, 24, 'Update review coverage if production routes change');
const viewports = [{ width: 1920, height: 1080 }, { width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }];
const slides = [], failures = [], consoleErrors = [], assertions = [];
let mode = 'normal';
const context = await browser.newContext();
await context.route('**/*', async route => {
  const request = route.request(), url = new URL(request.url());
  if (url.origin !== new URL(origin).origin) return route.abort();
  if (!url.pathname.startsWith('/api/v1/')) return route.continue();
  // Review never changes a real backend, even if a control is activated accidentally.
  if (request.method() !== 'GET') return route.fulfill({ status: 405, json: { code: 'review_read_only', message: 'Visual review does not submit mutations.' } });
  if (mode === 'error' && url.pathname.endsWith('/agents')) return route.fulfill({ status: 503, json: { code: 'service_unavailable', message: 'Review error state', correlation_id: 'pid_00000004-0000-4000-8000-000000000004', retryable: true } });
  if (mode === 'loading' && url.pathname.endsWith('/home/summary')) await new Promise(resolve => setTimeout(resolve, 1500));
  return route.fulfill({ status: fixtureStatus(url), json: fixture(url), headers: { ETag: '"1"', 'Cache-Control': 'no-store' } });
});
const page = await context.newPage();
page.on('pageerror', error => consoleErrors.push(error.message));
let theme = 'light', viewport = viewports[0];
await context.addInitScript(() => { if (!localStorage.getItem('zasp.theme')) localStorage.setItem('zasp.theme', 'light'); });
async function open(route) {
  await page.goto(origin + route, { waitUntil: 'networkidle' });
  await page.locator('h1').first().waitFor({state: 'attached'});
  await page.evaluate(theme => { document.documentElement.dataset.theme = theme; localStorage.setItem('zasp.theme', theme); window.dispatchEvent(new Event('zasp-theme-change')); }, theme);
  await page.evaluate(() => document.fonts.ready);
}
async function capture(title, route, state = 'Page', focus, contextLocators) {
  const filename = `${String(slides.length + 1).padStart(3, '0')}-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${theme}-${viewport.width}.png`;
  const file = path.join('screenshots', filename);
  const frame = await captureViewport(page, path.join(output, file), focus, contextLocators);
  const overflow = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth }));
  if (overflow.document > overflow.viewport + 1) failures.push({ title, theme, viewport, issue: 'Page horizontal overflow', ...overflow });
  if (route === '/administration/identity-access') {
    const clipped = await page.locator('.identity-list .row-actions > *').evaluateAll(nodes => nodes.filter(node => {
      const bounds = node.getBoundingClientRect(), panel = node.closest('.card').getBoundingClientRect();
      return bounds.left < panel.left - 1 || bounds.right > panel.right + 1;
    }).map(node => node.textContent));
    if (clipped.length) failures.push({ title, theme, viewport, issue: 'Clipped identity controls', clipped });
  }
  if (route === '/investigate/sessions') {
    const readable = await page.locator('.table-pagination .button:disabled').evaluateAll(nodes => nodes.every(node => getComputedStyle(node).opacity === '1'));
    if (!readable) failures.push({ title, theme, viewport, issue: 'Faded disabled pagination labels' });
  }
  if (await page.locator('.brand-logo').count()) {
    const selected = page.locator(`.brand-logo__${theme}`), hidden = page.locator(`.brand-logo__${theme === 'dark' ? 'light' : 'dark'}`);
    if (!await selected.isVisible() || await hidden.isVisible()) failures.push({ title, theme, viewport, issue: 'Wrong wordmark for theme' });
  }
  if (await page.locator('.auth-page').count()) {
    const artwork = await page.locator('.auth-page').evaluate(element => getComputedStyle(element, '::before').backgroundImage);
    if (!artwork.includes(`zasp-wordmark-${theme}.svg`)) failures.push({ title, theme, viewport, issue: 'Wrong sign-in wordmark for theme' });
  }
  const alerts = await page.getByRole('alert').allTextContents();
  const brokenImages = await page.locator('img').evaluateAll(images => images.filter(img => !img.complete || img.naturalWidth === 0).map(img => img.src));
  if (brokenImages.length) failures.push({ title, theme, viewport, issue: 'Broken image', images: brokenImages });
  slides.push({ title, route, state, theme, viewport: viewport.width, ...frame, file, alerts, source: 'Running Zasp app · synthetic browser API fixtures' });
  await writeFile(path.join(output, 'capture-progress.json'), JSON.stringify({ slides, failures, consoleErrors, assertions }, null, 2));
}
for (viewport of viewports) {
  await page.setViewportSize(viewport);
  for (theme of ['light', 'dark']) {
    if (!workflowsOnly) {
      for (const item of routes) {
        await open(item.route);
        await capture(item.title, item.route);
      }
    }
    await captureWorkflows({page, open, capture});
    console.log(`Captured ${workflowsOnly ? 'workflows' : 'pages and workflows'} at ${viewport.width}px in ${theme} theme`);
  }
}
if (!workflowsOnly) {
// Inspect every tabbed section at a readable desktop size in both palettes.
viewport = viewports[1]; await page.setViewportSize(viewport);
for (theme of ['light', 'dark']) {
  for (const route of ['/inventory/tools','/red-team/results','/protect/guardrails','/protect/security-agents']) {
    await open(route);
    const tabs = await page.getByRole('tab').allTextContents();
    for (let i = 1; i < tabs.length; i++) {
      await page.getByRole('tab').nth(i).click();
      await page.waitForLoadState('networkidle');
      await capture(tabs[i].trim(), route, 'Tab', page.getByRole('tab').nth(i));
    }
  }
  await open('/discovery/assets');
  const firstRow = page.getByRole('button', { name: 'Open Support agent', exact: true });
  await firstRow.click();
  await page.getByRole('dialog', { name: 'Support agent', exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Canonical record', exact: true }).waitFor();
  await capture('Agent details', '/discovery/assets', 'Drawer', page.getByRole('heading', {name:'Canonical record', exact:true}));
  const dialog = page.getByRole('dialog');
  await page.keyboard.press('Shift+Tab');
  assert(await dialog.evaluate(dialog => dialog.contains(document.activeElement)), 'Drawer must trap focus');
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'detached' });
  assert(await firstRow.evaluate(node => node === document.activeElement), 'Drawer must restore focus');
  assertions.push(`${theme}: detail drawer focus trap, Escape and focus restoration`);
  const filter = page.getByRole('searchbox', { name: 'Filter Agents' });
  await filter.fill('no-matching-record');
  await page.getByText('Nothing matches', { exact: false }).waitFor();
  assert.equal(await page.locator('.data-table tbody tr').count(), 0);
  await capture('Filtered empty results', '/discovery/assets', 'Empty state', page.getByText('Nothing matches', {exact:false}));
  await filter.fill('Support');
  assert.equal(await page.locator('.data-table tbody tr').count(), 1);
  assertions.push(`${theme}: inventory search filters rows and handles empty results`);
  await filter.fill('');
  await page.getByRole('button', { name: 'Unmanaged (4)' }).click();
  assert.equal(await page.locator('.data-table tbody tr').count(), 4);
  assertions.push(`${theme}: unmanaged filter retains correct rows`);
  await capture('Unmanaged agents', '/discovery/assets', 'Selected filter', page.getByRole('button',{name:'Unmanaged (4)'}));
  mode = 'error'; await open('/discovery/assets');
  await page.getByRole('alert').filter({ hasText: 'Product API unavailable' }).waitFor();
  await capture('API error', '/discovery/assets', 'Error state', page.getByRole('button',{name:'Retry',exact:true}));
  mode = 'normal'; await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await page.getByRole('button', { name: 'Open Support agent', exact: true }).waitFor();
  assertions.push(`${theme}: error retry restores inventory`);
  mode = 'loading';
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  await page.evaluate(t => { document.documentElement.dataset.theme = t; }, theme);
  await page.getByRole('status').filter({ hasText: 'Loading authorized data' }).waitFor();
  await capture('Loading data', '/', 'Loading state', page.getByRole('status').filter({hasText:'Loading authorized data'}));
  mode = 'normal';
  await open('/sign-in'); await capture('Sign in', '/sign-in');
  await open('/auth/callback'); await capture('Sign in callback', '/auth/callback', 'Missing callback parameters');
}
// Mobile navigation uses the production links inside the existing accessible drawer.
viewport = viewports[3]; await page.setViewportSize(viewport);
for (theme of ['light','dark']) {
  await open('/');
  const skip = page.getByRole('link', {name:'Skip to content',exact:true});
  const skipVisible = () => skip.evaluate(node => {
    const r = node.getBoundingClientRect(), hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return !!hit && node.contains(hit);
  });
  assert(!await skipVisible(), 'Unfocused skip link must not cover the header');
  await page.keyboard.press('Tab');
  assert(await skip.evaluate(node => node === document.activeElement) && await skipVisible(), 'First Tab must expose skip navigation');
  const pageURL = page.url();
  await page.keyboard.press('Enter');
  assert.equal(page.url(), pageURL, 'Skipping to main content must preserve scoped navigation');
  assert(await page.locator('#main-content').evaluate(node => node === document.activeElement));
  await page.getByRole('button', {name:'Sign out',exact:true}).focus();
  await page.keyboard.press('Tab');
  assert(await page.locator('#main-content').evaluate(node => node.contains(document.activeElement)), 'Collapsed navigation must be excluded from the tab order');
  assertions.push(`${theme}: mobile skip link and collapsed navigation tab order`);
  const toggle = page.getByRole('button', { name: 'Open navigation' });
  await toggle.click();
  await page.getByRole('dialog', { name: 'Navigation', exact: true }).waitFor();
  assert.equal(await page.getByRole('dialog').getByRole('link').count(), routes.length);
  await capture('Mobile navigation', '/', 'Navigation drawer', page.getByRole('dialog').getByRole('link').first());
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'detached' });
  assert(await toggle.evaluate(node => node === document.activeElement));
  assertions.push(`${theme}: all 24 mobile destinations, Escape and focus restoration`);
  const target = theme === 'light' ? 'dark' : 'light';
  await page.getByRole('button', { name: `Switch to ${target} theme` }).click();
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), target);
  assertions.push(`${theme}: theme preference survives reload`);
}
}
assert.equal(consoleErrors.length, 0, `Browser errors: ${consoleErrors.join('; ')}`);
const report = { captureVersion: 2, fixtureNotice: 'Isolated synthetic responses. Live authentication, authorization enforcement and backend mutations are not verified.', routes: new Set(slides.map(s => s.route).filter(r => routes.some(item => item.route === r))).size, viewports, themes: ['light','dark'], screenshotCount: slides.length, failures, consoleErrors, assertions, slides };
await writeFile(path.join(output,'manifest.json'), JSON.stringify(report,null,2));
await buildWalkthrough(output, report);
await browser.close();
console.log(JSON.stringify({ screenshotCount:slides.length, failures, assertions },null,2));
assert.equal(failures.length, 0, 'Resolve screenshot review defects before completion');
