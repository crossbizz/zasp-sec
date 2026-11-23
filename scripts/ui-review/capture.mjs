/** Run against the local development app. API fixtures stay in this browser context. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { fixture } from './fixtures.mjs';
import { investigationStream, reviewModelWorkflows, reviewQualification } from './model-workflows.mjs';
import { buildWalkthrough } from './walkthrough.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const output = path.join(root, 'outputs/aegis-review');
await mkdir(path.join(output, 'screenshots'), { recursive: true });
const { chromium } = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({ executablePath: process.env.ZASP_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const origin = process.env.ZASP_UI_REVIEW_ORIGIN || 'http://localhost:3000';
const source = await readFile(path.join(root, 'app/components/ZaspProductionApp.tsx'), 'utf8');
const routes = [...source.matchAll(/\{ path: "([^"]+)", label: "([^"]+)"/g)].map(match => ({ route: match[1], title: match[2] }));
assert.equal(routes.length, 25, 'Update review coverage if production routes change');
const viewports = [{ width: 1920, height: 1080 }, { width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }];
const slides = [], failures = [], consoleErrors = [], assertions = [];
let mode = 'normal';
const context = await browser.newContext();
await context.route('**/api/v1/**', async route => {
  const request = route.request(), url = new URL(request.url());
  // Review never changes a real backend. The session response is a local stream fixture.
  if (request.method() === 'POST' && /^\/api\/v1\/security-agents\/chat\/threads\/[^/]+\/stream$/.test(url.pathname)) return investigationStream(route);
  if (request.method() !== 'GET') return route.fulfill({ status: 405, json: { code: 'review_read_only', message: 'Visual review does not submit mutations.' } });
  if (mode === 'error' && url.pathname.endsWith('/agents')) return route.fulfill({ status: 503, json: { code: 'service_unavailable', message: 'Review error state', correlation_id: 'pid_00000004-0000-4000-8000-000000000004', retryable: true } });
  if (mode === 'loading' && url.pathname.endsWith('/home/summary')) await new Promise(resolve => setTimeout(resolve, 1500));
  return route.fulfill({ json: fixture(url), headers: { ETag: '"1"', 'Cache-Control': 'no-store' } });
});
const page = await context.newPage();
page.on('pageerror', error => consoleErrors.push(error.message));
let theme = 'light', viewport = viewports[0];

async function open(route) {
  await context.addCookies([{ name: 'zasp.theme', value: theme, url: origin }]);
  const response = await page.goto(origin + route, { waitUntil: 'networkidle' });
  assert(response?.ok(), `Route ${route} returned HTTP ${response?.status()}`);
  await page.locator('h1').first().waitFor();
  if (routes.some(item => item.route === route)) await page.waitForSelector('.app-shell');
  await page.evaluate(() => document.fonts.ready);
}
async function capture(title, route, state = 'Page') {
  const filename = `${String(slides.length + 1).padStart(3, '0')}-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${theme}-${viewport.width}.png`;
  const file = path.join('screenshots', filename);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const png = await page.screenshot({ path: path.join(output, file), fullPage: true, animations: 'disabled' });
  const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
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
  slides.push({ title, route, state, theme, viewport: viewport.width, width, height, file, alerts, source: 'Running Zasp app · synthetic browser API fixtures' });
  await writeFile(path.join(output, 'capture-progress.json'), JSON.stringify({ slides, failures, consoleErrors, assertions }, null, 2));
}
for (viewport of viewports) {
  await page.setViewportSize(viewport);
  for (theme of ['light', 'dark']) {
    for (const item of routes) {
      if (process.argv.includes('--reuse-pages') && item.route !== '/discovery/assets') {
        const filename = `${String(slides.length + 1).padStart(3, '0')}-${item.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${theme}-${viewport.width}.png`;
        const file = path.join('screenshots', filename), png = await readFile(path.join(output, file));
        const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
        if (width > viewport.width + 1) failures.push({ title: item.title, theme, viewport, issue: 'Page horizontal overflow', width });
        slides.push({ ...item, state: 'Page', theme, viewport: viewport.width, width, height, file, alerts: [], source: 'Running Zasp app · synthetic browser API fixtures' });
      } else { await open(item.route); await capture(item.title, item.route); }
    }
    console.log(`Captured ${routes.length} routes at ${viewport.width}px in ${theme} theme`);
  }
}
// Inspect every tabbed section at a readable desktop size in both palettes.
viewport = viewports[1]; await page.setViewportSize(viewport);
for (theme of ['light', 'dark']) {
  for (const route of ['/inventory/tools','/red-team/results','/protect/guardrails','/protect/security-agents']) {
    await open(route);
    const tabs = await page.getByRole('tab').allTextContents();
    for (let i = 1; i < tabs.length; i++) {
      await page.getByRole('tab').nth(i).click();
      await page.waitForLoadState('networkidle');
      await capture(tabs[i].trim(), route, 'Tab');
    }
  }
  await open('/discovery/assets');
  const firstRow = page.getByRole('button', { name: 'Open Support agent', exact: true });
  await firstRow.click();
  await page.getByRole('dialog', { name: 'Support agent', exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Canonical record', exact: true }).waitFor();
  await capture('Agent details', '/discovery/assets', 'Drawer');
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
  await capture('Filtered empty results', '/discovery/assets', 'Empty state');
  await filter.fill('Support');
  assert.equal(await page.locator('.data-table tbody tr').count(), 1);
  assertions.push(`${theme}: inventory search filters rows and handles empty results`);
  await filter.fill('');
  await page.getByRole('button', { name: 'Unmanaged (4)' }).click();
  assert.equal(await page.locator('.data-table tbody tr').count(), 4);
  assertions.push(`${theme}: unmanaged filter retains correct rows`);
  await capture('Unmanaged agents', '/discovery/assets', 'Selected filter');
  mode = 'error'; await open('/discovery/assets');
  await page.getByRole('alert').filter({ hasText: 'Product API unavailable' }).waitFor();
  await capture('API error', '/discovery/assets', 'Error state');
  mode = 'normal'; await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await page.getByRole('button', { name: 'Open Support agent', exact: true }).waitFor();
  assertions.push(`${theme}: error retry restores inventory`);
  mode = 'loading';
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
  await page.evaluate(t => { document.documentElement.dataset.theme = t; }, theme);
  await page.getByRole('status').filter({ hasText: 'Loading authorized data' }).waitFor();
  await capture('Loading data', '/', 'Loading state');
  mode = 'normal';
  await open('/sign-in'); await capture('Sign in', '/sign-in');
  await open('/auth/callback'); await capture('Sign in callback', '/auth/callback', 'Missing callback parameters');
}
// Mobile navigation uses the production links in an inline disclosure.
viewport = viewports[3]; await page.setViewportSize(viewport);
for (theme of ['light','dark']) {
  await open('/');
  const toggle = page.getByRole('button', { name: 'Open navigation' });
  await toggle.click();
  const menu = page.getByRole('navigation', { name: 'Main navigation' });
  await menu.waitFor();
  assert.equal(await menu.getByRole('link').count(), routes.length);
  await capture('Mobile navigation', '/', 'Expanded navigation');
  await page.keyboard.press('Escape');
  await menu.waitFor({ state: 'hidden' });
  assert(await toggle.evaluate(node => node === document.activeElement));
  assertions.push(`${theme}: all ${routes.length} mobile destinations, Escape and focus restoration`);
  const target = theme === 'light' ? 'dark' : 'light';
  await page.getByRole('button', { name: `Switch to ${target} theme` }).click();
  await page.reload({ waitUntil: 'networkidle' });
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), target);
  assertions.push(`${theme}: theme preference survives reload`);
}
for (viewport of [viewports[1], viewports[3]]) {
  await page.setViewportSize(viewport);
  await reviewModelWorkflows(page, open, capture);
  await reviewQualification(page, open, capture, fixture);
  assertions.push(`Workflow Studio, analyst history and streaming, calibration and confidence bins at ${viewport.width}px`);
}
assert.equal(consoleErrors.length, 0, `Browser errors: ${consoleErrors.join('; ')}`);
const report = { fixtureNotice: 'Isolated synthetic responses. Live authentication, authorization enforcement and backend mutations are not verified.', routes: routes.length, viewports, themes: ['light','dark'], screenshotCount: slides.length, failures, consoleErrors, assertions, slides };
await writeFile(path.join(output,'manifest.json'), JSON.stringify(report,null,2));
await buildWalkthrough(output, report);
await browser.close();
console.log(JSON.stringify({ screenshotCount:slides.length, failures, assertions },null,2));
assert.equal(failures.length, 0, 'Resolve screenshot review defects before completion');
