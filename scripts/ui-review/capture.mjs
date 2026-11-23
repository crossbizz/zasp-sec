/** Run against the local development app. API fixtures stay in this browser context. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { bootstrap, fixture, fixtureStatus } from './fixtures.mjs';
import { captureViewport } from './viewport-capture.mjs';
import { inspectLayout, inspectDrawer, inspectSignOutFailure, visitTabs } from './shell-audit.mjs';
import { captureWorkflows } from './workflows.mjs';
import { investigationStream, reviewModelWorkflows, reviewQualification } from './model-workflows.mjs';
import { buildWalkthrough } from './walkthrough.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const output = process.env.ZASP_UI_REVIEW_OUTPUT || path.join(root, 'outputs/aegis-review');
const workflowsOnly = process.argv.includes('--workflows-only');
await mkdir(path.join(output, 'screenshots'), { recursive: true });
const { chromium } = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright-core');
const browser = await chromium.launch({ executablePath: process.env.ZASP_CHROMIUM || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
const origin = process.env.ZASP_UI_REVIEW_ORIGIN || 'http://localhost:3000';
const source = await readFile(path.join(root, 'app/components/ZaspProductionApp.tsx'), 'utf8');
const routes = [...source.matchAll(/\{ path: "([^"]+)", label: "([^"]+)"/g)].map(match => ({ route: match[1], title: match[2] }));
assert.equal(routes.length, 25, 'Update review coverage if production routes change');
const viewports = [{ width: 1920, height: 1080 }, { width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }];
const slides = [], failures = [], consoleErrors = [], assertions = [];
const audit = [], fallbackReads = new Set();
let mode = 'normal';
const context = await browser.newContext();
await context.route('**/*', async route => {
  const request = route.request(), url = new URL(request.url());
  if (url.origin !== new URL(origin).origin) return route.abort();
  if (!url.pathname.startsWith('/api/v1/')) return route.continue();
  // Review never changes a real backend, even if a control is activated accidentally.
  if (request.method() === 'POST' && /^\/api\/v1\/security-agents\/chat\/threads\/[^/]+\/stream$/.test(url.pathname)) return investigationStream(route);
  if (request.method() !== 'GET') return route.fulfill({ status: 405, json: { code: 'review_read_only', message: 'Visual review does not submit mutations.' } });
  if (mode === 'error' && url.pathname.endsWith('/agents')) return route.fulfill({ status: 503, json: { code: 'service_unavailable', message: 'Review error state', correlation_id: 'pid_00000004-0000-4000-8000-000000000004', retryable: true } });
  if (mode === 'loading' && url.pathname.endsWith('/home/summary')) await new Promise(resolve => setTimeout(resolve, 1500));
  return route.fulfill({ status: fixtureStatus(url), json: fixture(url, path => fallbackReads.add(path)), headers: { ETag: '"1"', 'Cache-Control': 'no-store' } });
});
const page = await context.newPage();
page.on('pageerror', error => consoleErrors.push(error.message));
let theme = 'light', viewport = viewports[0];

async function open(route) {
  fallbackReads.clear();
  await context.addCookies([{ name: 'zasp.theme', value: theme, url: origin }]);
  const response = await page.goto(origin + route, { waitUntil: 'networkidle' });
  assert(response?.ok(), `Route ${route} returned HTTP ${response?.status()}`);
  await page.locator('h1').first().waitFor();
  if (routes.some(item => item.route === route)) await page.waitForSelector('.app-shell');
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
  const layout = await inspectLayout(page, routes.map(r => r.route));
  const fallback = [...fallbackReads].sort();
  const intentionalError = ['Error state','Missing callback parameters'].includes(state);
  const notices = [...layout.alerts,...layout.unavailable];
  if (layout.problems.length || (notices.length && !intentionalError)) {
    failures.push({title,route,state,theme,viewport:viewport.width,issue:'Layout or data unavailable',problems:layout.problems,notices});
  }
  audit.push({title,route,state,theme,viewport:viewport.width,...layout,fallbackReads:fallback});
  const alerts = layout.alerts;
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
        if (viewport.width === 390) {
          const menu = page.getByRole('button',{name:'Open navigation',exact:true});
          await menu.click();
          const nav = page.getByRole('navigation',{name:'Main navigation',exact:true});
          assert.deepEqual(await nav.getByRole('link').evaluateAll(links=>links.map(a=>a.getAttribute('href'))),routes.map(r=>r.route));
          assert.equal(await nav.locator('[aria-current=page]').getAttribute('href'),item.route);
          await page.keyboard.press('Escape');
          await nav.waitFor({state:'hidden'});
          assert(await menu.evaluate(e=>document.activeElement===e),'Mobile menu must return focus on every route');
        }
        if ([1440,390].includes(viewport.width)) {
          await visitTabs(page, (name, tab) => capture(name, item.route, 'Tab', tab));
          if (item.route === '/compliance/evidence') {
            const coverage = page.getByRole('button', {name:'Framework coverage',exact:true});
            await coverage.click();
            await page.getByRole('table',{name:'Coverage by control'}).waitFor();
            await capture('Framework coverage', item.route, 'View', coverage);
          }
          if (item.route === '/investigate/sessions') {
            const consoleLogins = page.getByRole('button', {name:'Console logins',exact:true});
            await consoleLogins.click();
            await page.getByText('session-review', {exact:true}).waitFor();
            await capture('Console logins', item.route, 'View', consoleLogins);
          }
        }
      }
    }
    await captureWorkflows({page, open, capture});
    console.log(`Captured ${workflowsOnly ? 'workflows' : 'pages and workflows'} at ${viewport.width}px in ${theme} theme`);
  }
}
if (!workflowsOnly) {
// Exercise detail, filter and retry states after capturing every route and visible tab.
for (viewport of [viewports[1],viewports[3]]) {
await page.setViewportSize(viewport);
for (theme of ['light', 'dark']) {
  await open('/discovery/assets');
  const firstRow = page.getByRole('button', { name: 'Open Support agent', exact: true });
  await firstRow.click();
  await page.getByRole('dialog', { name: 'Support agent', exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Canonical record', exact: true }).waitFor();
  await capture('Agent details', '/discovery/assets', 'Drawer', page.getByRole('heading', {name:'Canonical record', exact:true}));
  const dialog = page.getByRole('dialog');
  audit.push({title:'Agent details',theme,viewport:viewport.width,drawer:await inspectDrawer(page,dialog)});
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
  await open('/');
  const search = page.getByRole('search'), input = search.getByRole('searchbox');
  await input.fill('agent'); await input.press('Enter');
  const results = page.locator('#product-search-results .search-results-inline'), options = results.locator('li a[href], li button');
  await options.last().waitFor();
  assert.equal(await options.count(),12);
  await options.first().focus();
  for(let n=1;n<12;n++) await page.keyboard.press('Tab');
  const lastMatch=options.last();
  assert(await lastMatch.evaluate(el=>el===document.activeElement),'All search results must be keyboard reachable');
  const dimensions = await results.evaluate(el=>{
    const r=el.getBoundingClientRect();return {top:r.top,left:r.left,right:r.right,bottom:r.bottom,width:innerWidth,height:innerHeight};
  });
  assert(dimensions.left>=-1 && dimensions.right<=dimensions.width+1, 'Search results exceed the content width');
  assert(await lastMatch.evaluate(el=>{const r=el.getBoundingClientRect(), hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2); return !!hit && el.contains(hit);}), 'Final search result must scroll into view and receive pointer input');
  await capture('Search results','/','Search menu',lastMatch);
  await page.keyboard.press('Escape');
  await results.waitFor({state:'detached'});
  assert(await input.evaluate(el=>el===document.activeElement),'Escape must restore search focus');
  assertions.push(`${theme}/${viewport.width}: 12 search results reachable and Escape returns focus`);
  await open('/sign-in'); await capture('Sign in', '/sign-in');
  await open('/auth/callback'); await capture('Sign in callback', '/auth/callback', 'Missing callback parameters');
}
}
// Mobile navigation uses the production links in an inline disclosure.
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
  await page.getByRole('button', {name:/Switch to .* theme/}).focus();
  await page.keyboard.press('Tab');
  assert(await page.locator('#main-content').evaluate(node => node.contains(document.activeElement)), 'Collapsed navigation must be excluded from the tab order');
  assertions.push(`${theme}: mobile skip link and collapsed navigation tab order`);
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
}
if (!workflowsOnly) {
  for (const view of [{width:320,height:568}, {width:1440,height:900}]) {
    await inspectSignOutFailure(browser, origin, view, view.width === 320);
    assertions.push(`${view.width}px: sign-out failure keeps header controls and content visible, then permits retry`);
  }
}
assert.equal(consoleErrors.length, 0, `Browser errors: ${consoleErrors.join('; ')}`);
const report = { captureVersion: 2, fixtureCapabilities:bootstrap.capabilities, fixturePermissions:bootstrap.permissions, layoutAudit:'layout-audit.json', fixtureNotice: 'Isolated synthetic responses. Live authentication, authorization enforcement and backend mutations are not verified.', routes: new Set(slides.map(s => s.route).filter(r => routes.some(item => item.route === r))).size, viewports, themes: ['light','dark'], screenshotCount: slides.length, failures, consoleErrors, assertions, slides };
await writeFile(path.join(output,'layout-audit.json'), JSON.stringify(audit,null,2));
await writeFile(path.join(output,'manifest.json'), JSON.stringify(report,null,2));
await buildWalkthrough(output, report);
await browser.close();
console.log(JSON.stringify({ screenshotCount:slides.length, failures, assertions },null,2));
assert.equal(failures.length, 0, 'Resolve screenshot review defects before completion');
