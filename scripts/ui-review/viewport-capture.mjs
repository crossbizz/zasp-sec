import assert from 'node:assert/strict';

// A document screenshot taken after scrolling can composite fixed controls over
// unrelated content. Keep the screenshot and the target's bounds in one viewport.
export async function captureViewport(page, destination, focus, contextLocators = []) {
  if (focus) {
    await focus.waitFor({ state: 'visible' });
    await focus.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' }));
  } else {
    await page.evaluate(() => window.scrollTo({ top: 0, left: 0, behavior: 'instant' }));
  }
  if (contextLocators.length) {
    const boxes = await Promise.all([focus, ...contextLocators].map(locator => locator.boundingBox()));
    assert(boxes.every(Boolean), 'Workflow context must be displayed');
    const top = Math.min(...boxes.map(r => r.y)), bottom = Math.max(...boxes.map(r => r.y + r.height));
    await page.evaluate(({top,bottom}) => {
      const header = Math.max(0, document.querySelector('.topbar')?.getBoundingClientRect().bottom || 0);
      window.scrollBy({top:(top + bottom - innerHeight - header) / 2, behavior:'instant'});
    }, {top,bottom});
  }
  await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  const regions = focus ? await Promise.all([focus, ...contextLocators].map(locator => locator.evaluate(node => {
    const r = node.getBoundingClientRect();
    // Sample the context edges as well as its center. A sticky header can cover
    // a field label while leaving the middle of its form visible.
    const visible = [0.08, 0.5, 0.92].every(fraction => {
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height * fraction);
      return !!hit && node.contains(hit);
    });
    const label = node.getAttribute('aria-label') || node.labels?.[0]?.textContent.trim() || node.textContent.trim();
    return {x:r.left, y:r.top, width:r.width, height:r.height, label, visible};
  }))) : [];
  const [target, ...context] = regions;
  const viewport = page.viewportSize();
  for (const region of regions) {
    assert(region.visible && region.width > 0 && region.height > 0 &&
      region.x >= -1 && region.x + region.width <= viewport.width + 1 &&
      region.y >= -1 && region.y + region.height <= viewport.height + 1,
    `Captured target or context is clipped or obscured: ${JSON.stringify(region)}`);
  }
  if (focus && viewport.width >= 1024) {
    const header = page.locator('.topbar .brand');
    if (await header.count() && !(await page.getByRole('dialog').count())) {
      assert(await header.evaluate(node => {
        const r = node.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return r.top >= 0 && !!hit && node.contains(hit);
      }), 'The fixed desktop header is obscured in the workflow viewport');
    }
  }
  const png = await page.screenshot({ path: destination, fullPage: false, scale: 'css', animations: 'disabled' });
  const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
  assert.deepEqual({width, height}, viewport, 'PNG dimensions differ from the inspected viewport');
  const scroll = await page.evaluate(() => ({x: scrollX, y: scrollY}));
  return { width, height, scroll, ...(target ? {target, context} : {}) };
}
