import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';

const output = process.env.ZASP_UI_REVIEW_OUTPUT || 'outputs/aegis-review';
const {chromium} = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({executablePath:process.env.ZASP_CHROMIUM || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try {
  const page = await browser.newPage({viewport:{width:1440,height:1000}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(process.env.ZASP_UI_WALKTHROUGH_ORIGIN || 'http://localhost:3011/walkthrough.html');
  const slides = await page.locator('#slides').evaluate(el => JSON.parse(el.textContent).map(({file, width, height, target, context, state}) => ({file,width,height,target,context,state})));
  const byName = new Map(slides.map(s => [s.file.split('/').pop(), s]));
  const focusedFrames = slides.filter(s => s.state === 'Ready to submit');
  assert.equal(focusedFrames.length, 4 * 4 * 2, 'Four named workflows must be captured across all viewport sizes and themes');
  let verified = 0, visibleTargets = 0;

  async function checkImage() {
    const file = await page.locator('#download').getAttribute('download'), slide = byName.get(file);
    assert(slide, `Gallery contains an unknown capture: ${file}`);
    const image = await page.locator('#shot').evaluate(async (img,{target,context}) => {
      await img.decode();
      await new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done)));
      const box = img.getBoundingClientRect(), pane = img.parentElement.getBoundingClientRect();
      const renderedWidth = box.width - 2 * img.clientLeft, renderedHeight = box.height - 2 * img.clientTop;
      const inPane = region => {
        const x = box.left + img.clientLeft + region.x * renderedWidth / img.naturalWidth;
        const y = box.top + img.clientTop + region.y * renderedHeight / img.naturalHeight;
        const right = x + region.width * renderedWidth / img.naturalWidth;
        const bottom = y + region.height * renderedHeight / img.naturalHeight;
        return x >= pane.left - 1 && y >= pane.top - 1 && right <= pane.right + 1 && bottom <= pane.bottom + 1;
      };
      const regions=target?[target,...(context||[])]:[];
      const span=regions.length?(Math.max(...regions.map(r=>r.y+r.height))-Math.min(...regions.map(r=>r.y)))*renderedHeight/img.naturalHeight:0;
      return {naturalWidth:img.naturalWidth, naturalHeight:img.naturalHeight, renderedWidth,renderedHeight,
        viewer:img.parentElement.clientWidth, visible:!target || inPane(target), contextVisible:span+4>pane.height || regions.every(inPane)};
    }, {target:slide.target,context:slide.context});
    assert.equal(image.naturalWidth, slide.width); assert.equal(image.naturalHeight,slide.height);
    const ratio = image.naturalWidth/image.naturalHeight, renderedRatio = image.renderedWidth/image.renderedHeight;
    assert(Math.abs(renderedRatio/ratio - 1) < 0.01, `Aspect ratio changed: ${file}`);
    assert(image.renderedWidth <= image.viewer, `Image exceeds viewer: ${file}`);
    if (slide.target) {
      assert(image.visible, `Action outside the gallery preview: ${slide.target.label} in ${file}`);
      assert(image.contextVisible, `Workflow context is clipped despite fitting in the gallery preview: ${file}`);
      visibleTargets++;
    }
    verified++;
  }
  for (const size of [{width:1440,height:1000},{width:390,height:844}]) {
    await page.setViewportSize(size);
    for (const mode of ['width','fit']) {
      if (!await page.locator('#stage').evaluate((el,m) => el.classList.contains(m),mode)) await page.locator('#fit').click();
      for (const theme of ['light','dark']) {
        await page.locator('#theme').selectOption(theme);
        for (const viewport of ['1920','1440','1024','390']) {
          await page.locator('#viewport').selectOption(viewport);
          const options = await page.locator('#screen option').allTextContents();
          for (let i=0; i<options.length; i++) {
            // All screen captures get both display modes on desktop. The focused
            // actions must additionally fit the smaller reviewer's viewport.
            if (size.width === 390 && !options[i].endsWith(' · Ready to submit')) continue;
            await page.locator('#screen').selectOption(String(i));
            await checkImage();
          }
        }
      }
    }
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.locator('#theme').selectOption('light');
    await page.locator('#viewport').selectOption(String(size.width));
    await page.locator('#screen').selectOption({label:'Scope a policy replay · Ready to submit'});
    if (!await page.locator('#stage').evaluate(el => el.classList.contains('width'))) await page.locator('#fit').click();
    await checkImage();
    await page.screenshot({path:path.join(output, size.width===390 ? 'walkthrough-mobile-preview.png' : 'walkthrough-preview.png')});
  }
  const previous = await page.locator('#title').textContent();
  await page.getByRole('button',{name:'Next screenshot'}).click();
  assert.notEqual(await page.locator('#title').textContent(), previous);
  assert.deepEqual(errors, []);
  const result={screenshotsVerified: slides.length, workflowScreenshots: focusedFrames.length, renderingsVerified:verified,
    targetVisibilityChecks:visibleTargets, modes:['Fit width','Fit whole image'], narrowViewer:true, browserErrors:errors};
  await writeFile(path.join(output,'walkthrough-verification.json'),JSON.stringify(result,null,2));
  console.log(result);
} finally {
  await browser.close();
}
