import { writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const {chromium} = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright');
const browser=await chromium.launch({executablePath:process.env.ZASP_CHROMIUM || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
const page=await browser.newPage({viewport:{width:1440,height:1000}});
const errors=[];page.on('pageerror',error=>errors.push(error.message));
await page.goto(process.env.ZASP_UI_WALKTHROUGH_ORIGIN || 'http://localhost:3011/walkthrough.html');
let verified=0;
for(const mode of ['width','fit']) {
  if(mode==='fit') await page.getByRole('button',{name:'Fit whole image',exact:true}).click();
  for(const theme of ['light','dark']) {
    await page.locator('#theme').selectOption(theme);
    for(const viewport of ['1920','1440','1024','390']) {
      await page.locator('#viewport').selectOption(viewport);
      const count=await page.locator('#screen option').count();
      for(let i=0;i<count;i++) {
        await page.locator('#screen').selectOption(String(i));
        const image=await page.locator('#shot').evaluate(async img=>{
          await img.decode();const box=img.getBoundingClientRect();
          return {naturalWidth:img.naturalWidth,naturalHeight:img.naturalHeight,width:box.width-2,height:box.height-2,viewer:img.parentElement.clientWidth,alt:img.alt};
        });
        assert(image.naturalWidth>0 && image.naturalHeight>0,'Screenshot failed to load');
        const natural=image.naturalWidth/image.naturalHeight, displayed=image.width/image.height;
        assert(Math.abs(displayed/natural-1)<0.01,`Aspect ratio changed: ${image.alt}`);
        assert(image.width<=image.viewer,`Image exceeds viewer: ${image.alt}`);
        verified++;
      }
    }
  }
}
await page.getByRole('button',{name:'Fit width',exact:true}).click();
await page.locator('#viewport').selectOption('1440');await page.locator('#theme').selectOption('light');
await page.locator('#screen').selectOption({label:'Agents'});
await page.locator('#shot').evaluate(img=>img.decode());
await page.screenshot({path:'outputs/aegis-review/walkthrough-preview.png'});
// Verify selectors and keyboard navigation on a narrow viewer as well.
await page.setViewportSize({width:390,height:844});
await page.locator('#viewport').selectOption('390');
await page.locator('#screen').selectOption({label:'Integrations'});
await page.locator('#shot').evaluate(img=>img.decode());
assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
await page.getByRole('button',{name:'Fit whole image',exact:true}).click();
await page.locator('#shot').evaluate(img=>img.decode());
await page.screenshot({path:'outputs/aegis-review/walkthrough-mobile-preview.png'});
await page.getByRole('button',{name:'Next screenshot'}).click();
assert.equal(await page.locator('#title').textContent(),'Sensors');
assert.equal(errors.length,0,errors.join('; '));
const result={screenshotsVerified:verified/2,renderingsVerified:verified,modes:['Fit width','Fit whole image'],narrowViewer:true,browserErrors:errors};
await writeFile('outputs/aegis-review/walkthrough-verification.json',JSON.stringify(result,null,2));
console.log(result);await browser.close();
