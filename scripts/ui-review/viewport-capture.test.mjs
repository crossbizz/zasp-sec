import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {captureViewport} from './viewport-capture.mjs';

// Run with the same Chromium and Playwright used by capture.mjs.
test('the PNG contains the named action in viewport coordinates after scrolling past a fixed header', async () => {
  const {chromium} = await import(process.env.ZASP_PLAYWRIGHT_MODULE || 'playwright-core');
  const browser = await chromium.launch({executablePath:process.env.ZASP_CHROMIUM || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
  const dir = await mkdtemp(path.join(tmpdir(), 'zasp-viewport-test-'));
  try {
    const page = await browser.newPage({ viewport:{width:390,height:844} });
    await page.setContent('<style>*{box-sizing:border-box}body{margin:0;background:white}header{position:fixed;inset:0 0 auto;height:60px;background:#223344}button{margin-top:1800px;width:220px;height:60px;border:0;background:#216321;color:white}main{min-height:3600px}</style><header></header><main><button>Review scoped action</button></main>');
    const filename = path.join(dir, 'workflow.png');
    const frame = await captureViewport(page,filename,page.getByRole('button',{name:'Review scoped action'}));
    assert(frame.scroll.y > 1000);
    const pixels = await page.evaluate(async ({png,x,y}) => {
      const bytes = Uint8Array.from(atob(png), c => c.charCodeAt(0));
      const image = await createImageBitmap(new Blob([bytes],{type:'image/png'}));
      const canvas = document.createElement('canvas');canvas.width=image.width;canvas.height=image.height;
      const ctx=canvas.getContext('2d');ctx.drawImage(image,0,0);
      return [[10,10],[x+7,y+7]].map(([left,top]) => [...ctx.getImageData(left,top,1,1).data]);
    }, {png:(await readFile(filename)).toString('base64'),x:Math.ceil(frame.target.x),y:Math.ceil(frame.target.y)});
    assert.deepEqual(pixels,[[34,51,68,255],[33,99,33,255]]);
  } finally {
    await browser.close(); await rm(dir,{recursive:true,force:true});
  }
});
