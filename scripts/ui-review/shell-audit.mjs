import assert from 'node:assert/strict';

export async function inspectLayout(page, routes) {
  return page.evaluate(async (routes) => {
    const main = document.querySelector('main'), shell = document.querySelector('.production-app');
    const problems = [];
    const visuallyPresent = e => e.checkVisibility({visibilityProperty:true}) && e.getClientRects().length > 0;
    const name = e => (e.getAttribute('aria-label') || e.labels?.[0]?.innerText || e.innerText || e.getAttribute('type') || e.tagName).trim().slice(0,90);
    const receivesPointer = e => {
      const r = e.getBoundingClientRect(), hit = document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
      return !!hit && e.contains(hit);
    };
    const panel = document.querySelector('[role=dialog]') || main || document.body;
    const controls = Array.from(panel.querySelectorAll('button,a[href],input:not([type=hidden]),select,textarea,summary')).filter(visuallyPresent);
    const scrollContainers = new Set();
    for (const e of controls) {
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      let left = r.left, right = r.right, clipped = false;
      for (let parent=e.parentElement; parent && parent !== document.body; parent=parent.parentElement) {
        const rect = parent.getBoundingClientRect(), css = getComputedStyle(parent);
        if (['auto','scroll'].includes(css.overflowX) && parent.scrollWidth > parent.clientWidth + 1) {
          // Outside the current pane is reachable if it is inside its scroll extent.
          const origin = rect.left + parent.clientLeft - parent.scrollLeft;
          if (left < origin-2 || right > origin+parent.scrollWidth+2) clipped=true;
          scrollContainers.add(parent);
          left = rect.left; right = rect.right;
        } else if (['hidden','clip'].includes(css.overflowX) && (left < rect.left-2 || right > rect.right+2)) {
          clipped = true;
        }
      }
      if (clipped || left < -2 || right > innerWidth + 2) problems.push('Clipped control: '+name(e));
    }
    function inspectVisibleHitTargets(headerBottom) {
      for (const e of controls) {
        if (e.disabled || getComputedStyle(e).pointerEvents === 'none') continue;
        const r=e.getBoundingClientRect(), x=r.left+r.width/2, y=r.top+r.height/2;
        if (x<1 || x>innerWidth-1 || y<headerBottom+1 || y>innerHeight-1 || r.width<3 || r.height<3) continue;
        // A scrollable table can carry a row behind its own pane, including a
        // native scrollbar. Check only centers visible through every clip.
        let clipped=false;
        for(let parent=e.parentElement;parent&&parent!==document.body;parent=parent.parentElement) {
          const box=parent.getBoundingClientRect(),css=getComputedStyle(parent);
          if (css.overflowX!=='visible' && (x<box.left || x>box.left+parent.clientWidth) ||
              css.overflowY!=='visible' && (y<box.top || y>box.top+parent.clientHeight)) {clipped=true;break;}
        }
        if(clipped) continue;
        const hit=document.elementFromPoint(x,y);
        if (hit && (e.contains(hit) || [...(e.labels||[])].some(l=>l.contains(hit)) || hit.closest('.global-results,[role=menu]'))) continue;
        problems.push('Obscured control: '+name(e));
      }
    }
    const start = window.scrollY, maxScroll = Math.max(0, document.documentElement.scrollHeight-innerHeight);
    if (document.documentElement.scrollWidth>innerWidth+1) problems.push('Document overflows viewport');
    if (shell && !document.querySelector('[role=dialog]')) {
      const header=shell.querySelector('.topbar'), sidebar=shell.querySelector('.sidebar'), mobile=innerWidth<=760;
      const brand=header.querySelector('.brand'), toggle=header.querySelector('.mobile-menu');
      const nav=[...sidebar.querySelectorAll('nav a')];
      if (nav.filter(a=>a.getAttribute('aria-current')==='page').map(a=>a.getAttribute('href')).join()!==location.pathname) problems.push('Current navigation destination is missing');
      if (routes.some((path,i) => nav[i]?.getAttribute('href')!==path) || nav.length!==routes.length) problems.push('Navigation destinations incomplete');
      for (const stop of new Set([0,Math.round(maxScroll/2),maxScroll])) {
        window.scrollTo({top:stop,behavior:'instant'});
        await new Promise(done => requestAnimationFrame(done));
        const bounds = header.getBoundingClientRect();
        if (Math.abs(bounds.top)>1 || bounds.bottom>innerHeight || !receivesPointer(brand)) {
          problems.push('Header obscured after scrolling');
        }
        inspectVisibleHitTargets(bounds.bottom);
      }
      const bounds=header.getBoundingClientRect();
      if (mobile) {
        if (visuallyPresent(sidebar) || !visuallyPresent(toggle) || !receivesPointer(toggle)) problems.push('Incorrect mobile navigation visibility');
      } else {
        const edge=sidebar.getBoundingClientRect();
        if (!visuallyPresent(sidebar) || edge.top<bounds.bottom-1 || edge.bottom>innerHeight+1 || visuallyPresent(toggle)) problems.push('Sidebar displaced after scrolling');
        const position=sidebar.scrollTop;
        for (const [scroll,link] of [[0,nav[0]],[sidebar.scrollHeight,nav.at(-1)]]) {
          sidebar.scrollTop=scroll;
          if (!receivesPointer(link)) problems.push('Sidebar destination unreachable: '+name(link));
        }
        sidebar.scrollTop=position;
      }
      window.scrollTo({top:start,behavior:'instant'});
    } else if (!shell) inspectVisibleHitTargets(0);
    const alerts=[...panel.querySelectorAll('[role=alert]')].filter(visuallyPresent).map(e=>e.innerText.trim()).filter(Boolean);
    const emptyStates=[...panel.querySelectorAll('h2,h3,p,[role=status]')].filter(visuallyPresent).map(e=>e.innerText.trim())
      .filter(t=>t.length>0 && t.length<200 && /^(?:no |nothing |there (?:are|is) no )/i.test(t)).slice(0,12);
    const unavailable=[...panel.querySelectorAll('h2,h3,p,[role=status]')].filter(visuallyPresent).map(e=>e.innerText.trim())
      .filter(t=>t.length>0 && t.length<300 && /(?:^(?:Could not|Unable to|Failed to) (?:load|fetch|refresh|read)|service (?:is )?unavailable|API unavailable|invalid response)/i.test(t));
    const dataRows=[...panel.querySelectorAll('tbody tr')].filter(visuallyPresent).length;
    return {controls:controls.length, scrollContainers:scrollContainers.size, maxScroll, alerts, unavailable, emptyStates, dataRows,
      status:alerts.length || unavailable.length?'unavailable':dataRows?'data_rows':emptyStates.length?'empty_state':'rendered_controls',problems:[...new Set(problems)]};
  }, routes);
}

export async function visitTabs(page, visit) {
  const visited=new Set();
  for (;;) {
    const groups=await page.getByRole('tablist').evaluateAll(lists=>lists.map((list,index)=>{
      const ancestors=[]; for(let node=list.parentElement;node;node=node.parentElement)
        if(node.getAttribute('role')==='tabpanel') ancestors.unshift(node.getAttribute('aria-label') || 'panel');
      const tabs=[...list.querySelectorAll(':scope > [role=tab]')].map((tab,i)=>({
        index:i,name:tab.innerText.trim().replace(/\s+\d+$/,''),selected:tab.getAttribute('aria-selected')==='true',disabled:tab.disabled,
      }));
      return {index,ancestors,tabs};
    }));
    const candidates=groups.flatMap(g=>g.tabs.filter(t=>!t.disabled).map(t=>({...t,group:g.index,depth:g.ancestors.length,
      key: JSON.stringify([g.ancestors,g.tabs.map(x=>x.name),t.name])}))).sort((a,b)=>b.depth-a.depth||Number(b.selected)-Number(a.selected));
    const next=candidates.find(c=>!visited.has(c.key));
    if(!next) return;
    assert(visited.size<80,'Unexpected number of tab states on one route');
    visited.add(next.key);
    const tab=page.getByRole('tablist').nth(next.group).getByRole('tab').nth(next.index);
    if(!next.selected) {
      await tab.click();
      await page.waitForLoadState('networkidle');
    }
    assert.equal(await tab.getAttribute('aria-selected'),'true',`Tab did not activate: ${next.name}`);
    await visit(next.name,tab);
  }
}

export async function inspectDrawer(page, dialog) {
  await dialog.waitFor({state:'visible'});
  await dialog.evaluate(el=>Promise.allSettled(el.getAnimations().filter(a=>Number.isFinite(a.effect?.getComputedTiming().endTime)).map(a=>a.finished)));
  const r = await dialog.boundingBox(), viewport = page.viewportSize();
  assert(r && r.x>=-1 && r.y>=-1 && r.x+r.width<=viewport.width+1 && r.y+r.height<=viewport.height+1, `Drawer exceeds viewport: ${JSON.stringify(r)} at ${JSON.stringify(viewport)}`);
  const pos=await page.evaluate(()=>({top:scrollY, max:Math.max(0,document.documentElement.scrollHeight-innerHeight)}));
  // Wheel the exposed backdrop in both directions, including from the page bottom.
  const outside=r.x>4 ? 2 : r.x+r.width<viewport.width-4 ? viewport.width-2 : null;
  if (outside !== null) {
    await page.mouse.move(outside,viewport.height/2);
    for(const direction of [480,-480]){
      await page.mouse.wheel(0,direction);
      await page.waitForTimeout(100);
      assert.equal(await page.evaluate(()=>scrollY),pos.top,'Backdrop wheel scrolled the underlying page');
    }
  }
  const close=dialog.getByRole('button',{name:/close/i}).first();
  const actions=dialog.locator('a[href]:visible,button:not([disabled]):visible,input:not([disabled]):visible,select:not([disabled]):visible,summary:visible');
  const last=actions.last();
  await close.focus();
  // Use real tabbing through the scrollable body; programmatic focus on a
  // clipped last link would miss unreachable items or a premature wrap.
  const count = await actions.count();
  let tabStops = 0;
  while (!(await last.evaluate(el => el === document.activeElement))) {
    assert(tabStops < count, 'Keyboard navigation did not reach the final drawer action');
    await page.keyboard.press('Tab');
    tabStops++;
  }
  const reachable = loc => loc.evaluate(e=>{
    const b=e.getBoundingClientRect(),hit=document.elementFromPoint(b.x+b.width/2,b.y+b.height/2);
    return !!hit && e.contains(hit);
  });
  assert(await reachable(last),'Last drawer control cannot be reached');
  assert(await reachable(close),'Close control is obscured while reading the drawer bottom');
  await page.keyboard.press('Tab');
  assert(await dialog.evaluate(d=>d.contains(document.activeElement)),'Keyboard focus escaped drawer');
  return {lastControl:await last.textContent(),tabStops,closeAtBottom:true,backgroundScrollRange:pos.max,backdropTested:outside!==null};
}
