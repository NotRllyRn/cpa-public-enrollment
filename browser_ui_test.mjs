// Optional real-browser checks: PLAYWRIGHT_MODULE may point to an installed
// Playwright module. All auth requests are mocked; no OpenAI/CPA login occurs.
import {test, before, after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, mkdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFileSync, spawn} from 'node:child_process';
import {createServer} from 'node:net';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
let browser, server, base, root;
const artifacts=process.env.ENROLL_BROWSER_ARTIFACTS;
const waiting={status:'waiting',csrf:'one',user_code:'TEST-CODE'};
const operator='<img src=x onerror="alert(1)"> & Example Operator';
before(async()=>{
 root=mkdtempSync(join(tmpdir(),'cpa-focused-browser-'));
 const portServer=createServer(); await new Promise(r=>portServer.listen(0,'127.0.0.1',r));
 const port=portServer.address().port; await new Promise(r=>portServer.close(r));
 base=`http://127.0.0.1:${port}`;
 const binary=join(root,'enrollment');
 execFileSync('go',['build','-o',binary,'.']);
 writeFileSync(join(root,'key'),'mock-management-key',{mode:0o600});
 server=spawn(binary,[],{env:{...process.env,ENROLL_LISTEN:`127.0.0.1:${port}`,ENROLL_PUBLIC_ORIGIN:'https://enroll.example.test',ENROLL_CPA_URL:'http://127.0.0.1:1',ENROLL_CPA_KEY_FILE:join(root,'key'),ENROLL_STATE_DIR:join(root,'state'),ENROLL_OPERATOR_NAME:operator},stdio:'ignore'});
 for(let n=0;;n++) {
  try { const r=await fetch(base); if(r.ok)break; } catch {}
  if(n===50)throw Error('Local enrollment listener did not start');
  await new Promise(r=>setTimeout(r,100));
 }
 browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 if(artifacts)mkdirSync(artifacts,{recursive:true});
});
after(async()=>{
 await browser?.close();
 if(server && server.exitCode===null) { server.kill('SIGTERM'); await new Promise(r=>server.once('exit',r)); }
 if(root)rmSync(root,{recursive:true,force:true});
});
async function pageFor(initial,{viewport={width:900,height:1000},colorScheme='light',clipboard='success'}={}) {
 const context=await browser.newContext({viewport,colorScheme});
 const page=await context.newPage(); let state=initial; const calls=[];
 const errors=[]; page.on('pageerror',e=>errors.push(e.message));
 // Polling is exercised explicitly in browser_test.mjs; freeze the timer here
 // so visual and keyboard assertions cannot race a background mocked status.
 await page.addInitScript(()=>{window.setInterval=()=>0;});
 // Test both actual browser clipboard and deterministic rejection/late completion.
 if(clipboard!=='native')await page.addInitScript(mode=>{
  window.copied=[];
  Object.defineProperty(navigator,'clipboard',{value:{writeText:async code=>{
   window.copied.push(code);
   if(mode==='failure')throw Error('Permission denied');
   if(mode==='pending')await new Promise(resolve=>window.resolveCopy=resolve);
  }}});
 },clipboard);
 await context.route('**/*',async route=>{
  const url=new URL(route.request().url());
  if(route.request().method()==='POST') {
   calls.push({url:url.pathname,data:route.request().postDataJSON()});
   assert.equal(url.origin,base,'No auth calls may leave the test listener');
   if(state==='network')return route.abort('failed');
   return route.fulfill({status:state.error?409:200,contentType:'application/json',body:JSON.stringify(state)});
  }
  if(url.href==='https://auth.openai.com/codex/device')return route.fulfill({contentType:'text/html',body:'<!doctype html><title>Mock OpenAI</title><h1>Mock sign-in destination</h1>'});
  if(url.origin!==base)throw Error('Unexpected external request: '+url);
  return route.continue();
 });
 await page.goto(base);
 await page.waitForFunction(()=>document.getElementById('state-title').textContent!=='Checking sign-in status');
 return {page,context,calls,errors,setState:s=>{state=s;}};
}
async function locked(page,expected=true) {
 const link=page.locator('#open-signin');
 assert.equal(await link.getAttribute('aria-disabled'),String(expected));
 assert.equal(await link.getAttribute('href'),expected?null:'https://auth.openai.com/codex/device');
 assert.equal(await link.evaluate(el=>el.tabIndex),expected?-1:0);
}
test('real DOM: copy gate, failed clipboard, current code/session, focus and stable disclosures',async()=>{
 const b=await pageFor(waiting,{clipboard:'failure'}), {page,context}=b;
 try {
  await locked(page);
  await page.locator('#open-signin').evaluate(el=>el.click());
  assert.equal(context.pages().length,1);
  await page.getByRole('button',{name:'Copy code',exact:true}).click();
  await page.getByText(/Could not copy the code/).waitFor(); await locked(page);
  await page.evaluate(()=>navigator.clipboard.writeText=async code=>window.copied.push(code));
  await page.locator('#copy').click(); await page.getByText(/Code copied/).waitFor(); await locked(page,false);
  assert.deepEqual(await page.evaluate(()=>window.copied),['TEST-CODE','TEST-CODE']);
  // No DOM mutation at all in the status live region on an identical polling update.
  await page.locator('summary').first().click();
  await page.evaluate(()=>{
   window.statusMutations=0;
   new MutationObserver(records=>window.statusMutations+=records.length).observe(document.getElementById('status'),{subtree:true,childList:true,characterData:true});
  });
  await page.locator('summary').first().focus();
  await page.evaluate(s=>show(s),waiting);
  assert.equal(await page.locator('details').first().getAttribute('open'),'');
  assert.equal(await page.evaluate(()=>document.activeElement.tagName),'SUMMARY');
  assert.equal(await page.evaluate(()=>window.statusMutations),0);
  await page.locator('#open-signin').focus();
  await page.evaluate(s=>show(s),{...waiting,user_code:'NEW-CODE'}); await locked(page);
  assert.equal(await page.evaluate(()=>document.activeElement.id),'copy');
  await page.locator('#copy').click(); await locked(page,false);
  await page.evaluate(s=>show(s),{...waiting,csrf:'two',user_code:'NEW-CODE'}); await locked(page);
  await page.locator('#copy').focus(); await page.keyboard.press('Tab');
  assert.notEqual(await page.evaluate(()=>document.activeElement.id),'open-signin');
  await page.locator('#copy').click(); await locked(page,false);
  await page.locator('#open-signin').focus();
  await page.evaluate(()=>show({status:'saving',csrf:'two'}));
  assert.equal(await page.evaluate(()=>document.activeElement.id),'state-title');
  assert.deepEqual(b.errors,[]);
 } finally {await context.close();}
});
test('real DOM: late clipboard completion stays locked after a session change',async()=>{
 const {page,context}=await pageFor(waiting,{clipboard:'pending'});
 try {
  await page.locator('#copy').click(); await page.waitForFunction(()=>typeof window.resolveCopy==='function');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'copy');
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(()=>window.copied.length),1,'Pending copy must not run twice');
  await page.evaluate(s=>show(s),{...waiting,csrf:'two'});
  await page.evaluate(()=>window.resolveCopy()); await locked(page);
 } finally {await context.close();}
});
test('real Chromium clipboard write unlocks sign-in without navigation or approval',async()=>{
 const {page,context,calls}=await pageFor(waiting,{clipboard:'native'});
 try {
  await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:base});
  await page.locator('#copy').click(); await page.getByText(/Code copied/).waitFor(); await locked(page,false);
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'TEST-CODE');
  assert.equal(context.pages().length,1);
  const popupReady=context.waitForEvent('page');
  await page.locator('#open-signin').click();
  const popup=await popupReady;
  await popup.getByRole('heading',{name:'Mock sign-in destination'}).waitFor();
  assert.equal(popup.url(),'https://auth.openai.com/codex/device');
  assert.equal(await page.locator('#task').getAttribute('data-state'),'waiting');
  assert.equal(calls.some(c=>['/start','/approved'].includes(c.url)),false);
 } finally {await context.close();}
});
test('flow states, responsive light/dark, plain-text operator and closure actions',async()=>{
 const states=['idle','creating','waiting','saving','verifying','complete','duplicate','operator-review','error','expired'];
 for(const colorScheme of ['light','dark'])for(const width of [320,768,1280]) {
  const {page,context,errors}=await pageFor({status:'idle',csrf:'one'},{viewport:{width,height:1050},colorScheme});
  try {
   assert.equal(await page.locator('#operator-name').textContent(),operator);
   assert.equal(await page.locator('#operator-name img').count(),0);
   for(const status of states) {
    await page.evaluate(s=>show(s),{...waiting,status});
    assert.equal(await page.locator('#start').isVisible(),['idle','expired'].includes(status));
    assert.equal(await page.locator('#instructions').isVisible(),status==='waiting');
    assert.equal(await page.locator('#resume').isVisible(),false);
    assert.equal(await page.locator('#disclosure').isVisible(),status==='idle');
    const stage=['idle','creating','expired'].includes(status)?'review':status==='waiting'?'approve':'confirm';
    assert.equal(await page.locator('[aria-current="step"]').getAttribute('id'),'stage-'+stage);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${status} overflows ${width}`);
    if(artifacts && ['idle','waiting','complete','operator-review','expired'].includes(status))await page.screenshot({path:join(artifacts,`${colorScheme}-${width}-${status}.png`),fullPage:true});
   }
   assert.deepEqual(errors,[]);
  } finally {await context.close();}
 }
});
test('explicit consent only after reset, interrupted vs terminal error, unsupported and no-script',async()=>{
 const {page,context,calls,setState}=await pageFor({status:'expired',csrf:'one'});
 try {
  setState({status:'idle',csrf:'two'});
  await page.getByRole('button',{name:'Reset expired sign-in'}).click();
  await page.getByRole('button',{name:'Authorize and start'}).waitFor();
  assert.equal(calls.filter(c=>c.url==='/restart').length,1);
  assert.equal(calls.some(c=>c.url==='/start'),false);
  setState({status:'creating',csrf:'two'});
  await page.getByRole('button',{name:'Authorize and start'}).click();
  await page.getByRole('heading',{name:'Creating your sign-in code'}).waitFor();
  assert.equal(await page.evaluate(()=>document.activeElement.id),'state-title');
  assert.equal(calls.find(c=>c.url==='/start').data.Consent,true);
  await page.evaluate(()=>failure(new TypeError('Failed to fetch')));
  assert.equal(await page.locator('#resume').isVisible(),true);
  assert.equal(await page.locator('#start').isVisible(),false);
  assert.equal(await page.locator('#state-title').textContent(),'Connection interrupted');
  await page.evaluate(()=>show({status:'error',csrf:'two'}));
  assert.equal(await page.locator('#resume').isVisible(),false);
  assert.equal(await page.locator('#start').isVisible(),false);
  await page.evaluate(()=>failure(Object.assign(new Error('Service updated or session unavailable.'),{code:'session_lost'})));
  await page.getByRole('button',{name:'Reset session to review access'}).waitFor();
  await page.getByText(/If you already approved at OpenAI/).waitFor();
  setState({status:'idle',csrf:'three'});
  await page.getByRole('button',{name:'Reset session to review access'}).click();
  await page.getByRole('button',{name:'Authorize and start'}).waitFor();
  assert.equal(calls.filter(c=>c.url==='/start').length,1,'Lost-session reset must not start another sign-in');
 } finally {await context.close();}
 const unsupported=await browser.newContext(); const up=await unsupported.newPage();
 await up.addInitScript(()=>Object.defineProperty(navigator,'locks',{value:undefined}));
 await up.goto(base); await up.getByText('Use a supported browser').waitFor();
 assert.equal(await up.locator('#start').isVisible(),false); await unsupported.close();
 const noScript=await browser.newContext({javaScriptEnabled:false}), np=await noScript.newPage();
 await np.goto(base); assert.equal(await np.locator('noscript').isVisible(),true);
 assert.equal(await np.locator('#start').isVisible(),false); await noScript.close();
});
