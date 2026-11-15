import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./web/app.js',import.meta.url),'utf8');
const html=readFileSync(new URL('./web/index.html',import.meta.url),'utf8');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
function browser({supported=false,reply,writeText}={}) {
 const elements=new Map(), calls=[], clipboard=[];
 const document={getElementById(id){
  if(!elements.has(id)) {
   const attributes=new Map(); let content='';
   elements.set(id, {dataset:{}, hidden:false, writes:0,
    get textContent(){return content;}, set textContent(value){this.writes++;content=value;},
    setAttribute(name,value){attributes.set(name,value);},removeAttribute(name){attributes.delete(name);},getAttribute(name){return attributes.get(name)??null;},
    focus(){document.activeElement=this;},closest(){return null;}
   });
  }
  return elements.get(id);
 }};
 const context=vm.createContext({document, navigator:supported?{locks:{request:async(_name,fn)=>fn()},clipboard:{writeText:async text=>{clipboard.push(text);if(writeText)await writeText(text);}}}:{}, AbortSignal, setTimeout, setInterval(){}, fetch:async(url,options)=>{
  const data=JSON.parse(options.body); calls.push({url,options,data});
  const response=reply?await reply(url,data):{device_auth_id:'id',user_code:'code'};
  return {ok:!response.error,status:response.error?409:200,json:async()=>response};
 }});
 vm.runInContext(source,context);
 return {context,calls,elements,clipboard,run:code=>vm.runInContext(code,context)};
}
test('device transport creates and polls directly to OpenAI with no cookies',async()=>{
 const {run,calls}=browser();
 await run('browserAuth.create()');
 await run('browserAuth.poll({device_auth_id:"id",user_code:"code"})');
 assert.deepEqual(calls.map(c=>c.url),['https://auth.openai.com/api/accounts/deviceauth/usercode','https://auth.openai.com/api/accounts/deviceauth/token']);
 for(const c of calls){assert.equal(c.options.credentials,'omit');assert.equal(c.options.referrerPolicy,'no-referrer');assert.equal(c.options.method,'POST');}
 assert.equal(calls[0].data.client_id,'app_EMoamEEZ73f0CkXaXp7hrann');
 assert.equal(calls[1].data.device_auth_id,'id');
});
test('terminal diagnostics are literal text and offer explicit reset',()=>{
 const b=browser();
 for(const status of ['error','operator-review']) {
  b.run(`show({status:${JSON.stringify(status)},message:'Checking CPA inventory failed: HTTP 403 (Forbidden). <img src=x onerror=alert(1)>'})`);
  assert.match(b.elements.get('status').textContent,/Checking CPA inventory failed: HTTP 403/);
  assert.match(b.elements.get('status').textContent,/<img src=x/);
  assert.equal(b.elements.get('start').hidden,false);
  assert.match(b.elements.get('status').textContent,/Reset/);
  assert.equal(b.elements.get('instructions').hidden,true);
 }
});
test('OpenAI failures show operation and status, never upstream body',async()=>{
 const b=browser({reply:()=>({error:{message:'<html>SECRET member@example.test</html>'}})});
 await assert.rejects(b.run('browserAuth.create()'),e=>/Creating OpenAI sign-in code failed: HTTP 409/.test(e.message)&&!e.message.includes('SECRET'));
 await assert.rejects(b.run('browserAuth.poll({})'),e=>/Checking OpenAI device approval failed: HTTP 409/.test(e.message)&&!e.message.includes('member@'));
});
test('unsupported browser does not initialize or create a code',()=>{
 const {calls,elements}=browser();assert.equal(calls.length,0);assert.match(elements.get('status').textContent,/Web Locks/);
});
test('approval sends only transient proof to Go, never token endpoint from JS',()=>{
 assert.match(source,/AuthorizationCode:approved.authorization_code,Verifier:approved.code_verifier/);
 assert.doesNotMatch(source,/localStorage\s*[.\[]|sessionStorage\s*[.\[]|access_token|refresh_token|\/oauth\/token/);
});
test('expiry hides code and stops polling until explicit restart rotates CSRF',async()=>{
 const b=browser({supported:true,reply:url=>url==='/restart'?{status:'idle',csrf:'new-csrf'}:{status:'expired',csrf:'old-csrf',user_code:'STALE'}});
 await settle();
 assert.equal(b.elements.get('instructions').hidden,true);
 assert.equal(b.elements.get('code').textContent,'');
 assert.equal(b.elements.get('start').textContent,'Reset session to review access');
 await b.run('tick()'); assert.equal(b.calls.length,1);
 await b.elements.get('start').onclick();
 assert.deepEqual(b.calls.map(c=>c.url),['/session','/restart']);
 assert.equal(b.calls[1].data.CSRF,'old-csrf');
 assert.equal(b.elements.has('consent'),false);
 assert.equal(b.elements.get('start').disabled,false);
 assert.equal(b.run('csrf'),'new-csrf');
});
test('lost cookie state shows service-updated warning without silently creating a session',async()=>{
 const b=browser({supported:true,reply:url=>url==='/restart'?{status:'idle',csrf:'recovered'}:{error:{code:'session_lost',message:'Service updated. Contact the operator if saving.'}}});
 await settle(); await b.run('tick()');
 assert.equal(b.calls.length,1); assert.match(b.elements.get('status').textContent,/Service updated/);
 assert.doesNotMatch(b.elements.get('status').textContent,/reload/i);
 assert.equal(b.elements.get('start').textContent,'Reset session to review access');
 await b.elements.get('start').onclick();
 assert.equal(b.calls[1].url,'/restart'); assert.equal(b.run('csrf'),'recovered');
});
test('stale tab synchronizes current session but never redelivers stale approval',async()=>{
 let sessions=0;
 const b=browser({supported:true,reply:url=>{
  if(url==='/session') return ++sessions===1?{status:'waiting',csrf:'old',user_code:'CODE'}:{status:'saving',csrf:'other-tab'};
  if(url==='/status') return {status:'waiting',csrf:'old',user_code:'CODE'};
  if(url==='/poll') return {status:'waiting',lease:'proof',device_auth_id:'device',user_code:'CODE'};
  if(url.startsWith('https:')) return {authorization_code:'approval',code_verifier:'verifier'};
  if(url==='/approved') return {error:{code:'session_changed',message:'Another tab changed session.'}};
  throw new Error('unexpected '+url);
 }});
 await settle(); await b.run('tick()');
 assert.equal(b.calls.filter(c=>c.url==='/approved').length,1);
 assert.equal(sessions,2); assert.equal(b.run('csrf'),'other-tab');
 assert.match(b.elements.get('status').textContent,/Saving/);
 assert.equal(b.elements.get('start').disabled,true); assert.equal(b.elements.get('instructions').hidden,true);
});
test('expiry conflict checks existing save without presenting a restart',async()=>{
 let sessions=0;
 const b=browser({supported:true,reply:url=>{
  if(url==='/session') return ++sessions===1?{status:'waiting',csrf:'one',user_code:'CODE'}:{status:'verifying',csrf:'one'};
  if(url==='/status') return {error:{code:'session_expired',message:'Authorization ended.'}};
  throw new Error('must not create or poll');
 }});
 await settle(); await b.run('tick()');
 assert.match(b.elements.get('status').textContent,/Checking that CPA/);
 assert.equal(b.elements.get('start').disabled,true);
 assert.equal(b.elements.get('code').textContent,'');
});
test('terminal states hide device code and offer reset only when allowed',async()=>{
 for(const status of ['complete','duplicate','operator-review','error']) {
  const b=browser({supported:true,reply:()=>({status,csrf:'one',user_code:'STALE'})});
  await settle(); await b.run('tick()');
  assert.equal(b.calls.length,1); assert.equal(b.elements.get('start').disabled,status==='complete');
  assert.equal(b.elements.get('instructions').hidden,true); assert.equal(b.elements.get('code').textContent,'');
 }
});

test('idle initialization and status checks never automatically start sign-in', async()=>{
 const b=browser({supported:true,reply:()=>({status:'idle',csrf:'one'})});
 await settle(); await b.run('tick()');
 assert.deepEqual(b.calls.map(c=>c.url),['/session','/status']);
 assert.equal(b.elements.get('start').disabled,false);
 await b.elements.get('start').onclick();
 const start=b.calls.find(c=>c.url==='/start');
 assert.equal(start.data.Consent,true);
});
test('all flow states have clear headings, actions and code visibility', async()=>{
 for(const status of ['idle','creating','waiting','saving','verifying','complete','duplicate','operator-review','error','expired']) {
  const b=browser({supported:true,reply:()=>({status,csrf:'one',user_code:'CODE'})});
  await settle();
  assert.ok(b.elements.get('state-title').textContent);
  assert.ok(b.elements.get('status').textContent);
  assert.equal(b.elements.get('instructions').hidden,status!=='waiting');
  assert.equal(b.elements.get('start').disabled,!['idle','expired','error','operator-review','duplicate'].includes(status));
 }
});
test('explicit authorization, progressive disclosure and exact stopping-access text',()=>{
 assert.doesNotMatch(html,/type="checkbox"|id="consent"/);
 assert.match(html,/By selecting Authorize and start, you allow this operator/);
 assert.match(html,/<details class="learn-more">\s*<summary>How access works<\/summary>/);
 assert.doesNotMatch(html,/<details[^>]*\sopen[\s>]/);
 assert.doesNotMatch(html,/stores and refreshes credentials|never enter your OpenAI password here|until you revoke it|Only continue if you trust|it does not test actual Codex requests/);
 assert.match(html,/<h1 id="title">Connect Codex<\/h1>/);
 assert.doesNotMatch(html,/<p class="kicker">|<p class="operator">/);
 assert.match(html,/operator controls how your Codex access/);
 assert.match(html,/<p><strong>How to stop access\?<\/strong> Manage connected access in your OpenAI account<\/p>/);
 assert.doesNotMatch(html,/security settings|removing.*stored|promise of revocation|Ask the operator about/);
 assert.match(html,/Opening the page alone does not approve access/);
 assert.match(html,/aria-live="polite"/);
});

const waiting={status:'waiting',csrf:'one',user_code:'CURRENT'};
function assertGate(b,unlocked) {
 const link=b.elements.get('open-signin');
 assert.equal(link.getAttribute('aria-disabled'),String(!unlocked));
 assert.equal(link.getAttribute('href'),unlocked?'https://auth.openai.com/codex/device':null);
 assert.equal(link.tabIndex,unlocked?0:-1);
}
test('OpenAI link is locked until Copy succeeds for the current code, navigation never approves',async()=>{
 const b=browser({supported:true,reply:()=>waiting}); await settle();
 assertGate(b,false);
 let prevented=false;
 b.elements.get('open-signin').onclick({preventDefault(){prevented=true;}});
 assert.equal(prevented,true);
 await b.elements.get('copy').onclick();
 assert.deepEqual(b.clipboard,['CURRENT']); assertGate(b,true);
 assert.match(b.elements.get('copy-feedback').textContent,/Code copied/);
 b.elements.get('open-signin').onclick({preventDefault(){throw Error('successful copy must unlock');}});
 assert.deepEqual(b.calls.map(c=>c.url),['/session']);
 assert.equal(b.elements.get('task').dataset.state,'waiting');
});
test('clipboard failure or missing API keeps OpenAI locked and gives retry advice',async()=>{
 let fail=true;
 const b=browser({supported:true,reply:()=>waiting,writeText:()=>{if(fail)throw Error('Permission denied');}}); await settle();
 await b.elements.get('copy').onclick(); assertGate(b,false);
 assert.equal(b.elements.get('copy').getAttribute('aria-disabled'),'false');
 assert.match(b.elements.get('copy-feedback').textContent,/Allow clipboard access.*Copy code to retry/);
 fail=false; await b.elements.get('copy').onclick(); assertGate(b,true);
 // A new failed copy must not retain an earlier successful gate.
 b.run('navigator.clipboard = undefined');
 await b.elements.get('copy').onclick(); assertGate(b,false);
 assert.match(b.elements.get('copy-feedback').textContent,/stays locked/);
});
test('code and session changes each require a successful re-copy, same polls do not',async()=>{
 const b=browser({supported:true,reply:()=>waiting}); await settle();
 await b.elements.get('copy').onclick();
 const statusWrites=b.elements.get('status').writes;
 const copyWrites=b.elements.get('copy-feedback').writes;
 await b.run('show({status:"waiting",csrf:"one",user_code:"CURRENT"})');
 assertGate(b,true);
 assert.equal(b.elements.get('status').writes,statusWrites);
 assert.equal(b.elements.get('copy-feedback').writes,copyWrites);
 await b.run('show({status:"waiting",csrf:"one",user_code:"OTHER"})'); assertGate(b,false);
 await b.elements.get('copy').onclick(); assertGate(b,true);
 await b.run('show({status:"waiting",csrf:"two",user_code:"OTHER"})'); assertGate(b,false);
 await b.elements.get('copy').onclick(); assertGate(b,true);
 await b.run('show({status:"saving",csrf:"two"})'); assertGate(b,false);
 assert.equal(b.elements.get('instructions').hidden,true);
});
test('late clipboard success never unlocks a changed session or code',async()=>{
 for(const change of [
  'show({status:"waiting",csrf:"one",user_code:"NEW"})',
  'show({status:"waiting",csrf:"two",user_code:"CURRENT"})',
  'show({status:"expired",csrf:"one"}); show({status:"waiting",csrf:"one",user_code:"CURRENT"})'
 ]) {
  let resolve;
  const b=browser({supported:true,reply:()=>waiting,writeText:()=>new Promise(r=>resolve=r)}); await settle();
  const copying=b.elements.get('copy').onclick(); assertGate(b,false);
  await b.run(change); resolve(); await copying; assertGate(b,false);
  assert.equal(b.elements.get('copy').getAttribute('aria-disabled'),'false');
 }
});
test('transport interruption is not a terminal save error; checking restores state but requires re-copy',async()=>{
 const b=browser({supported:true,reply:()=>waiting}); await settle();
 await b.elements.get('copy').onclick();
 await b.run('failure(new TypeError("Failed to fetch"))');
 assertGate(b,false); assert.equal(b.elements.get('task').dataset.state,'network');
 assert.match(b.elements.get('status').textContent,/result is unknown/);
 assert.equal(b.elements.get('resume').hidden,false);
 assert.equal(b.elements.get('start').hidden,true);
 await b.elements.get('resume').onclick(); assertGate(b,false);
 await b.run('failure(Object.assign(new Error("OpenAI request failed"),{code:"openai_request_failed"}))');
 assert.equal(b.elements.get('task').dataset.state,'openai_request_failed');
 assert.match(b.elements.get('status').textContent,/OpenAI request failed/);
 // DOMException timeout numeric codes are transport failures, not server errors.
 await b.run('failure(Object.assign(new Error("aborted"),{code:23}))');
 assert.equal(b.elements.get('task').dataset.state,'network');
});
test('state-specific actions require review after terminal reset',async()=>{
 for(const status of ['idle','creating','waiting','saving','verifying','complete','duplicate','operator-review','error','expired']) {
  const b=browser({supported:true,reply:()=>({...waiting,status})}); await settle();
  assert.equal(b.elements.get('disclosure').hidden,status!=='idle');
  assert.equal(b.elements.get('start').hidden,!['idle','expired','error','operator-review','duplicate'].includes(status));
  assert.equal(b.elements.get('resume').hidden,true);
  assert.equal(b.calls.some(c=>c.url==='/start'),false);
 }
});
