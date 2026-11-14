import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./page.go',import.meta.url),'utf8').split('const script = `')[1].split('`')[0];
const settle=()=>new Promise(resolve=>setImmediate(resolve));
function browser({supported=false,reply}={}) {
 const elements=new Map(); const calls=[];
 const context=vm.createContext({document:{getElementById(id){if(!elements.has(id))elements.set(id,{checked:false});return elements.get(id);}}, navigator:supported?{locks:{request:async(_name,fn)=>fn()}}:{}, AbortSignal, setTimeout, setInterval(){}, fetch:async(url,options)=>{
  const data=JSON.parse(options.body); calls.push({url,options,data});
  const response=reply?await reply(url,data):{device_auth_id:'id',user_code:'code'};
  return {ok:!response.error,status:response.error?409:200,json:async()=>response};
 }});
 vm.runInContext(source,context);
 return {context,calls,elements,run:code=>vm.runInContext(code,context)};
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
 assert.equal(b.elements.get('start').textContent,'Start new sign-in');
 await b.run('tick()'); assert.equal(b.calls.length,1);
 await b.elements.get('start').onclick();
 assert.deepEqual(b.calls.map(c=>c.url),['/session','/restart']);
 assert.equal(b.calls[1].data.CSRF,'old-csrf');
 assert.equal(b.elements.get('consent').checked,false);
 assert.equal(b.elements.get('start').disabled,true);
 assert.equal(b.run('csrf'),'new-csrf');
});
test('lost cookie state shows service-updated warning without silently creating a session',async()=>{
 const b=browser({supported:true,reply:url=>url==='/restart'?{status:'idle',csrf:'recovered'}:{error:{code:'session_lost',message:'Service updated. Contact the operator if saving.'}}});
 await settle(); await b.run('tick()');
 assert.equal(b.calls.length,1); assert.match(b.elements.get('status').textContent,/Service updated/);
 assert.doesNotMatch(b.elements.get('status').textContent,/reload/i);
 assert.equal(b.elements.get('start').textContent,'Start new sign-in');
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
test('terminal and operator-review states never offer restart or keep device code',async()=>{
 for(const status of ['complete','duplicate','operator-review','error']) {
  const b=browser({supported:true,reply:()=>({status,csrf:'one',user_code:'STALE'})});
  await settle(); await b.run('tick()');
  assert.equal(b.calls.length,1); assert.equal(b.elements.get('start').disabled,true);
  assert.equal(b.elements.get('instructions').hidden,true); assert.equal(b.elements.get('code').textContent,'');
 }
});
