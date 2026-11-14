import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./page.go',import.meta.url),'utf8').split('const script = `')[1].split('`')[0];
function browser() {
 const elements=new Map(); const calls=[];
 const context=vm.createContext({document:{getElementById(id){if(!elements.has(id))elements.set(id,{});return elements.get(id);}}, navigator:{}, AbortSignal, setTimeout, setInterval(){}, fetch:async(url,options)=>{calls.push({url,options});return {ok:true,status:200,json:async()=>({device_auth_id:'id',user_code:'code'})};}});
 vm.runInContext(source,context);
 return {context,calls,elements};
}
test('device transport creates and polls directly to OpenAI with no cookies',async()=>{
 const {context,calls}=browser();
 await vm.runInContext('browserAuth.create()',context);
 await vm.runInContext('browserAuth.poll({device_auth_id:"id",user_code:"code"})',context);
 assert.deepEqual(calls.map(c=>c.url),['https://auth.openai.com/api/accounts/deviceauth/usercode','https://auth.openai.com/api/accounts/deviceauth/token']);
 for(const c of calls){assert.equal(c.options.credentials,'omit');assert.equal(c.options.referrerPolicy,'no-referrer');assert.equal(c.options.method,'POST');}
 assert.equal(JSON.parse(calls[0].options.body).client_id,'app_EMoamEEZ73f0CkXaXp7hrann');
 assert.equal(JSON.parse(calls[1].options.body).device_auth_id,'id');
});
test('unsupported browser does not initialize or create a code',()=>{
 const {calls,elements}=browser();assert.equal(calls.length,0);assert.match(elements.get('status').textContent,/Web Locks/);
});
test('approval sends only transient proof to Go, never token endpoint from JS',()=>{
 assert.match(source,/AuthorizationCode:approved.authorization_code,Verifier:approved.code_verifier/);
 assert.doesNotMatch(source,/localStorage\s*[.\[]|sessionStorage\s*[.\[]|access_token|refresh_token|\/oauth\/token/);
});
