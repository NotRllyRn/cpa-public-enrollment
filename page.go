package main

const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CPA enrollment</title><h1>Connect your ChatGPT account</h1><p>This grants CPA ongoing access to your ChatGPT account. CPA will store and refresh credentials until you revoke access. Only continue if you trust this operator.</p><label><input id="consent" type="checkbox"> I authorize this ongoing access.</label><p><button id="start" disabled>Start enrollment</button></p><p id="status">Loading…</p><p id="instructions" hidden>Open <a href="https://auth.openai.com/codex/device" target="_blank" rel="noreferrer noopener">https://auth.openai.com/codex/device</a> and enter <strong id="code"></strong>. Keep this page open.</p><p>Do not share your code. If saving needs operator review, do not enroll again.</p><script src="/app.js" defer></script></html>`

const script = `"use strict";
const $ = id => document.getElementById(id);
let csrf, busy = false, paused = false;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function deliver(path, data) {
 // Retry only delivery to this companion, never OpenAI creation or exchange.
 for (let i=0; i<3; i++) {try {return await api(path,data);} catch(e) {if(i===2) throw e; await sleep(1000);}}
}
async function api(path, data = {}) {
 const r = await fetch(path, {method:'POST', redirect:'error', headers:{'Content-Type':'application/json'}, body:JSON.stringify({CSRF:csrf, ...data}), signal:AbortSignal.timeout(10000)});
 if (!r.ok) throw new Error('Session request failed. Reload to resume; contact the operator if this persists.');
 return r.json();
}
// Only this transport contacts OpenAI. It never receives access/refresh tokens.
const browserAuth = {
 async post(path, data) {
  const r = await fetch('https://auth.openai.com'+path, {method:'POST', redirect:'error', credentials:'omit', referrerPolicy:'no-referrer', headers:{'Content-Type':'application/json'},body:JSON.stringify(data), signal:AbortSignal.timeout(15000)});
  if (r.status === 403 || r.status === 404) return null;
  if (!r.ok) throw new Error('OpenAI request failed. No automatic creation retry; reload to resume.');
  return r.json();
 },
 create() {return this.post('/api/accounts/deviceauth/usercode', {client_id:'app_EMoamEEZ73f0CkXaXp7hrann'});},
 poll(s) {return this.post('/api/accounts/deviceauth/token', {device_auth_id:s.device_auth_id,user_code:s.user_code});}
};
function show(s) {
 $('status').textContent = s.status;
 $('instructions').hidden = !s.user_code;
 $('code').textContent = s.user_code || '';
 $('start').disabled = !(s.status === 'idle' || s.status === 'creating');
}
async function tick() {
 if (busy || paused) return;
 busy = true;
 try {
  const s = await api('/status'); show(s);
  if (s.status === 'waiting') {
   const claim = await api('/poll');
   if (claim.lease) {
    const approved = await browserAuth.poll(claim);
    if (approved) {
     // Transient proof only: never localStorage, URLs or logs.
     await deliver('/approved', {Lease:claim.lease,AuthorizationCode:approved.authorization_code,Verifier:approved.code_verifier});
    }
   }
  }
 } catch(e) { paused = true; $('status').textContent = 'Polling paused. Reload to resume. ' + e.message; }
 finally {busy = false;}
}
$('start').onclick = async () => {
 if (busy || !$('consent').checked) return;
 busy = true; paused = false; $('start').disabled = true;
 try {
  const s = await api('/start', {Consent:true}); show(s);
  if (s.status === 'creating' && s.lease) {
   const c = await browserAuth.create();
   if (!c) throw new Error('OpenAI creation unavailable.');
   const state = await deliver('/created', {Lease:s.lease,ID:c.device_auth_id,Code:c.user_code || c.usercode,Interval:Number(c.interval)||5});
   show(state);
  }
 } catch(e) { paused = true; $('status').textContent = e.message; }
 finally {busy = false;}
};
(async () => {
 if (!navigator.locks) { $('status').textContent='A browser with Web Locks support is required.'; return; }
 // Serializes the first cookie bootstrap too, before a shared session exists.
 const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/session'));
 csrf=s.csrf;show(s);setInterval(tick, 2000);
})().catch(() => { $('status').textContent='Unable to initialize session.'; });
`
