package main

const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CPA enrollment</title><h1>Connect your ChatGPT account</h1><p>This grants CPA ongoing access to your ChatGPT account. CPA will store and refresh credentials until you revoke access. Only continue if you trust this operator.</p><label><input id="consent" type="checkbox"> I authorize this ongoing access.</label><p><button id="start" disabled>Start enrollment</button> <button id="resume" hidden>Check sign-in status</button></p><p id="status">Loading…</p><p id="instructions" hidden>Open <a href="https://auth.openai.com/codex/device" target="_blank" rel="noreferrer noopener">https://auth.openai.com/codex/device</a> and enter <strong id="code"></strong>. Keep this page open.</p><p>Do not share your code. If saving needs operator review, do not enroll again.</p><script src="/app.js" defer></script></html>`

const script = `"use strict";
const $ = id => document.getElementById(id);
let csrf, busy = false, paused = false, recovery = false;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function deliver(path, data) {
 // Retry only transport/temporary delivery failures, never structured conflicts
 // or OpenAI creation/exchange. A changed session must not receive old proof.
 for (let i=0; i<3; i++) {try {return await api(path,data);} catch(e) {if((e.code && e.code !== 'save_busy') || i===2) throw e; await sleep(1000);}}
}
async function api(path, data = {}) {
 const r = await fetch(path, {method:'POST', redirect:'error', headers:{'Content-Type':'application/json'}, body:JSON.stringify({CSRF:csrf, ...data}), signal:AbortSignal.timeout(10000)});
 const body = await r.json().catch(() => ({}));
 if (!r.ok) {
  const e = new Error(body.error?.message || 'Sign-in service unavailable. Check status shortly; do not start another sign-in while saving.');
  e.code = body.error?.code; throw e;
 }
 return body;
}
// Only this transport contacts OpenAI. It never receives access/refresh tokens.
const browserAuth = {
 async post(path, data) {
  const r = await fetch('https://auth.openai.com'+path, {method:'POST', redirect:'error', credentials:'omit', referrerPolicy:'no-referrer', headers:{'Content-Type':'application/json'},body:JSON.stringify(data), signal:AbortSignal.timeout(15000)});
  if (r.status === 403 || r.status === 404) return null;
  if (!r.ok) throw new Error('OpenAI request failed. Check sign-in status; code creation is not automatically retried.');
  return r.json();
 },
 create() {return this.post('/api/accounts/deviceauth/usercode', {client_id:'app_EMoamEEZ73f0CkXaXp7hrann'});},
 poll(s) {return this.post('/api/accounts/deviceauth/token', {device_auth_id:s.device_auth_id,user_code:s.user_code});}
};
const messages = {
 idle:'Ready to start sign-in.', creating:'Creating sign-in code…', waiting:'Waiting for approval.',
 expired:'This sign-in expired after 15 minutes. Start a new sign-in to get a new code.',
 saving:'Saving your account. Do not start another sign-in.', verifying:'Checking that CPA adopted your account. Do not start another sign-in.',
 complete:'Account connected.', duplicate:'This account is already present. Contact the operator if needed.',
 'operator-review':'Saving needs operator review. Do not enroll again; contact the operator.',
 error:'Sign-in could not be saved. Contact the operator before trying again.'
};
function hideCode() { $('instructions').hidden = true; $('code').textContent = ''; }
function show(s) {
 if (s.csrf) csrf = s.csrf;
 recovery = s.status === 'expired';
 paused = recovery || ['complete','duplicate','operator-review','error'].includes(s.status);
 $('status').textContent = messages[s.status] || s.status;
 hideCode();
 if (s.status === 'waiting' && s.user_code) { $('instructions').hidden = false; $('code').textContent = s.user_code; }
 $('start').textContent = recovery ? 'Start new sign-in' : 'Start enrollment';
 $('start').disabled = recovery ? false : !(['idle','creating'].includes(s.status) && $('consent').checked);
 $('resume').hidden = !paused;
}
async function syncSession() {
 const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/session'));
 show(s);
}
async function failure(e) {
 paused = true; hideCode(); $('start').disabled = true; $('resume').hidden = false;
 if (['session_changed','session_expired','session_active','stale_reservation','stale_approval'].includes(e.code)) {
  try { await syncSession(); return; } catch(next) { e = next; }
 }
 if (e.code === 'session_lost') {
  csrf = undefined; recovery = true;
  $('start').textContent = 'Start new sign-in'; $('start').disabled = false;
 }
 $('status').textContent = e.message || 'Connection interrupted. Check sign-in status before taking further action.';
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
     show(await deliver('/approved', {Lease:claim.lease,AuthorizationCode:approved.authorization_code,Verifier:approved.code_verifier}));
    }
   } else if (claim.status !== 'waiting') { show(claim); }
  }
 } catch(e) { await failure(e); }
 finally {busy = false;}
}
$('consent').onchange = () => { if (!busy && !recovery) tick(); };
$('resume').onclick = async () => {
 if (busy) return;
 busy = true;
 try { await syncSession(); } catch(e) { await failure(e); } finally { busy = false; }
};
$('start').onclick = async () => {
 if (busy || (!recovery && !$('consent').checked)) return;
 busy = true; $('start').disabled = true;
 try {
  if (recovery) {
   const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/restart'));
   $('consent').checked = false; show(s); return;
  }
  const s = await api('/start', {Consent:true}); show(s);
  if (s.status === 'creating' && s.lease) {
   const c = await browserAuth.create();
   if (!c) throw new Error('OpenAI creation unavailable. Check sign-in status.');
   show(await deliver('/created', {Lease:s.lease,ID:c.device_auth_id,Code:c.user_code || c.usercode,Interval:Number(c.interval)||5}));
  }
 } catch(e) { await failure(e); }
 finally {busy = false;}
};
(async () => {
 if (!navigator.locks) { $('status').textContent='A browser with Web Locks support is required.'; return; }
 try { await syncSession(); } catch(e) { await failure(e); }
 setInterval(tick, 2000);
})();
`
