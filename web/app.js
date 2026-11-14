"use strict";
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
 complete:'Your account was connected successfully. You may close this tab.', duplicate:'This account is already present. Contact the operator if needed.',
 'operator-review':'Saving needs operator review. Do not enroll again; contact the operator.',
 error:'Sign-in could not be saved. Contact the operator before trying again.'
};
const titles = {
 idle:'Ready to connect', creating:'Creating your code', waiting:'Approve access at OpenAI',
 saving:'Saving your account', verifying:'Verifying connection', complete:'Account connected',
 duplicate:'Account already connected', 'operator-review':'Contact the operator',
 error:'Sign-in needs attention', expired:'Sign-in expired'
};
function hideCode() { $('instructions').hidden = true; $('code').textContent = ''; }
function show(s) {
 if (s.csrf) csrf = s.csrf;
 recovery = s.status === 'expired';
 paused = recovery || ['complete','duplicate','operator-review','error'].includes(s.status);
 $('state-title').textContent = titles[s.status] || 'Sign-in status';
 $('status').textContent = messages[s.status] || s.status;
 $('status').parentElement.dataset.state = s.status;
 hideCode();
 if (s.status === 'waiting' && s.user_code) { $('instructions').hidden = false; $('code').textContent = s.user_code; }
 $('start').textContent = recovery ? 'Start new sign-in' : 'Start sign-in';
 $('start').disabled = !(recovery || s.status === 'idle');
 $('resume').hidden = !paused;
}
async function syncSession() {
 const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/session'));
 show(s);
}
async function failure(e) {
 paused = true; hideCode(); $('start').disabled = true; $('resume').hidden = false;
 $('state-title').textContent = 'Sign-in needs attention';
 $('status').parentElement.dataset.state = e.code || 'error';
 if (['session_changed','session_expired','session_active','stale_reservation','stale_approval'].includes(e.code)) {
  try { await syncSession(); return; } catch(next) { e = next; }
 }
 if (e.code === 'session_lost') {
  csrf = undefined; recovery = true;
  $('state-title').textContent = 'Sign-in session unavailable';
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
$('resume').onclick = async () => {
 if (busy) return;
 busy = true;
 try { await syncSession(); } catch(e) { await failure(e); } finally { busy = false; }
};
$('start').onclick = async () => {
 if (busy || $('start').disabled) return;
 busy = true; $('start').disabled = true;
 try {
  if (recovery) {
   const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/restart'));
   show(s); return;
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
 if (!navigator.locks || typeof AbortSignal === 'undefined' || !AbortSignal.timeout) {
  $('start').disabled = true;
  $('state-title').textContent = 'Browser not supported';
  $('status').textContent='A browser with Web Locks and request timeout support is required. Use a current browser. No sign-in has been started.'; return;
 }
 try { await syncSession(); } catch(e) { await failure(e); }
 setInterval(tick, 2000);
})();
