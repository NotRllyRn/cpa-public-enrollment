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
  const operation = path.endsWith('/usercode') ? 'Creating OpenAI sign-in code' : 'Checking OpenAI device approval';
  let r;
  try { r = await fetch('https://auth.openai.com'+path, {method:'POST', redirect:'error', credentials:'omit', referrerPolicy:'no-referrer', headers:{'Content-Type':'application/json'},body:JSON.stringify(data), signal:AbortSignal.timeout(15000)}); } catch {
   const e = new Error(operation + ' failed: OpenAI could not be reached or the request timed out. Check sign-in status; do not start another sign-in.');
   e.code = 'openai_request_failed'; throw e;
  }
  // These responses mean approval is still pending only on the poll endpoint.
  if ((r.status === 403 || r.status === 404) && path.endsWith('/token')) return null;
  if (!r.ok) {
   const e = new Error(operation + ' failed: HTTP ' + r.status + '. Check sign-in status; code creation is not automatically retried.');
   e.code = 'openai_request_failed'; throw e;
  }
  try { return await r.json(); } catch {
   const e = new Error(operation + ' failed: OpenAI returned invalid JSON. Check sign-in status before trying again.');
   e.code = 'openai_request_failed'; throw e;
  }
 },
 create() {return this.post('/api/accounts/deviceauth/usercode', {client_id:'app_EMoamEEZ73f0CkXaXp7hrann'});},
 poll(s) {return this.post('/api/accounts/deviceauth/token', {device_auth_id:s.device_auth_id,user_code:s.user_code});}
};
const messages = {
 idle:'You’ll approve access on OpenAI’s website, then return here.',
 creating:'No approval has happened yet. Wait here; we will not automatically request another code.',
 waiting:'Waiting for your approval on OpenAI’s website.',
 expired:'The old code can no longer be used. Reset this session, then review access before starting again. Resetting does not create a code.',
 saving:'Saving your account. Keep this tab open. Do not start another sign-in.',
 verifying:'Checking that CPA adopted your account. Do not start another sign-in.',
 complete:'Your credentials were accepted by CPA. You may close this tab.',
 duplicate:'This account is already connected. No new enrollment was added. If this is unexpected, contact the operator before trying again.',
 'operator-review':'The result is uncertain. You can reset local pending credentials and review access again. Reset does not revoke access or undo a CPA import.',
 error:'Sign-in could not be saved. Reset to clear local pending credentials and review access again.'
};
const titles = {
 idle:'Review ongoing access', creating:'Creating your sign-in code', waiting:'Finish on OpenAI',
 saving:'Saving your account', verifying:'Confirming your connection', complete:'Codex connected',
 duplicate:'Account already connected', 'operator-review':'The operator needs to check this',
 error:'Sign-in needs attention', expired:'This sign-in expired'
};
// Keep the DOM (including open disclosures and keyboard focus) stable on polls.
// Updating live text only when it changes avoids repeating identical announcements.
function text(id, value) { if ($(id).textContent !== value) $(id).textContent = value; }
function restoreFocus(previous) {
 // Browsers may blur to <body> as soon as a focused control is hidden.
 if (previous?.closest('[hidden]')) $('state-title').focus();
}
const destination = 'https://auth.openai.com/codex/device';
let codeKey = '', copyGeneration = 0, copied = false, copyPending = false;
function renderCopyGate() {
 const link = $('open-signin');
 link.setAttribute('aria-disabled', String(!copied));
 link.tabIndex = copied ? 0 : -1;
 if (copied) link.setAttribute('href', destination); else link.removeAttribute('href');
}
function resetCopy(key = '') {
 if (key === codeKey) return;
 const linkFocused = document.activeElement === $('open-signin');
 codeKey = key; copyGeneration++; copied = false; copyPending = false;
 $('copy').setAttribute('aria-disabled', 'false');
 text('copy-feedback', key ? 'Copy this code to unlock OpenAI sign-in.' : '');
 renderCopyGate();
 if (key && linkFocused) $('copy').focus();
}
function hideCode() {
 $('instructions').hidden = true; text('code', ''); resetCopy();
}
$('open-signin').onclick = event => {
 if (!copied || !codeKey) event.preventDefault();
 // Navigation never changes approval state or creates a new OAuth request.
};
$('copy').onclick = async () => {
 if (!codeKey || copyPending) return;
 const key = codeKey, generation = ++copyGeneration, code = $('code').textContent;
 copied = false; copyPending = true; renderCopyGate();
 // aria-disabled prevents duplicate work without discarding keyboard focus.
 $('copy').setAttribute('aria-disabled', 'true');
 text('copy-feedback', 'Copying code…');
 try {
  if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
  await navigator.clipboard.writeText(code);
  if (key !== codeKey || generation !== copyGeneration) return;
  copied = true; renderCopyGate();
  text('copy-feedback', 'Code copied. Open OpenAI sign-in to enter it.');
 } catch {
  if (key !== codeKey || generation !== copyGeneration) return;
  text('copy-feedback', 'Could not copy the code. Allow clipboard access in your browser, then select Copy code to retry. OpenAI sign-in stays locked until copying succeeds.');
 } finally {
  if (key === codeKey && generation === copyGeneration) {
   copyPending = false; $('copy').setAttribute('aria-disabled', 'false');
  }
 }
};
function show(s) {
 const focused = document.activeElement;
 if (s.csrf) csrf = s.csrf;
 recovery = ['expired','error','operator-review','duplicate'].includes(s.status);
 paused = recovery || ['complete','duplicate','operator-review','error'].includes(s.status);
 text('state-title', titles[s.status] || 'Sign-in status');
 const detail = ['error','operator-review'].includes(s.status) && typeof s.message === 'string' ? s.message + ' ' : '';
 text('status', detail + (messages[s.status] || 'Check sign-in status before taking further action.'));
 $('task').dataset.state = s.status;
 $('disclosure').hidden = s.status !== 'idle';
 if (s.status === 'waiting' && s.user_code) {
  $('instructions').hidden = false; text('code', s.user_code);
  resetCopy(JSON.stringify([csrf, s.user_code]));
 } else { hideCode(); }
 text('start', recovery ? 'Reset session to review access' : 'Authorize and start');
 $('start').disabled = !(recovery || s.status === 'idle');
 $('start').hidden = $('start').disabled;
 $('start').setAttribute('aria-disabled', String($('start').disabled));
 $('start').setAttribute('aria-describedby', recovery ? 'status' : 'disclosure');
 $('resume').hidden = true;
 const stage = ['idle','creating','expired'].includes(s.status) ? 'review' : s.status === 'waiting' ? 'approve' : 'confirm';
 for (const name of ['review','approve','confirm']) {
  if (name === stage) $('stage-'+name).setAttribute('aria-current', 'step');
  else $('stage-'+name).removeAttribute('aria-current');
 }
 restoreFocus(focused);
}
async function syncSession() {
 const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/session'));
 show(s);
}
async function failure(e) {
 const focused = document.activeElement;
 paused = true; recovery = false; hideCode();
 $('disclosure').hidden = true;
 $('start').disabled = true; $('start').hidden = true; $('resume').hidden = false;
 $('start').setAttribute('aria-disabled', 'true');
 if (['session_changed','session_expired','session_active','stale_reservation','stale_approval'].includes(e.code)) {
  try { await syncSession(); restoreFocus(focused); return; } catch(next) { e = next; }
 }
 const structured = typeof e.code === 'string' && e.code !== '';
 $('task').dataset.state = structured ? e.code : 'network';
 text('state-title', structured ? 'Sign-in needs attention' : 'Connection interrupted');
 text('status', structured ? e.message : 'The sign-in service or OpenAI could not be reached. The result is unknown; approval or saving may still be in progress. Check sign-in status. Do not start another sign-in.');
 if (e.code === 'session_lost') {
  csrf = undefined; recovery = true;
  text('state-title', 'Your session is unavailable');
  text('status', e.message + ' Reset does not create a code.');
  text('start', 'Reset session to review access');
  $('start').setAttribute('aria-describedby', 'status');
  $('start').disabled = false; $('start').hidden = false;
  $('start').setAttribute('aria-disabled', 'false');
 }
 restoreFocus(focused);
}
async function tick() {
 if (busy || paused) return;
 busy = true;
 try {
  const s = await api('/status'); show(s);
  if (s.status === 'waiting') {
   const claim = await api('/poll');
   if (claim.lease) {
    let approved;
    try { approved = await browserAuth.poll(claim); }
    catch(e) { await api('/client-failure', {Stage:'poll',Lease:claim.lease}).catch(() => {}); throw e; }
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
 busy = true; $('start').setAttribute('aria-disabled', 'true');
 try {
  if (recovery) {
   const s = await navigator.locks.request('cpa-session-bootstrap', () => api('/restart'));
   show(s); return;
  }
  const s = await api('/start', {Consent:true}); show(s);
  if (s.status === 'creating' && s.lease) {
   let c;
   try { c = await browserAuth.create(); }
   catch(e) { await api('/client-failure', {Stage:'creation',Lease:s.lease}).catch(() => {}); throw e; }
   if (!c) {
    await api('/client-failure', {Stage:'creation',Lease:s.lease}).catch(() => {});
    const e = new Error('OpenAI creation unavailable. Check sign-in status; a new code will not be requested automatically.');
    e.code = 'openai_creation_unavailable'; throw e;
   }
   show(await deliver('/created', {Lease:s.lease,ID:c.device_auth_id,Code:c.user_code || c.usercode,Interval:Number(c.interval)||5}));
  }
 } catch(e) { await failure(e); }
 finally {busy = false;}
};
(async () => {
 if (!navigator.locks || typeof AbortSignal === 'undefined' || !AbortSignal.timeout) {
  $('start').disabled = true; $('start').hidden = true;
  text('state-title', 'Use a supported browser');
  text('status', 'A browser with Web Locks and request timeout support is required. Use a current browser. No sign-in has been started here.'); return;
 }
 try { await syncSession(); } catch(e) { await failure(e); }
 setInterval(tick, 2000);
})();
