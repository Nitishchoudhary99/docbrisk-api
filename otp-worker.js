/* ==========================================================================
   DocBrisk API — Cloudflare Worker
   Real OTP delivery, real accounts, real sessions, real Pro enforcement.
   ========================================================================== */

const CONFIG = {
  OTP_TTL: 600,
  TICKET_TTL: 900,
  SESSION_DAYS: 30,
  OTP_MAX_ATTEMPTS: 5,
  OTP_RESEND_SECONDS: 45,
  // Cloudflare Workers (workerd) hard-caps PBKDF2 at 100,000 iterations per
  // crypto.subtle call. Anything higher throws:
  //   NotSupportedError: Pbkdf2 failed: iteration counts above 100000 are not supported
  // which surfaced as a generic "Unexpected server error" on signup. 100,000 is
  // the maximum the platform allows and is what Workers-based apps use.
  // Each user record stores its own `iterations`, so this value can be changed
  // later without invalidating existing passwords.
  PBKDF2_ITERATIONS: 100000,
  PRICE_INR: 99,
  PRO_DAYS: 30,
  // Free uses of Pro tools for every free account, counted per account.
  TRIAL_LIMITS: { 'ocr-pdf': 3, 'mail-merge': 3 }
};

const json = (obj, status, extra) => new Response(JSON.stringify(obj), {
  status: status || 200,
  headers: Object.assign({ 'Content-Type': 'application/json' }, extra || {})
});

function cors(env, request) {
  const allowed = (env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
  const origin = request.headers.get('Origin') || '';
  const allow = allowed.includes('*') ? '*' : (allowed.includes(origin) ? origin : allowed[0] || '');
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,x-admin-key',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

const enc = new TextEncoder();
const hex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

// Hard platform limit in Cloudflare Workers. Exceeding it makes
// crypto.subtle.deriveBits throw NotSupportedError, which is what turned a
// signup into a bare "Unexpected server error". Clamping here means an
// out-of-range value degrades security slightly instead of breaking signup.
const PBKDF2_MAX = 100000;

async function pbkdf2(password, salt, iterations) {
  const rounds = Math.min(Math.max(1, iterations | 0), PBKDF2_MAX);
  const key = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(String(salt)), iterations: rounds, hash: 'SHA-256' }, key, 256);
  return hex(bits);
}
async function sha256(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(String(s)))); }

function safeEqual(a, b) {
  const x = String(a), y = String(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  return diff === 0;
}

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  return atob(pad + '='.repeat((4 - pad.length % 4) % 4));
};

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body));
  return body + '.' + b64url(sig);
}
async function verifyToken(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = b64url(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  if (!safeEqual(sig, expected)) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(body)); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

const normEmail = (e) => String(e || '').trim().toLowerCase();
const isEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(normEmail(e));
function normPhone(p) {
  let s = String(p || '').replace(/[^\d+]/g, '');
  if (!s) return '';
  if (s.startsWith('+')) return s;
  s = s.replace(/^0+/, '');
  if (s.length === 10) return '+91' + s;
  if (s.length > 10 && s.startsWith('91')) return '+' + s;
  return '+' + s;
}
const isPhone = (p) => /^\+\d{10,15}$/.test(normPhone(p));

function passwordOk(pw) {
  const s = String(pw || '');
  if (s.length < 8) return 'Password must be at least 8 characters.';
  if (/^(password|123456|12345678|qwerty|welcome|admin|letmein|abc123)/i.test(s)) return 'Choose a less guessable password.';
  if (/(.)\1{3,}/.test(s)) return 'Too many repeated characters.';
  return null;
}

async function rateLimit(env, bucket, max, windowSec) {
  const key = 'rl:' + bucket;
  const raw = await env.DB.get(key);
  const now = Math.floor(Date.now() / 1000);
  let rec = raw ? JSON.parse(raw) : { start: now, n: 0 };
  if (now - rec.start >= windowSec) rec = { start: now, n: 0 };
  rec.n++;
  await env.DB.put(key, JSON.stringify(rec), { expirationTtl: windowSec });
  if (rec.n > max) return { ok: false, retryAfter: windowSec - (now - rec.start) };
  return { ok: true };
}

async function sendEmailResend(env, to, subject, html) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM || 'DocBrisk <onboarding@resend.dev>', to: [to], subject, html })
  });
  if (!r.ok) throw new Error('email provider: ' + (await r.text()).slice(0, 180));
}

async function sendEmailBrevo(env, to, subject, html) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'accept': 'application/json' },
    body: JSON.stringify({
      sender: { email: env.MAIL_FROM_ADDR || 'no-reply@docbrisk.com', name: env.MAIL_FROM_NAME || 'DocBrisk' },
      to: [{ email: to }], subject, htmlContent: html
    })
  });
  if (!r.ok) throw new Error('email provider: ' + (await r.text()).slice(0, 180));
}

async function sendSmsMsg91(env, to, code) {
  const mobile = to.replace(/^\+/, '');
  const url = new URL('https://control.msg91.com/api/v5/otp');
  url.searchParams.set('template_id', env.MSG91_TEMPLATE_ID);
  url.searchParams.set('mobile', mobile);
  url.searchParams.set('otp', code);
  const r = await fetch(url, { method: 'POST', headers: { 'authkey': env.MSG91_AUTHKEY, 'Content-Type': 'application/json' } });
  const t = await r.text();
  if (!r.ok || /error/i.test(t)) throw new Error('sms provider: ' + t.slice(0, 180));
}

async function sendSmsTwilio(env, to, body) {
  const sid = env.TWILIO_SID, tok = env.TWILIO_TOKEN;
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: 'POST',
    headers: { 'Authorization': 'Basic ' + btoa(`${sid}:${tok}`), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: body })
  });
  if (!r.ok) throw new Error('sms provider: ' + (await r.text()).slice(0, 180));
}

function proActiveEmailHtml(name) {
  return `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:460px;margin:0 auto;padding:28px">
    <h2 style="margin:0 0 6px;color:#0f172a">You're on DocBrisk Pro</h2>
    <p style="color:#475569;font-size:14px">Hi ${name || 'there'} — your payment is confirmed and Pro is now active on your account for 30 days.</p>
    <p style="color:#475569;font-size:14px">That unlocks all 25 CV templates, the Watermark Remover, Batch Processor, Smart Redaction, Extract Images, Clean Scan, Resize Pages, the QR Stamper, the OCR Scanner and Mail Merge.</p>
    <p style="color:#94a3b8;font-size:12px;margin-top:22px">Thanks for supporting DocBrisk.</p></div>`;
}

function otpEmailHtml(code, purpose) {
  const what = purpose === 'reset' ? 'reset your password' : 'verify your account';
  return `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:460px;margin:0 auto;padding:28px">
    <h2 style="margin:0 0 6px;color:#0f172a">Your DocBrisk code</h2>
    <p style="color:#475569;font-size:14px;margin:0 0 22px">Use this code to ${what}. It expires in 10 minutes.</p>
    <div style="font-size:34px;font-weight:800;letter-spacing:10px;text-align:center;padding:18px;
      background:#eef2ff;border:1px solid #c7d2fe;border-radius:14px;color:#312e81">${code}</div>
    <p style="color:#94a3b8;font-size:12px;margin-top:22px">
      If you didn't request this, ignore this email — nothing has changed.</p></div>`;
}

async function deliverOtp(env, channel, destination, code, purpose) {
  if (channel === 'email') {
    const provider = (env.EMAIL_PROVIDER || 'resend').toLowerCase();
    if (provider === 'brevo') return sendEmailBrevo(env, destination, 'Your DocBrisk verification code', otpEmailHtml(code, purpose));
    return sendEmailResend(env, destination, 'Your DocBrisk verification code', otpEmailHtml(code, purpose));
  }
  const provider = (env.SMS_PROVIDER || 'msg91').toLowerCase();
  if (provider === 'twilio') return sendSmsTwilio(env, destination, `${code} is your DocBrisk verification code. It expires in 10 minutes.`);
  return sendSmsMsg91(env, destination, code);
}

const userKey = (email) => 'u:' + normEmail(email);
const getUser = async (env, email) => {
  const raw = await env.DB.get(userKey(email));
  return raw ? JSON.parse(raw) : null;
};
const putUser = (env, u) => env.DB.put(userKey(u.email), JSON.stringify(u));

/* Owner accounts. Set OWNER_EMAILS in the Worker's variables to a
   comma-separated list — those accounts get every Pro feature permanently,
   without paying and without an expiry.

   This lives on the server on purpose. A client-side "admin password" would
   sit in the page source where anyone could read it and unlock Pro for
   themselves; here the list never leaves Cloudflare, and the browser only
   ever learns "this account is pro". */
let OWNER_SET = null;
function isOwner(env, email) {
  if (!OWNER_SET) {
    OWNER_SET = new Set(String(env.OWNER_EMAILS || '')
      .split(',').map(e => e.trim().toLowerCase()).filter(Boolean));
  }
  return OWNER_SET.has(String(email || '').trim().toLowerCase());
}

function publicUser(u, env) {
  const owner = env ? isOwner(env, u.email) : false;
  return {
    email: u.email, name: u.name, phone: u.phone || '',
    emailVerified: !!u.emailVerified, phoneVerified: !!u.phoneVerified,
    plan: (owner || proActive(u)) ? 'pro' : 'free',
    renews: owner ? null : (u.renews || null),
    owner,
    payments: (u.payments || []).map(p => ({ utr: p.utr, amount: p.amount, at: p.at, verified: !!p.verified }))
  };
}
const proActive = (u) => u && u.plan === 'pro' && (!u.renews || Date.now() < u.renews);

async function requireAuth(env, request) {
  const h = request.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const payload = await verifyToken(token, env.SESSION_SECRET);
  if (!payload || !payload.sub) return null;
  const u = await getUser(env, payload.sub);
  if (!u) return null;
  if (payload.pwv && u.pwChangedAt && payload.pwv < u.pwChangedAt) return null;
  return u;
}
const issueSession = (env, u) => signToken(
  { sub: u.email, pwv: u.pwChangedAt || 0, exp: Date.now() + CONFIG.SESSION_DAYS * 864e5 }, env.SESSION_SECRET);

async function otpSend(env, request, body, ip) {
  const { channel, purpose } = body;
  if (!['email', 'sms'].includes(channel)) return json({ error: 'Unknown channel.' }, 400);
  if (!['verify', 'reset', 'signup'].includes(purpose)) return json({ error: 'Unknown purpose.' }, 400);

  const dest = channel === 'email' ? normEmail(body.destination) : normPhone(body.destination);
  if (channel === 'email' && !isEmail(dest)) return json({ error: 'That email address does not look right.' }, 400);
  if (channel === 'sms' && !isPhone(dest)) return json({ error: 'Enter a valid mobile number with country code.' }, 400);

  const ipLimit = await rateLimit(env, 'ip:' + ip, 20, 3600);
  if (!ipLimit.ok) return json({ error: 'Too many requests from this network. Try again later.' }, 429);
  const destLimit = await rateLimit(env, 'dest:' + dest, 5, 900);
  if (!destLimit.ok) return json({ error: 'Too many codes requested for that destination.' }, 429);

  const key = `otp:${purpose}:${dest}`;
  const existing = await env.DB.get(key);
  if (existing) {
    const rec = JSON.parse(existing);
    const since = (Date.now() - rec.issuedAt) / 1000;
    if (since < CONFIG.OTP_RESEND_SECONDS) {
      return json({ error: `Please wait ${Math.ceil(CONFIG.OTP_RESEND_SECONDS - since)}s before requesting another code.` }, 429);
    }
  }

  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const salt = randHex(8);
  await env.DB.put(key, JSON.stringify({
    hash: await pbkdf2(code, salt, 10000), salt, issuedAt: Date.now(), attempts: 0, channel, purpose
  }), { expirationTtl: CONFIG.OTP_TTL });

  try {
    await deliverOtp(env, channel, dest, code, purpose);
  } catch (e) {
    await env.DB.delete(key);
    return json({ error: 'Could not send the code right now. Please try again shortly.', detail: String(e.message).slice(0, 160) }, 502);
  }
  return json({ sent: true, expiresIn: CONFIG.OTP_TTL, destination: masked(channel, dest) });
}

const masked = (channel, dest) => channel === 'email'
  ? dest.replace(/^(.).*(.@.*)$/, (m, a, b) => a + '•••' + b)
  : dest.replace(/^(\+\d{2})\d+(\d{3})$/, '$1•••••$2');

async function otpVerify(env, body, ip) {
  const { channel, purpose } = body;
  const dest = channel === 'email' ? normEmail(body.destination) : normPhone(body.destination);
  const key = `otp:${purpose}:${dest}`;
  const raw = await env.DB.get(key);
  if (!raw) return json({ error: 'No code was requested, or it has expired. Send a new one.' }, 400);

  const rec = JSON.parse(raw);
  if (rec.attempts >= CONFIG.OTP_MAX_ATTEMPTS) {
    await env.DB.delete(key);
    return json({ error: 'Too many incorrect attempts. Request a new code.' }, 429);
  }
  rec.attempts++;
  const ttlLeft = Math.max(30, CONFIG.OTP_TTL - Math.floor((Date.now() - rec.issuedAt) / 1000));
  await env.DB.put(key, JSON.stringify(rec), { expirationTtl: ttlLeft });

  const got = await pbkdf2(String(body.code || '').trim(), rec.salt, 10000);
  if (!safeEqual(got, rec.hash)) {
    const left = CONFIG.OTP_MAX_ATTEMPTS - rec.attempts;
    return json({ error: `Incorrect code. ${left > 0 ? left + ' attempt(s) left.' : 'No attempts left.'}` }, 400);
  }
  await env.DB.delete(key);

  const ticket = randHex(24);
  await env.DB.put('tk:' + ticket, JSON.stringify({ channel, destination: dest, purpose, at: Date.now() }),
    { expirationTtl: CONFIG.TICKET_TTL });
  return json({ verified: true, ticket, expiresIn: CONFIG.TICKET_TTL });
}

async function consumeTicket(env, ticket, expect) {
  if (!ticket) return null;
  const raw = await env.DB.get('tk:' + ticket);
  if (!raw) return null;
  const rec = JSON.parse(raw);
  if (expect) {
    if (expect.purpose && rec.purpose !== expect.purpose) return null;
    if (expect.destination && rec.destination !== expect.destination) return null;
  }
  await env.DB.delete('tk:' + ticket);
  return rec;
}

async function deliverProEmail(env, u) {
  const provider = (env.EMAIL_PROVIDER || 'resend').toLowerCase();
  const html = proActiveEmailHtml(u.name);
  if (provider === 'brevo') return sendEmailBrevo(env, u.email, 'DocBrisk Pro is active', html);
  return sendEmailResend(env, u.email, 'DocBrisk Pro is active', html);
}
function ctxWaitUntil(env, p) { return p.catch(() => {}); }

async function gatewayWebhook(env, request, body, rawBody) {
  const provider = (env.GATEWAY_PROVIDER || '').toLowerCase();
  if (!provider) return json({ error: 'No gateway configured.' }, 404);

  if (provider === 'razorpay') {
    const sig = request.headers.get('x-razorpay-signature') || '';
    const expected = hex(await crypto.subtle.sign('HMAC',
      await hmacKey(env.GATEWAY_SECRET), enc.encode(rawBody)));
    if (!safeEqual(sig, expected)) return json({ error: 'Bad signature.' }, 401);
    const ev = body.event || '';
    if (!/payment\.captured|order\.paid/.test(ev)) return json({ ok: true, ignored: ev });
    const pay = (body.payload && body.payload.payment && body.payload.payment.entity) || {};
    const email = normEmail(pay.email || (pay.notes && pay.notes.email));
    const amount = (pay.amount || 0) / 100;
    return grantFromGateway(env, email, pay.id, amount);
  }

  if (provider === 'cashfree') {
    const sig = request.headers.get('x-webhook-signature') || '';
    const ts = request.headers.get('x-webhook-timestamp') || '';
    const expected = b64url(await crypto.subtle.sign('HMAC',
      await hmacKey(env.GATEWAY_SECRET), enc.encode(ts + rawBody)));
    if (!sig || !safeEqual(sig.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'), expected)) {
      return json({ error: 'Bad signature.' }, 401);
    }
    const d = body.data || {};
    if ((d.payment && d.payment.payment_status) !== 'SUCCESS') return json({ ok: true, ignored: true });
    const email = normEmail(d.customer_details && d.customer_details.customer_email);
    return grantFromGateway(env, email, d.payment && d.payment.cf_payment_id, (d.payment && d.payment.payment_amount) || 0);
  }
  return json({ error: 'Unknown gateway.' }, 400);
}

async function grantFromGateway(env, email, ref, amount) {
  if (!email) return json({ error: 'Webhook carried no customer email.' }, 400);
  const u = await getUser(env, email);
  if (!u) return json({ error: 'No account for that email.' }, 404);
  u.payments = u.payments || [];
  if (u.payments.some(p => p.utr === String(ref))) return json({ ok: true, duplicate: true });
  u.payments.push({ utr: String(ref), amount, at: Date.now(), verified: true, gateway: true });
  u.plan = 'pro';
  u.renews = Math.max(Date.now(), u.renews || 0) + CONFIG.PRO_DAYS * 864e5;
  await putUser(env, u);
  try { await deliverProEmail(env, u); } catch (e) {}
  return json({ ok: true, granted: true });
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  let body = {}, rawBody = '';
  if (request.method === 'POST') {
    try { rawBody = await request.text(); body = rawBody ? JSON.parse(rawBody) : {}; }
    catch (e) { body = {}; }
  }

  if (path === '/api/billing/webhook' && request.method === 'POST') {
    return gatewayWebhook(env, request, body, rawBody);
  }

  if (path === '/api/otp/send' && request.method === 'POST') return otpSend(env, request, body, ip);
  if (path === '/api/otp/verify' && request.method === 'POST') return otpVerify(env, body, ip);

  if (path === '/api/auth/signup' && request.method === 'POST') {
    const email = normEmail(body.email);
    if (!isEmail(email)) return json({ error: 'Please enter a valid email address.' }, 400);
    const pwErr = passwordOk(body.password);
    if (pwErr) return json({ error: pwErr }, 400);
    if (body.phone && !isPhone(body.phone)) return json({ error: 'Please enter a valid mobile number.' }, 400);
    if (await getUser(env, email)) return json({ error: 'An account with that email already exists.' }, 409);

    const rl = await rateLimit(env, 'signup:' + ip, 6, 3600);
    if (!rl.ok) return json({ error: 'Too many sign-ups from this network.' }, 429);

    let emailVerified = false;
    if (env.REQUIRE_EMAIL_VERIFICATION !== 'false') {
      const t = await consumeTicket(env, body.ticket, { destination: email });
      if (!t) return json({ error: 'Verify your email address first.', needsOtp: true }, 403);
      emailVerified = true;
    }

    const salt = randHex(16);
    // Recovery codes are already high-entropy random strings (not a
    // user-chosen password), so a single fast SHA-256 is enough here —
    // running PBKDF2 five extra times on top of the main password hash
    // was the main cause of the CPU-time crash on signup.
    const recoveryPlain = Array.from({ length: 5 }, () => randHex(4).toUpperCase().match(/.{4}/g).join('-'));
    const recovery = [];
    for (const r of recoveryPlain) recovery.push(await sha256(r + ':' + salt));

    const u = {
      email, name: (body.name || '').trim() || email.split('@')[0],
      phone: body.phone ? normPhone(body.phone) : '',
      salt, iterations: CONFIG.PBKDF2_ITERATIONS,
      pw: await pbkdf2(body.password, salt, CONFIG.PBKDF2_ITERATIONS),
      emailVerified, phoneVerified: false,
      recovery, recoveryUsed: [],
      plan: 'free', renews: null, payments: [],
      createdAt: Date.now(), pwChangedAt: Date.now()
    };
    await putUser(env, u);
    if (u.phone) await env.DB.put('p:' + u.phone, email);
    return json({ token: await issueSession(env, u), user: publicUser(u, env), recoveryCodes: recoveryPlain });
  }

  if (path === '/api/auth/login' && request.method === 'POST') {
    const email = normEmail(body.email);
    const rl = await rateLimit(env, 'login:' + email, 10, 900);
    if (!rl.ok) return json({ error: 'Too many attempts. Try again in a few minutes.' }, 429);

    const u = await getUser(env, email);
    const salt = u ? u.salt : 'decoy-salt-value';
    const got = await pbkdf2(body.password, salt, (u && u.iterations) || CONFIG.PBKDF2_ITERATIONS);
    if (!u || !safeEqual(got, u.pw)) return json({ error: 'Incorrect email or password.' }, 401);
    return json({ token: await issueSession(env, u), user: publicUser(u, env) });
  }

  if (path === '/api/auth/me') {
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    return json({ user: publicUser(u, env) });
  }

  if (path === '/api/auth/password' && request.method === 'POST') {
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    const got = await pbkdf2(body.currentPassword, u.salt, u.iterations || CONFIG.PBKDF2_ITERATIONS);
    if (!safeEqual(got, u.pw)) return json({ error: 'Your current password is not correct.' }, 400);
    const pwErr = passwordOk(body.newPassword);
    if (pwErr) return json({ error: pwErr }, 400);
    u.salt = randHex(16);
    u.pw = await pbkdf2(body.newPassword, u.salt, CONFIG.PBKDF2_ITERATIONS);
    u.iterations = CONFIG.PBKDF2_ITERATIONS;
    u.pwChangedAt = Date.now();
    await putUser(env, u);
    return json({ ok: true, token: await issueSession(env, u) });
  }

  if (path === '/api/auth/reset/start' && request.method === 'POST') {
    const channel = body.channel === 'sms' ? 'sms' : 'email';
    let email = null;
    const asEmail = normEmail(body.identifier);
    if (isEmail(asEmail) && await getUser(env, asEmail)) email = asEmail;
    if (!email && isPhone(body.identifier)) email = await env.DB.get('p:' + normPhone(body.identifier));

    const generic = { sent: true, anonymous: true,
      message: 'If an account exists for that, a code has been sent.' };
    if (!email) return json(generic);
    const u = await getUser(env, email);
    const dest = channel === 'sms' ? u.phone : email;
    if (!dest) return json(generic);
    const r = await otpSend(env, request, { channel, destination: dest, purpose: 'reset' }, ip);
    if (r.status === 429 || r.status === 502) return json(generic);
    return json({ sent: true, email, channel, destination: masked(channel, dest) });
  }

  if (path === '/api/auth/reset/complete' && request.method === 'POST') {
    const email = normEmail(body.email);
    const u = await getUser(env, email);
    const t = await consumeTicket(env, body.ticket, { purpose: 'reset' });
    if (!u || !t) return json({ error: 'That reset link has expired. Start again.' }, 400);
    if (t.destination !== email && t.destination !== u.phone) return json({ error: 'Verification does not match this account.' }, 400);
    const pwErr = passwordOk(body.newPassword);
    if (pwErr) return json({ error: pwErr }, 400);
    u.salt = randHex(16);
    u.pw = await pbkdf2(body.newPassword, u.salt, CONFIG.PBKDF2_ITERATIONS);
    u.iterations = CONFIG.PBKDF2_ITERATIONS;
    u.pwChangedAt = Date.now();
    await putUser(env, u);
    return json({ ok: true });
  }

  if (path === '/api/auth/phone' && request.method === 'POST') {
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    const phone = normPhone(body.phone);
    if (!isPhone(phone)) return json({ error: 'Enter a valid mobile number.' }, 400);
    const t = await consumeTicket(env, body.ticket, { destination: phone });
    if (!t) return json({ error: 'Verify the number first.', needsOtp: true }, 403);
    if (u.phone && u.phone !== phone) await env.DB.delete('p:' + u.phone);
    u.phone = phone; u.phoneVerified = true;
    await putUser(env, u);
    await env.DB.put('p:' + phone, u.email);
    return json({ ok: true, user: publicUser(u, env) });
  }

  if (path === '/api/billing/claim' && request.method === 'POST') {
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    const utr = String(body.utr || '').trim();
    if (utr.length < 6) return json({ error: 'Enter the transaction reference from your UPI app.' }, 400);
    const rl = await rateLimit(env, 'claim:' + u.email, 5, 3600);
    if (!rl.ok) return json({ error: 'Too many claims. Contact support.' }, 429);

    u.payments = u.payments || [];
    if (u.payments.some(p => p.utr === utr)) return json({ error: 'That transaction reference has already been submitted.' }, 409);
    u.payments.push({ utr, amount: CONFIG.PRICE_INR, vpa: env.UPI_VPA || '', at: Date.now(), verified: false });

    if (env.AUTO_APPROVE_PAYMENTS === 'true') {
      u.plan = 'pro';
      u.renews = Date.now() + CONFIG.PRO_DAYS * 864e5;
      u.payments[u.payments.length - 1].verified = true;
      u.payments[u.payments.length - 1].autoApproved = true;
    }
    await putUser(env, u);
    await env.DB.put('claim:' + Date.now() + ':' + u.email, JSON.stringify({ email: u.email, utr, at: Date.now() }),
      { expirationTtl: 60 * 86400 });
    return json({
      ok: true, pending: env.AUTO_APPROVE_PAYMENTS !== 'true',
      user: publicUser(u, env),
      message: env.AUTO_APPROVE_PAYMENTS === 'true'
        ? 'Pro is active.'
        : 'Payment recorded. Pro activates once we confirm the transfer, usually within a few hours.'
    });
  }

  if (path === '/api/billing/status') {
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    return json({ pro: isOwner(env, u.email) || proActive(u), user: publicUser(u, env) });
  }

  /* Free uses of Pro tools (OCR Scanner, Mail Merge).
     Every free account can use each tool in CONFIG.TRIAL_LIMITS a few times.
     The count is stored on the account, so clearing the browser or changing
     phones does not reset it. Paid Pro and owner accounts are never counted.
       POST /api/trial/status { feature } -> { remaining, limit }
       POST /api/trial/use    { feature } -> { remaining, limit }, or 402 when used up */
  if (path === '/api/trial/status' || path === '/api/trial/use') {
    if (request.method !== 'POST') return json({ error: 'Use POST.' }, 405);
    const u = await requireAuth(env, request);
    if (!u) return json({ error: 'Not signed in.' }, 401);
    const feature = String(body.feature || '');
    const limit = CONFIG.TRIAL_LIMITS[feature];
    if (!limit) return json({ error: 'Unknown feature.' }, 400);
    if (isOwner(env, u.email) || proActive(u)) return json({ pro: true, remaining: null, limit });
    u.trials = u.trials || {};
    const used = u.trials[feature] || 0;
    if (path === '/api/trial/status') return json({ remaining: Math.max(0, limit - used), limit });
    if (used >= limit) return json({ error: 'Your free uses of this tool are finished.', remaining: 0, limit }, 402);
    u.trials[feature] = used + 1;
    await putUser(env, u);
    return json({ remaining: limit - used - 1, limit });
  }

  if (path.startsWith('/api/admin/')) {
    const key = request.headers.get('x-admin-key') || '';
    if (!env.ADMIN_KEY || !safeEqual(key, env.ADMIN_KEY)) return json({ error: 'Forbidden.' }, 403);

    if (path === '/api/admin/payments') {
      const list = await env.DB.list({ prefix: 'claim:' });
      const out = [];
      for (const k of list.keys) {
        const raw = await env.DB.get(k.name);
        if (!raw) continue;
        const c = JSON.parse(raw);
        const u = await getUser(env, c.email);
        const p = u && (u.payments || []).find(x => x.utr === c.utr);
        out.push({ email: c.email, utr: c.utr, at: c.at, verified: !!(p && p.verified), plan: u ? u.plan : 'missing' });
      }
      return json({ claims: out.sort((a, b) => b.at - a.at) });
    }

    if (path === '/api/admin/user' && request.method === 'POST') {
      const u = await getUser(env, body.email);
      if (!u) return json({ error: 'No such user.' }, 404);
      return json({ user: publicUser(u, env) });
    }

    if (path === '/api/admin/verify-payment' && request.method === 'POST') {
      const u = await getUser(env, body.email);
      if (!u) return json({ error: 'No such user.' }, 404);
      const p = (u.payments || []).find(x => x.utr === String(body.utr || '').trim());
      if (!p) return json({ error: 'No such payment claim.' }, 404);
      if (body.approve === false) {
        p.verified = false; p.rejected = true;
        u.plan = 'free'; u.renews = null;
      } else {
        p.verified = true; p.rejected = false;
        u.plan = 'pro';
        u.renews = Math.max(Date.now(), u.renews || 0) + CONFIG.PRO_DAYS * 864e5;
      }
      await putUser(env, u);
      if (body.approve !== false) {
        try { ctxWaitUntil(env, deliverProEmail(env, u)); } catch (e) {}
      }
      return json({ ok: true, user: publicUser(u, env) });
    }
  }

  if (path === '/api/health') {
    return json({
      ok: true,
      emailProvider: env.EMAIL_PROVIDER || 'resend',
      smsProvider: env.SMS_PROVIDER || 'msg91',
      emailConfigured: !!(env.RESEND_API_KEY || env.BREVO_API_KEY),
      smsConfigured: !!(env.MSG91_AUTHKEY || env.TWILIO_SID),
      autoApprovePayments: env.AUTO_APPROVE_PAYMENTS === 'true',
      requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION !== 'false'
    });
  }

  return json({ error: 'Not found.' }, 404);
}

export default {
  async fetch(request, env, ctx) {
    const headers = cors(env, request);
    if (request.method === 'OPTIONS') return new Response(null, { headers });
    if (!env.DB) return json({ error: 'Server misconfigured: KV namespace "DB" is not bound.' }, 500, headers);
    if (!env.SESSION_SECRET) return json({ error: 'Server misconfigured: SESSION_SECRET is not set.' }, 500, headers);
    try {
      const res = await handle(request, env, ctx);
      const out = new Response(res.body, res);
      Object.entries(headers).forEach(([k, v]) => out.headers.set(k, v));
      return out;
    } catch (e) {
      return json({ error: 'Unexpected server error.', detail: String(e && e.message).slice(0, 200) }, 500, headers);
    }
  }
};
