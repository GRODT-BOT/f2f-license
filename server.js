'use strict';

// ---------------------------------------------------------------------------
// Flat to Funded - licence server
//
// Zero dependencies: Node built-ins only. Licences live in a JSON file on a
// persistent volume, which is plenty for this scale and means no database
// service to pay for or keep alive.
//
// The strategy calls POST /api/verify. Every answer is signed with an RSA
// private key that exists only here; the strategy carries the matching PUBLIC
// key, so a customer cannot fake an "allowed" reply by pointing the hostname
// at a server of their own.
//
// Env:
//   ADMIN_TOKEN      required - password for the admin page and API
//   RSA_PRIVATE_KEY  required - PKCS#8 PEM, newlines may be written as \n
//   DATA_DIR         where licences.json lives (default /data)
//   MAX_MACHINES     computers allowed per licence (default 1)
//   PORT             set by Railway
//
// Second product - "MNQ Hourly" (FlatToFundedHourly strategy). Completely
// separate: its own licence file, its own FTH- keys, its own signing key and its
// own verify endpoint, so a Flat to Funded key never unlocks the Hourly bot and
// vice versa. Same admin page (switch product with the tabs at the top).
//   RSA_PRIVATE_KEY_HOURLY  required for the Hourly product - PKCS#8 PEM
//   MAX_MACHINES_HOURLY     computers per Hourly licence (default MAX_MACHINES)
//   PRODUCT_HOURLY          product name in signed answers (default FlatToFundedHourly)
// ---------------------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const PRIVATE_KEY = (process.env.RSA_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const PRODUCT = process.env.PRODUCT || 'FlatToFunded';
const MAX_MACHINES = parseInt(process.env.MAX_MACHINES || '1', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';
const DB_FILE = path.join(DATA_DIR, 'licences.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const RESELLERS_FILE = path.join(DATA_DIR, 'resellers.json');
// Secret for signing partner session tokens. Derived from ADMIN_TOKEN so there
// is no extra env var to manage, and sessions rotate if you change the token.
const SESSION_SECRET = crypto.createHash('sha256').update('f2f.session|' + ADMIN_TOKEN).digest();

const PRODUCTS = {
  ftf: {
    id: 'ftf', name: PRODUCT, label: 'Flat to Funded', prefix: 'FTF',
    file: DB_FILE, privateKey: PRIVATE_KEY, maxMachines: MAX_MACHINES
  },
  hourly: {
    id: 'hourly', name: process.env.PRODUCT_HOURLY || 'FlatToFundedHourly', label: 'MNQ Hourly', prefix: 'FTH',
    file: path.join(DATA_DIR, 'licences-hourly.json'),
    privateKey: (process.env.RSA_PRIVATE_KEY_HOURLY || '').replace(/\\n/g, '\n'),
    maxMachines: parseInt(process.env.MAX_MACHINES_HOURLY || process.env.MAX_MACHINES || '1', 10)
  }
};

if (!ADMIN_TOKEN) console.warn('WARNING: ADMIN_TOKEN not set - admin API is locked out.');
for (const p of Object.values(PRODUCTS))
  if (!p.privateKey) console.warn('WARNING: no signing key for ' + p.label + ' - its answers cannot be signed.');

// ---------------------------------------------------------------------------
// storage - one JSON file per product
// ---------------------------------------------------------------------------
for (const p of Object.values(PRODUCTS)) {
  p.db = { nextId: 1, licences: [], checks: [] };
  p.writing = Promise.resolve();
}

function loadDb(p) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(p.file)) {
      p.db = JSON.parse(fs.readFileSync(p.file, 'utf8'));
      p.db.checks = p.db.checks || [];
      console.log('loaded ' + p.db.licences.length + ' ' + p.label + ' licences from ' + p.file);
    } else {
      console.log('no ' + p.label + ' licence file yet, starting empty at ' + p.file);
    }
  } catch (err) {
    // Never start with a blank slate over a file we failed to parse - that
    // would silently wipe every customer on the next save.
    console.error('FATAL: could not read ' + p.file, err);
    process.exit(1);
  }
}

// Serialised, atomic: write a temp file then rename, so a crash mid-write
// cannot leave a truncated licence file behind.
function saveDb(p) {
  p.writing = p.writing.then(async () => {
    const tmp = p.file + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(p.db, null, 2));
    await fsp.rename(tmp, p.file);
  }).catch(err => console.error('save failed (' + p.label + ')', err));
  return p.writing;
}

// ---------------------------------------------------------------------------
// partner (reseller) accounts - their own JSON file on the same volume
// ---------------------------------------------------------------------------
const AUX = { file: RESELLERS_FILE, db: { resellers: [] }, writing: Promise.resolve() };

function loadAux() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(AUX.file)) {
      AUX.db = JSON.parse(fs.readFileSync(AUX.file, 'utf8'));
      AUX.db.resellers = AUX.db.resellers || [];
      console.log('loaded ' + AUX.db.resellers.length + ' partner account(s) from ' + AUX.file);
    } else {
      console.log('no partner accounts file yet, starting empty at ' + AUX.file);
    }
  } catch (err) {
    console.error('FATAL: could not read ' + AUX.file, err);
    process.exit(1);
  }
}
function saveAux() {
  AUX.writing = AUX.writing.then(async () => {
    const tmp = AUX.file + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(AUX.db, null, 2));
    await fsp.rename(tmp, AUX.file);
  }).catch(err => console.error('save failed (partners)', err));
  return AUX.writing;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1

function newKey(prefix) {
  const g = [];
  for (let i = 0; i < 4; i++) {
    let s = '';
    for (let j = 0; j < 5; j++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
    g.push(s);
  }
  return (prefix || 'FTF') + '-' + g.join('-');
}

// The exact string that gets signed. The C# side rebuilds this from the JSON
// fields and verifies against it, so this order must never drift from the
// strategy's BuildPayload().
function payloadString(p, o) {
  return [p.name, o.key, o.machine, o.allowed ? '1' : '0',
          o.expires || '', o.issued, o.nonce].join('|');
}

function sign(p, s) {
  if (!p.privateKey) return '';
  try {
    return crypto.sign('sha256', Buffer.from(s, 'utf8'), p.privateKey).toString('base64');
  } catch (err) { console.error('signing failed', err); return ''; }
}

function isAdmin(req) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!ADMIN_TOKEN || !tok) return false;
  const a = Buffer.from(tok), b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8',
                        'cache-control': 'no-store' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => {
      n += c.length;
      if (n > 65536) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
  });
}

function logCheck(p, entry) {
  p.db.checks.unshift(entry);
  if (p.db.checks.length > 500) p.db.checks.length = 500;
}

// ---------------------------------------------------------------------------
// partner auth: scrypt password hashing + stateless signed session tokens
// ---------------------------------------------------------------------------
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return { salt, hash };
}
function checkPw(pw, salt, hash) {
  if (!salt || !hash) return false;
  const a = crypto.scryptSync(String(pw), salt, 64);
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function makeSession(username, hours) {
  const exp = Date.now() + (hours || 12) * 3600000;
  const body = Buffer.from(username + '|' + exp).toString('base64url');
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function readSession(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const i = tok.indexOf('.');
  const body = tok.slice(0, i), mac = tok.slice(i + 1);
  const good = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(mac), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const raw = Buffer.from(body, 'base64url').toString('utf8');
  const j = raw.lastIndexOf('|');
  const username = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
  if (!exp || Date.now() > exp) return null;
  return { username };
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}
function resellerFromReq(req) {
  const se = readSession(bearer(req));
  if (!se) return null;
  return AUX.db.resellers.find(r => r.username === se.username && r.active) || null;
}

// every licence created by one partner, across every product
function partnerLicences(username) {
  const out = [];
  for (const p of Object.values(PRODUCTS))
    for (const l of p.db.licences)
      if (l.createdBy === username) out.push({ p, l });
  return out;
}
function countsFor(username) {
  const now = Date.now(), day = 86400000;
  let today = 0, week = 0, month = 0;
  for (const { l } of partnerLicences(username)) {
    const age = now - new Date(l.createdAt).getTime();
    if (age < day) today++;
    if (age < 7 * day) week++;
    if (age < 30 * day) month++;
  }
  return { today, week, month };
}

// WhatsApp notifications - best effort, never blocks a response
function notify(text) {
  try {
    const tgTok = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
    const tgChat = (process.env.TELEGRAM_CHAT_ID || '').trim();
    if (tgTok && tgChat) {
      const u = 'https://api.telegram.org/bot' + tgTok + '/sendMessage?chat_id=' +
                encodeURIComponent(tgChat) + '&text=' + encodeURIComponent(text);
      const rq = require('https').get(u, { timeout: 8000 }, r => r.resume());
      rq.on('timeout', () => rq.destroy());
      rq.on('error', e => console.error('notify(telegram):', e.message));
      return;
    }
    const phone = (process.env.CALLMEBOT_PHONE || '').trim();
    const key = (process.env.CALLMEBOT_APIKEY || '').trim();
    if (phone && key) {
      const u = 'https://api.callmebot.com/whatsapp.php?phone=' + encodeURIComponent(phone) +
                '&apikey=' + encodeURIComponent(key) + '&text=' + encodeURIComponent(text);
      const rq = require('https').get(u, { timeout: 8000 }, r => r.resume());
      rq.on('timeout', () => rq.destroy());
      rq.on('error', e => console.error('notify(callmebot):', e.message));
      return;
    }
    const sid = (process.env.TWILIO_SID || '').trim();
    const auth = (process.env.TWILIO_AUTH || '').trim();
    const from = (process.env.TWILIO_WHATSAPP_FROM || '').trim();
    const to = (process.env.NOTIFY_WHATSAPP_TO || '').trim();
    if (sid && auth && from && to) {
      const form = 'From=' + encodeURIComponent('whatsapp:' + from) +
                   '&To=' + encodeURIComponent('whatsapp:' + to) +
                   '&Body=' + encodeURIComponent(text);
      const rq = require('https').request({
        method: 'POST', host: 'api.twilio.com',
        path: '/2010-04-01/Accounts/' + sid + '/Messages.json',
        auth: sid + ':' + auth, timeout: 8000,
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(form) }
      }, r => r.resume());
      rq.on('timeout', () => rq.destroy());
      rq.on('error', e => console.error('notify(twilio):', e.message));
      rq.end(form);
    }
  } catch (e) { console.error('notify failed:', e.message); }
}

// ---------------------------------------------------------------------------
// the endpoint the strategy calls
// ---------------------------------------------------------------------------
async function verify(req, res, p) {
  let body;
  try { body = await readBody(req); }
  catch (e) { return json(res, 400, { error: 'bad request' }); }

  const key = String(body.key || '').trim().toUpperCase();
  const machine = String(body.machine || '').trim().slice(0, 128);
  const version = String(body.version || '').slice(0, 32);
  const issued = new Date().toISOString();
  const nonce = crypto.randomBytes(12).toString('hex');

  const answer = (allowed, reason, expires) => {
    const out = { product: p.name, key, machine, allowed, expires: expires || '',
                  issued, nonce, reason };
    out.signature = sign(p, payloadString(p, out));
    logCheck(p, { at: issued, key, machine, version, allowed, reason });
    saveDb(p);
    return json(res, 200, out);
  };

  if (!key) return answer(false, 'No licence key entered.');
  if (!machine) return answer(false, 'No machine id supplied.');

  const lic = p.db.licences.find(l => l.key === key);
  if (!lic) return answer(false, 'Licence key not recognised.');
  if (!lic.active) return answer(false, 'This licence has been deactivated. Contact support.');
  if (lic.expiresAt && new Date(lic.expiresAt) < new Date())
    return answer(false, 'This licence expired on ' + lic.expiresAt.slice(0, 10) + '.');

  lic.machines = lic.machines || [];
  const known = lic.machines.find(m => m.id === machine);
  if (known) {
    known.lastSeen = issued;
  } else if (lic.machines.length >= p.maxMachines) {
    return answer(false, 'This licence is already active on another computer. Contact support to move it.');
  } else {
    lic.machines.push({ id: machine, firstSeen: issued, lastSeen: issued });
  }
  lic.lastCheck = issued;
  return answer(true, 'ok', lic.expiresAt || '');
}

// ---------------------------------------------------------------------------
// admin API
// ---------------------------------------------------------------------------
async function admin(req, res, url) {
  if (!isAdmin(req)) return json(res, 401, { error: 'unauthorized' });
  // /api/admin/licences[/id/action]          -> Flat to Funded (unchanged)
  // /api/admin/hourly/licences[/id/action]   -> MNQ Hourly
  let parts = url.pathname.split('/').filter(Boolean);
  if (parts[2] === 'resellers') return adminResellers(req, res, parts);
  if (parts[2] === 'partner-activity' && req.method === 'GET') return adminPartnerActivity(req, res);
  let p = PRODUCTS.ftf;
  if (parts[2] === 'hourly') { p = PRODUCTS.hourly; parts = parts.slice(0, 2).concat(parts.slice(3)); }
  const db = p.db;

  if (parts[2] === 'checks' && req.method === 'GET')
    return json(res, 200, { checks: db.checks.slice(0, 200) });

  if (parts[2] !== 'licences') return json(res, 404, { error: 'not found' });

  if (req.method === 'GET' && parts.length === 3)
    return json(res, 200, { product: p.id, label: p.label, licences: db.licences, maxMachines: p.maxMachines });

  if (req.method === 'POST' && parts.length === 3) {
    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { error: 'bad request' }); }
    const email = String(body.email || '').trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
      return json(res, 400, { error: 'A valid email is required.' });
    const days = body.days === null || body.days === '' ? null : parseInt(body.days, 10);
    const lic = {
      id: db.nextId++,
      key: newKey(p.prefix),
      email,
      note: String(body.note || '').trim().slice(0, 200),
      active: true,
      expiresAt: Number.isFinite(days) && days > 0
        ? new Date(Date.now() + days * 86400000).toISOString() : null,
      createdAt: new Date().toISOString(),
      createdBy: 'admin',
      createdByRole: 'admin',
      paid: true,
      machines: [],
      lastCheck: null
    };
    db.licences.unshift(lic);
    await saveDb(p);
    return json(res, 200, { licence: lic });
  }

  if (req.method === 'POST' && parts.length === 5) {
    const id = parseInt(parts[3], 10);
    const action = parts[4];
    const lic = db.licences.find(l => l.id === id);
    if (!lic) return json(res, 404, { error: 'no such licence' });

    if (action === 'revoke') lic.active = false;
    else if (action === 'activate') lic.active = true;
    else if (action === 'reset-machine') lic.machines = [];
    else if (action === 'perpetual') lic.expiresAt = null;
    else if (action === 'delete') db.licences = p.db.licences = db.licences.filter(l => l.id !== id);
    else if (action === 'set-paid') {
      let body;
      try { body = await readBody(req); }
      catch (e) { return json(res, 400, { error: 'bad request' }); }
      lic.paid = !!body.paid;
    }
    else if (action === 'extend') {
      let body;
      try { body = await readBody(req); }
      catch (e) { return json(res, 400, { error: 'bad request' }); }
      const days = parseInt(body.days, 10);
      if (!Number.isFinite(days)) return json(res, 400, { error: 'days required' });
      // extend from today when the licence has already lapsed, otherwise from
      // its current end date - so "+30d" never silently shortens anything
      const from = lic.expiresAt && new Date(lic.expiresAt) > new Date()
        ? new Date(lic.expiresAt) : new Date();
      lic.expiresAt = new Date(from.getTime() + days * 86400000).toISOString();
    } else return json(res, 400, { error: 'unknown action' });

    await saveDb(p);
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: 'not found' });
}


// ---------------------------------------------------------------------------
// admin: manage partner accounts + see every partner-issued key
// ---------------------------------------------------------------------------
async function adminResellers(req, res, parts) {
  if (req.method === 'GET' && parts.length === 3) {
    const list = AUX.db.resellers.map(r => {
      const c = countsFor(r.username);
      return { id: r.id, username: r.username, products: r.products, active: r.active,
               createdAt: r.createdAt, today: c.today, week: c.week, month: c.month };
    });
    return json(res, 200, { resellers: list });
  }
  if (req.method === 'POST' && parts.length === 3) {
    let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    let products = Array.isArray(body.products) ? body.products.filter(x => PRODUCTS[x]) : [];
    if (!products.length) products = Object.keys(PRODUCTS);
    if (!/^[a-z0-9_.-]{3,32}$/.test(username))
      return json(res, 400, { error: 'Username must be 3-32 chars: letters, numbers, . _ -' });
    if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
    if (AUX.db.resellers.some(r => r.username === username))
      return json(res, 400, { error: 'That username already exists.' });
    const { salt, hash } = hashPw(password);
    const id = AUX.db.resellers.length ? Math.max.apply(null, AUX.db.resellers.map(x => x.id)) + 1 : 1;
    AUX.db.resellers.push({ id, username, salt, hash, products, active: true, createdAt: new Date().toISOString() });
    await saveAux();
    return json(res, 200, { reseller: { id, username, products } });
  }
  if (req.method === 'POST' && parts.length === 5) {
    const id = parseInt(parts[3], 10);
    const action = parts[4];
    const r = AUX.db.resellers.find(x => x.id === id);
    if (!r) return json(res, 404, { error: 'no such partner' });
    if (action === 'deactivate') r.active = false;
    else if (action === 'activate') r.active = true;
    else if (action === 'delete') AUX.db.resellers = AUX.db.resellers.filter(x => x.id !== id);
    else if (action === 'set-password') {
      let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
      const password = String(body.password || '');
      if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
      const h = hashPw(password); r.salt = h.salt; r.hash = h.hash;
    }
    else if (action === 'set-products') {
      let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
      const products = Array.isArray(body.products) ? body.products.filter(x => PRODUCTS[x]) : [];
      if (!products.length) return json(res, 400, { error: 'Pick at least one product.' });
      r.products = products;
    }
    else return json(res, 400, { error: 'unknown action' });
    await saveAux();
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'not found' });
}

function adminPartnerActivity(req, res) {
  const rows = [];
  let unpaid = 0;
  for (const p of Object.values(PRODUCTS)) {
    for (const l of p.db.licences) {
      if (l.createdByRole !== 'reseller') continue;
      if (!l.paid) unpaid++;
      rows.push({
        product: p.id, productLabel: p.label, id: l.id, key: l.key,
        createdBy: l.createdBy || '', createdAt: l.createdAt,
        email: l.email || '', note: l.note || '',
        active: l.active, paid: !!l.paid,
        expiresAt: l.expiresAt || null,
        activated: (l.machines || []).length > 0
      });
    }
  }
  rows.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return json(res, 200, { licences: rows, unpaid });
}

// ---------------------------------------------------------------------------
// partner (reseller) API - scoped to the signed-in partner's own licences
// ---------------------------------------------------------------------------
async function reseller(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api','reseller',...]

  if (parts[2] === 'login' && req.method === 'POST') {
    let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const r = AUX.db.resellers.find(x => x.username === username);
    if (!r || !r.active || !checkPw(password, r.salt, r.hash))
      return json(res, 401, { error: 'Wrong username or password.' });
    return json(res, 200, { token: makeSession(r.username, 12), username: r.username, products: r.products });
  }

  const r = resellerFromReq(req);
  if (!r) return json(res, 401, { error: 'unauthorized' });

  if (parts[2] === 'me' && req.method === 'GET') {
    const products = r.products.map(id => ({ id, label: PRODUCTS[id].label }));
    return json(res, 200, { username: r.username, products, counts: countsFor(r.username) });
  }

  if (parts[2] === 'licences' && req.method === 'GET' && parts.length === 3) {
    const mine = partnerLicences(r.username).map(({ p, l }) => ({
      product: p.id, productLabel: p.label, id: l.id, key: l.key,
      note: l.note || '', email: l.email || '', active: l.active,
      expiresAt: l.expiresAt || null, createdAt: l.createdAt,
      machines: l.machines || [], lastCheck: l.lastCheck || null, paid: !!l.paid
    }));
    mine.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return json(res, 200, { licences: mine, counts: countsFor(r.username) });
  }

  if (parts[2] === 'licences' && req.method === 'POST' && parts.length === 3) {
    let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
    const prodId = PRODUCTS[body.product] && r.products.includes(body.product) ? body.product : r.products[0];
    const p = PRODUCTS[prodId];
    if (!p) return json(res, 400, { error: 'No product available on your account.' });
    const days = body.days === null || body.days === '' ? null : parseInt(body.days, 10);
    const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
    const lic = {
      id: p.db.nextId++,
      key: newKey(p.prefix),
      email,
      note: String(body.note || '').trim().slice(0, 200),
      active: true,
      expiresAt: Number.isFinite(days) && days > 0
        ? new Date(Date.now() + days * 86400000).toISOString() : null,
      createdAt: new Date().toISOString(),
      createdBy: r.username,
      createdByRole: 'reseller',
      paid: false,
      machines: [],
      lastCheck: null
    };
    p.db.licences.unshift(lic);
    await saveDb(p);
    const dtxt = lic.expiresAt ? days + ' days' : 'no expiry';
    const c = countsFor(r.username);
    notify('[Partner] ' + r.username + ' ISSUED a ' + p.label + ' key (' + dtxt + '): ' +
           lic.key + (lic.note ? ' - ' + lic.note : '') +
           '\n' + r.username + ' today: ' + c.today + ' | this month: ' + c.month);
    return json(res, 200, { licence: lic });
  }

  if (parts[2] === 'licences' && req.method === 'POST' && parts.length === 5) {
    const id = parseInt(parts[3], 10);
    const action = parts[4];
    let found = null, prod = null;
    for (const p of Object.values(PRODUCTS)) {
      const l = p.db.licences.find(x => x.id === id && x.createdBy === r.username);
      if (l) { found = l; prod = p; break; }
    }
    if (!found) return json(res, 404, { error: 'no such licence' });
    if (action === 'revoke') found.active = false;
    else if (action === 'activate') found.active = true;
    else if (action === 'reset-machine') found.machines = [];
    else if (action === 'extend') {
      let body; try { body = await readBody(req); } catch (e) { return json(res, 400, { error: 'bad request' }); }
      const days = parseInt(body.days, 10);
      if (!Number.isFinite(days)) return json(res, 400, { error: 'days required' });
      const from = found.expiresAt && new Date(found.expiresAt) > new Date()
        ? new Date(found.expiresAt) : new Date();
      found.expiresAt = new Date(from.getTime() + days * 86400000).toISOString();
    } else return json(res, 400, { error: 'unknown action' });
    await saveDb(prod);
    if (action === 'revoke')
      notify('[Partner] ' + r.username + ' DEACTIVATED ' + prod.label + ' key: ' + found.key);
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: 'not found' });
}

const ADMIN_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flat to Funded — Licences</title>
<style>
  :root{
    --bg:#0b0f14; --panel:#111820; --panel2:#151d27; --line:#1e2a36;
    --ink:#dbe6ef; --dim:#7d8fa1; --accent:#56fcfd; --accent2:#6fc5cd;
    --ok:#3de8a8; --bad:#ff5c72; --warn:#ffc861;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  header{display:flex;align-items:center;gap:14px;padding:18px 24px;
         border-bottom:1px solid var(--line);background:var(--panel)}
  .mark{width:34px;height:34px;border-radius:9px;flex:none;
        background:linear-gradient(135deg,var(--accent),var(--accent2));
        color:#06202a;font-weight:800;font-size:19px;display:grid;place-items:center}
  h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase}
  h1 small{display:block;font-size:11px;letter-spacing:.06em;color:var(--dim);
           text-transform:none;font-weight:400;margin-top:2px}
  main{max-width:1180px;margin:0 auto;padding:24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:18px;margin-bottom:20px}
  .card h2{font-size:11px;letter-spacing:.16em;text-transform:uppercase;
           color:var(--dim);margin:0 0 14px}
  label{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
        color:var(--dim);margin-bottom:5px}
  input,select{background:var(--panel2);border:1px solid var(--line);color:var(--ink);
        border-radius:7px;padding:9px 11px;font:inherit;width:100%}
  input:focus,select:focus{outline:none;border-color:var(--accent2)}
  button{background:var(--accent);color:#06202a;border:0;border-radius:7px;
         padding:9px 16px;font:inherit;font-weight:650;cursor:pointer;white-space:nowrap}
  button:hover{filter:brightness(1.08)}
  button.ghost{background:transparent;color:var(--dim);border:1px solid var(--line);font-weight:500}
  button.ghost:hover{color:var(--ink);border-color:var(--accent2)}
  button.danger{background:transparent;color:var(--bad);border:1px solid #3a2029;font-weight:500}
  .row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
  .row>div{flex:1;min-width:150px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;
     color:var(--dim);font-weight:600;padding:0 10px 9px;border-bottom:1px solid var(--line)}
  td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:0}
  .key{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
       color:var(--accent);letter-spacing:.02em;cursor:pointer}
  .key:hover{text-decoration:underline}
  .pill{display:inline-block;font-size:10.5px;letter-spacing:.06em;padding:2px 8px;
        border-radius:20px;text-transform:uppercase;font-weight:650}
  .pill.on{background:rgba(61,232,168,.13);color:var(--ok)}
  .pill.off{background:rgba(255,92,114,.13);color:var(--bad)}
  .pill.exp{background:rgba(255,200,97,.13);color:var(--warn)}
  .dim{color:var(--dim)}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dim)}
  .acts{display:flex;gap:6px;flex-wrap:wrap}
  .acts button{padding:5px 10px;font-size:12px}
  .gate{max-width:400px;margin:14vh auto;text-align:center}
  .gate .card{text-align:left}
  .toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);
         background:var(--accent);color:#06202a;padding:10px 20px;border-radius:8px;
         font-weight:650;box-shadow:0 8px 30px rgba(0,0,0,.5)}
  .empty{color:var(--dim);text-align:center;padding:34px}
  .tabs{display:flex;gap:6px;margin-left:18px}
  .tabs button{background:transparent;color:var(--dim);border:1px solid var(--line);font-weight:600}
  .tabs button.on{background:var(--accent);color:#06202a;border-color:var(--accent)}
  @media(max-width:760px){ .hide-sm{display:none} main{padding:14px} header{flex-wrap:wrap} .tabs{margin-left:0} }
</style>
</head>
<body>

<div id="gate" class="gate" hidden>
  <div class="card">
    <h2>Admin sign in</h2>
    <label for="tok">Admin token</label>
    <input id="tok" type="password" placeholder="paste your ADMIN_TOKEN" autocomplete="off">
    <p class="dim" style="font-size:12px">This is the <span class="mono">ADMIN_TOKEN</span> you set on the server. It is stored in this browser only.</p>
    <button onclick="signIn()" style="width:100%">Unlock</button>
    <p id="gerr" style="color:var(--bad);font-size:12.5px;min-height:18px;margin:10px 0 0"></p>
  </div>
</div>

<div id="app" hidden>
  <header>
    <div class="mark">F</div>
    <h1>Flat to Funded<small id="sub">Licence administration</small></h1>
    <nav class="tabs">
      <button id="tab-ftf" onclick="setProduct('ftf')">Flat to Funded</button>
      <button id="tab-hourly" onclick="setProduct('hourly')">MNQ Hourly</button>
      <button id="tab-partners" onclick="openPartners()">Partners</button>
    </nav>
    <div style="margin-left:auto"><button class="ghost" onclick="signOut()">Sign out</button></div>
  </header>

  <main>
    <div id="productView">
    <div class="card">
      <h2>Issue a licence</h2>
      <div class="row">
        <div style="flex:2"><label for="email">Customer email</label>
          <input id="email" type="email" placeholder="trader@example.com"></div>
        <div><label for="days">Valid for</label>
          <select id="days">
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
            <option value="">Never expires</option>
            <option value="7">7 days (trial)</option>
          </select></div>
        <div style="flex:2"><label for="note">Note (optional)</label>
          <input id="note" placeholder="paid via Stripe, Discord @name…"></div>
        <div style="flex:0"><button onclick="create()">Create key</button></div>
      </div>
      <p id="cerr" style="color:var(--bad);font-size:12.5px;min-height:18px;margin:10px 0 0"></p>
    </div>

    <div class="card">
      <h2>Licences · <span id="count" class="dim">…</span></h2>
      <table>
        <thead><tr>
          <th>Key</th><th>Customer</th><th>Status</th>
          <th class="hide-sm">Expires</th><th class="hide-sm">Computer</th><th>Actions</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div id="empty" class="empty" hidden>No licences yet. Create one above.</div>
    </div>
    </div><!-- /productView -->

    <div id="partnerView" hidden>
      <div class="card">
        <h2>Partner portal link</h2>
        <p class="dim" style="margin:0 0 10px">Give this link to your partner. He signs in with the username &amp; password you set below, and only ever sees the keys he creates — never your existing customers.</p>
        <div class="row"><div style="flex:3"><input id="plink" readonly></div><div style="flex:0"><button class="ghost" onclick="copyLink()">Copy link</button></div></div>
      </div>
      <div class="card">
        <h2>Partner accounts</h2>
        <div class="row">
          <div><label for="pu">Username</label><input id="pu" placeholder="partner" autocomplete="off"></div>
          <div><label for="pp">Password</label><input id="pp" placeholder="set a password" autocomplete="off"></div>
          <div style="flex:0"><button onclick="createPartner()">Add partner</button></div>
        </div>
        <p id="perr" style="color:var(--bad);font-size:12.5px;min-height:18px;margin:10px 0 0"></p>
        <table style="margin-top:6px"><thead><tr><th>Partner</th><th class="hide-sm">Products</th><th>Issued day/wk/mo</th><th>Status</th><th>Actions</th></tr></thead><tbody id="prows"></tbody></table>
        <div id="pempty" class="empty" hidden>No partners yet. Add one above.</div>
      </div>
      <div class="card">
        <h2>Partner activity · <span id="unpaid" class="dim"></span></h2>
        <table><thead><tr><th>Key</th><th>Partner</th><th class="hide-sm">Product</th><th class="hide-sm">Created</th><th>Status</th><th>Paid?</th></tr></thead><tbody id="arows"></tbody></table>
        <div id="paempty" class="empty" hidden>No partner-issued keys yet.</div>
      </div>
    </div>
  </main>

</div>

<script>
let TOKEN = localStorage.getItem('f2f_admin_token') || '';
let PRODUCT = localStorage.getItem('f2f_admin_product') || 'ftf';
function base(){ return PRODUCT === 'hourly' ? '/api/admin/hourly' : '/api/admin'; }
function setProduct(p){
  PRODUCT = p; localStorage.setItem('f2f_admin_product', p);
  document.getElementById('tab-ftf').className = p === 'ftf' ? 'on' : '';
  document.getElementById('tab-hourly').className = p === 'hourly' ? 'on' : '';
  document.getElementById('sub').textContent = (p === 'hourly' ? 'MNQ Hourly' : 'Flat to Funded') + ' · licence administration';
  document.getElementById('tab-partners').className = '';
  show('productView', true); show('partnerView', false);
  if (!document.getElementById('app').hidden) load();
}

function show(id, on){ document.getElementById(id).hidden = !on; }
function toast(msg){
  const t = document.createElement('div'); t.className='toast'; t.textContent=msg;
  document.body.appendChild(t); setTimeout(()=>t.remove(), 2200);
}
async function api(path, opts){
  const o = Object.assign({headers:{}}, opts||{});
  o.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (o.body) o.headers['Content-Type'] = 'application/json';
  const r = await fetch(path, o);
  if (r.status === 401) { signOut(); throw new Error('unauthorized'); }
  const j = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
function signOut(){
  TOKEN=''; localStorage.removeItem('f2f_admin_token');
  show('app', false); show('gate', true);
}
async function signIn(){
  TOKEN = document.getElementById('tok').value.trim();
  document.getElementById('gerr').textContent = '';
  try {
    await api('/api/admin/licences');
    localStorage.setItem('f2f_admin_token', TOKEN);
    show('gate', false); show('app', true);
    load();
  } catch(e){
    document.getElementById('gerr').textContent = 'That token was not accepted.';
  }
}
async function create(){
  const email = document.getElementById('email').value.trim();
  const days  = document.getElementById('days').value;
  const note  = document.getElementById('note').value.trim();
  document.getElementById('cerr').textContent = '';
  try {
    const j = await api(base() + '/licences', {method:'POST',
      body: JSON.stringify({email, days: days === '' ? null : days, note})});
    document.getElementById('email').value = '';
    document.getElementById('note').value = '';
    await navigator.clipboard.writeText(j.licence.key).catch(()=>{});
    toast('Key created and copied: ' + j.licence.key);
    load();
  } catch(e){ document.getElementById('cerr').textContent = e.message; }
}
async function act(id, action, body){
  try { await api(base() + '/licences/' + id + '/' + action,
        {method:'POST', body: body ? JSON.stringify(body) : undefined});
        load(); } catch(e){ toast(e.message); }
}
function fmt(d){ return d ? new Date(d).toISOString().slice(0,10) : ''; }
function ago(d){
  if (!d) return 'never checked in';
  const days = Math.floor((Date.now() - new Date(d)) / 86400000);
  if (days === 0) return 'checked in today';
  if (days === 1) return 'checked in yesterday';
  return 'checked in ' + days + ' days ago';
}
function copy(k){ navigator.clipboard.writeText(k).then(()=>toast('Copied ' + k)); }

async function load(){
  const j = await api(base() + '/licences');
  const tb = document.getElementById('rows');
  document.getElementById('count').textContent = j.licences.length;
  show('empty', j.licences.length === 0);
  tb.innerHTML = '';
  for (const l of j.licences){
    const expired = l.expiresAt && new Date(l.expiresAt) < new Date();
    const status = !l.active ? '<span class="pill off">revoked</span>'
                 : expired   ? '<span class="pill exp">expired</span>'
                             : '<span class="pill on">active</span>';
    const machines = (l.machines || []);
    const mach = machines.length
      ? '<span class="mono">' + machines[0].id.slice(0,16) + '</span><br>' +
        '<span class="dim" style="font-size:11px">' + ago(l.lastCheck) + '</span>'
      : '<span class="dim">not activated yet</span>';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><span class="key" onclick="copy(\\'' + l.key + '\\')">' + l.key + '</span></td>' +
      '<td>' + (l.email || '<span class="dim">\u2014</span>') + (l.note ? '<br><span class="dim" style="font-size:12px">' + l.note + '</span>' : '') +
        (l.createdByRole === 'reseller' ? '<br><span class="dim" style="font-size:11px">via ' + l.createdBy + ' \u00b7 ' + fmtDT(l.createdAt) + '</span>' : '') + '</td>' +
      '<td>' + status + '</td>' +
      '<td class="hide-sm">' + (l.expiresAt ? fmt(l.expiresAt) : '<span class="dim">never</span>') + '</td>' +
      '<td class="hide-sm">' + mach + '</td>' +
      '<td><div class="acts">' +
        (l.active ? '<button class="danger" onclick="act(' + l.id + ',\\'revoke\\')">Revoke</button>'
                  : '<button onclick="act(' + l.id + ',\\'activate\\')">Restore</button>') +
        '<button class="ghost" onclick="act(' + l.id + ',\\'extend\\',{days:30})">+30d</button>' +
        (machines.length ? '<button class="ghost" onclick="act(' + l.id + ',\\'reset-machine\\')">Reset PC</button>' : '') +
      '</div></td>';
    tb.appendChild(tr);
  }
}

function openPartners(){
  document.getElementById('tab-ftf').className = '';
  document.getElementById('tab-hourly').className = '';
  document.getElementById('tab-partners').className = 'on';
  document.getElementById('sub').textContent = 'Partners · accounts & activity';
  show('productView', false); show('partnerView', true);
  document.getElementById('plink').value = location.origin + '/partner';
  loadPartners(); loadActivity();
}
function copyLink(){ copy(document.getElementById('plink').value); }
function fmtDT(d){ if(!d) return ''; const x=new Date(d); return x.toISOString().slice(0,10)+' '+x.toISOString().slice(11,16); }
async function createPartner(){
  const username=document.getElementById('pu').value.trim();
  const password=document.getElementById('pp').value;
  document.getElementById('perr').textContent='';
  try{
    await api('/api/admin/resellers',{method:'POST',body:JSON.stringify({username,password})});
    document.getElementById('pu').value=''; document.getElementById('pp').value='';
    toast('Partner added'); loadPartners();
  }catch(e){ document.getElementById('perr').textContent=e.message; }
}
async function partnerAct(id,action,body){
  try{ await api('/api/admin/resellers/'+id+'/'+action,{method:'POST',body:body?JSON.stringify(body):undefined}); loadPartners(); loadActivity(); }
  catch(e){ toast(e.message); }
}
function setPw(id){ const pw=prompt('New password for this partner:'); if(pw) partnerAct(id,'set-password',{password:pw}); }
async function loadPartners(){
  const j=await api('/api/admin/resellers');
  const tb=document.getElementById('prows'); tb.innerHTML='';
  show('pempty', j.resellers.length===0);
  for(const r of j.resellers){
    const status = r.active?'<span class="pill on">active</span>':'<span class="pill off">disabled</span>';
    const tr=document.createElement('tr');
    tr.innerHTML =
      '<td><b>'+r.username+'</b></td>'+
      '<td class="hide-sm"><span class="dim">'+r.products.join(', ')+'</span></td>'+
      '<td>'+r.today+' / '+r.week+' / '+r.month+'</td>'+
      '<td>'+status+'</td>'+
      '<td><div class="acts">'+
        '<button class="ghost" onclick="setPw('+r.id+')">Password</button>'+
        (r.active?'<button class="danger" onclick="partnerAct('+r.id+',\\'deactivate\\')">Disable</button>'
                 :'<button onclick="partnerAct('+r.id+',\\'activate\\')">Enable</button>')+
        '<button class="danger" onclick="if(confirm(\\'Delete partner '+r.username+'? The keys he already made stay active.\\'))partnerAct('+r.id+',\\'delete\\')">Delete</button>'+
      '</div></td>';
    tb.appendChild(tr);
  }
}
async function loadActivity(){
  const j=await api('/api/admin/partner-activity');
  document.getElementById('unpaid').textContent = j.unpaid+' unpaid';
  const tb=document.getElementById('arows'); tb.innerHTML='';
  show('paempty', j.licences.length===0);
  for(const l of j.licences){
    const expired = l.expiresAt && new Date(l.expiresAt) < new Date();
    const status = !l.active?'<span class="pill off">revoked</span>':expired?'<span class="pill exp">expired</span>':'<span class="pill on">active</span>';
    const paidBtn = l.paid
      ? '<button class="ghost" onclick="togglePaid(\\''+l.product+'\\','+l.id+',false)"><span class="pill on">paid</span></button>'
      : '<button class="danger" onclick="togglePaid(\\''+l.product+'\\','+l.id+',true)">mark paid</button>';
    const tr=document.createElement('tr');
    tr.innerHTML =
      '<td><span class="key" onclick="copy(\\''+l.key+'\\')">'+l.key+'</span>'+(l.note?'<br><span class="dim" style="font-size:12px">'+l.note+'</span>':'')+'</td>'+
      '<td><b>'+(l.createdBy||'')+'</b></td>'+
      '<td class="hide-sm"><span class="dim">'+l.productLabel+'</span></td>'+
      '<td class="hide-sm"><span class="mono">'+fmtDT(l.createdAt)+'</span></td>'+
      '<td>'+status+'</td>'+
      '<td>'+paidBtn+'</td>';
    tb.appendChild(tr);
  }
}
async function togglePaid(product,id,paid){
  const b = product==='hourly'?'/api/admin/hourly':'/api/admin';
  try{ await api(b+'/licences/'+id+'/set-paid',{method:'POST',body:JSON.stringify({paid})}); loadActivity(); load(); }
  catch(e){ toast(e.message); }
}

setProduct(PRODUCT);
if (TOKEN) { api('/api/admin/licences').then(()=>{ show('app',true); load(); })
                                       .catch(()=>{ show('gate',true); }); }
else show('gate', true);
</script>
</body>
</html>
`;

const PARTNER_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flat to Funded — Partner Portal</title>
<style>
  :root{--bg:#0b0f14;--panel:#111820;--panel2:#151d27;--line:#1e2a36;--ink:#dbe6ef;--dim:#7d8fa1;--accent:#56fcfd;--accent2:#6fc5cd;--ok:#3de8a8;--bad:#ff5c72;--warn:#ffc861;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  header{display:flex;align-items:center;gap:14px;padding:18px 24px;border-bottom:1px solid var(--line);background:var(--panel)}
  .mark{width:34px;height:34px;border-radius:9px;flex:none;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#06202a;font-weight:800;font-size:19px;display:grid;place-items:center}
  h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase}
  h1 small{display:block;font-size:11px;letter-spacing:.06em;color:var(--dim);text-transform:none;font-weight:400;margin-top:2px}
  main{max-width:1000px;margin:0 auto;padding:24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:20px}
  .card h2{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);margin:0 0 14px}
  label{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);margin-bottom:5px}
  input,select{background:var(--panel2);border:1px solid var(--line);color:var(--ink);border-radius:7px;padding:9px 11px;font:inherit;width:100%}
  input:focus,select:focus{outline:none;border-color:var(--accent2)}
  button{background:var(--accent);color:#06202a;border:0;border-radius:7px;padding:9px 16px;font:inherit;font-weight:650;cursor:pointer;white-space:nowrap}
  button:hover{filter:brightness(1.08)}
  button.ghost{background:transparent;color:var(--dim);border:1px solid var(--line);font-weight:500}
  button.danger{background:transparent;color:var(--bad);border:1px solid #3a2029;font-weight:500}
  .row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
  .row>div{flex:1;min-width:150px}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
  .stat{flex:1;min-width:120px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;text-align:center}
  .stat b{display:block;font-size:30px;font-weight:800;color:var(--accent)}
  .stat span{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);font-weight:600;padding:0 10px 9px;border-bottom:1px solid var(--line)}
  td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:0}
  .key{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--accent);cursor:pointer}
  .key:hover{text-decoration:underline}
  .pill{display:inline-block;font-size:10.5px;letter-spacing:.06em;padding:2px 8px;border-radius:20px;text-transform:uppercase;font-weight:650}
  .pill.on{background:rgba(61,232,168,.13);color:var(--ok)}
  .pill.off{background:rgba(255,92,114,.13);color:var(--bad)}
  .pill.exp{background:rgba(255,200,97,.13);color:var(--warn)}
  .dim{color:var(--dim)} .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dim)}
  .acts{display:flex;gap:6px;flex-wrap:wrap} .acts button{padding:5px 10px;font-size:12px}
  .gate{max-width:380px;margin:12vh auto}
  .toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);background:var(--accent);color:#06202a;padding:10px 20px;border-radius:8px;font-weight:650;box-shadow:0 8px 30px rgba(0,0,0,.5)}
  .empty{color:var(--dim);text-align:center;padding:30px}
  @media(max-width:760px){ .hide-sm{display:none} main{padding:14px} }
</style></head><body>

<div id="gate" class="gate" hidden>
  <div class="card">
    <h2>Partner sign in</h2>
    <label for="u">Username</label>
    <input id="u" autocomplete="username" placeholder="your username">
    <label for="pw" style="margin-top:10px">Password</label>
    <input id="pw" type="password" autocomplete="current-password" placeholder="your password">
    <button onclick="signIn()" style="width:100%;margin-top:14px">Sign in</button>
    <p id="gerr" style="color:var(--bad);font-size:12.5px;min-height:18px;margin:10px 0 0"></p>
  </div>
</div>

<div id="app" hidden>
  <header>
    <div class="mark">F</div>
    <h1>Flat to Funded<small>Partner portal</small></h1>
    <div style="margin-left:auto;display:flex;align-items:center;gap:12px">
      <span class="dim" id="who"></span>
      <button class="ghost" onclick="signOut()">Sign out</button>
    </div>
  </header>
  <main>
    <div class="stats">
      <div class="stat"><b id="s-today">0</b><span>Issued today</span></div>
      <div class="stat"><b id="s-week">0</b><span>This week</span></div>
      <div class="stat"><b id="s-month">0</b><span>This month</span></div>
    </div>
    <div class="card">
      <h2>Issue a licence</h2>
      <div class="row">
        <div id="prodWrap" style="flex:1" hidden><label for="prod">Product</label><select id="prod"></select></div>
        <div><label for="days">Valid for</label>
          <select id="days">
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
            <option value="7">7 days (trial)</option>
            <option value="">Never expires</option>
          </select></div>
        <div style="flex:2"><label for="note">Client name / note (optional)</label><input id="note" placeholder="e.g. John D. — Discord @john"></div>
        <div style="flex:0"><button onclick="create()">Create key</button></div>
      </div>
      <p id="cerr" style="color:var(--bad);font-size:12.5px;min-height:18px;margin:10px 0 0"></p>
    </div>
    <div class="card">
      <h2>Your licences · <span id="count" class="dim">…</span></h2>
      <table><thead><tr><th>Key</th><th class="hide-sm">Client</th><th>Status</th><th class="hide-sm">Expires</th><th class="hide-sm">Computer</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table>
      <div id="empty" class="empty" hidden>You haven't issued any keys yet. Create one above.</div>
    </div>
  </main>
</div>

<script>
let TOKEN = localStorage.getItem('f2f_partner_token') || '';
let PRODUCTS = [];
function show(id,on){ document.getElementById(id).hidden=!on; }
function toast(m){ const t=document.createElement('div'); t.className='toast'; t.textContent=m; document.body.appendChild(t); setTimeout(()=>t.remove(),2200); }
function copy(k){ navigator.clipboard.writeText(k).then(()=>toast('Copied '+k)); }
async function api(path,opts){
  const o=Object.assign({headers:{}},opts||{});
  o.headers['Authorization']='Bearer '+TOKEN;
  if(o.body) o.headers['Content-Type']='application/json';
  const r=await fetch(path,o);
  if(r.status===401){ signOut(); throw new Error('Session expired — sign in again.'); }
  const j=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.error||('HTTP '+r.status));
  return j;
}
function signOut(){ TOKEN=''; localStorage.removeItem('f2f_partner_token'); show('app',false); show('gate',true); }
async function signIn(){
  const username=document.getElementById('u').value.trim();
  const password=document.getElementById('pw').value;
  document.getElementById('gerr').textContent='';
  try{
    const r=await fetch('/api/reseller/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||'Sign in failed');
    TOKEN=j.token; localStorage.setItem('f2f_partner_token',TOKEN);
    show('gate',false); show('app',true); boot();
  }catch(e){ document.getElementById('gerr').textContent=e.message; }
}
async function boot(){
  const me=await api('/api/reseller/me');
  PRODUCTS=me.products;
  document.getElementById('who').textContent=me.username;
  const sel=document.getElementById('prod'); sel.innerHTML='';
  me.products.forEach(p=>{ const o=document.createElement('option'); o.value=p.id; o.textContent=p.label; sel.appendChild(o); });
  show('prodWrap', me.products.length>1);
  load();
}
function fmt(d){ return d? new Date(d).toISOString().slice(0,10):''; }
function ago(d){ if(!d) return 'never checked in'; const n=Math.floor((Date.now()-new Date(d))/86400000); return n===0?'checked in today':n===1?'checked in yesterday':'checked in '+n+' days ago'; }
async function create(){
  const product=document.getElementById('prod').value;
  const days=document.getElementById('days').value;
  const note=document.getElementById('note').value.trim();
  document.getElementById('cerr').textContent='';
  try{
    const j=await api('/api/reseller/licences',{method:'POST',body:JSON.stringify({product,days:days===''?null:days,note})});
    document.getElementById('note').value='';
    await navigator.clipboard.writeText(j.licence.key).catch(()=>{});
    toast('Key created & copied: '+j.licence.key);
    load();
  }catch(e){ document.getElementById('cerr').textContent=e.message; }
}
async function act(product,id,action,body){
  try{ await api('/api/reseller/licences/'+id+'/'+action,{method:'POST',body:body?JSON.stringify(body):undefined}); load(); }catch(e){ toast(e.message); }
}
async function load(){
  const j=await api('/api/reseller/licences');
  document.getElementById('s-today').textContent=j.counts.today;
  document.getElementById('s-week').textContent=j.counts.week;
  document.getElementById('s-month').textContent=j.counts.month;
  document.getElementById('count').textContent=j.licences.length;
  show('empty', j.licences.length===0);
  const tb=document.getElementById('rows'); tb.innerHTML='';
  for(const l of j.licences){
    const expired=l.expiresAt && new Date(l.expiresAt)<new Date();
    const status=!l.active?'<span class="pill off">revoked</span>':expired?'<span class="pill exp">expired</span>':'<span class="pill on">active</span>';
    const machines=l.machines||[];
    const mach=machines.length?'<span class="mono">'+machines[0].id.slice(0,16)+'</span><br><span class="dim" style="font-size:11px">'+ago(l.lastCheck)+'</span>':'<span class="dim">not activated yet</span>';
    const tr=document.createElement('tr');
    tr.innerHTML=
      '<td><span class="key" onclick="copy(\\''+l.key+'\\')">'+l.key+'</span>'+(PRODUCTS.length>1?'<br><span class="dim" style="font-size:11px">'+l.productLabel+'</span>':'')+'</td>'+
      '<td class="hide-sm">'+(l.note||'<span class="dim">—</span>')+'</td>'+
      '<td>'+status+'</td>'+
      '<td class="hide-sm">'+(l.expiresAt?fmt(l.expiresAt):'<span class="dim">never</span>')+'</td>'+
      '<td class="hide-sm">'+mach+'</td>'+
      '<td><div class="acts">'+
        (l.active?'<button class="danger" onclick="act(\\''+l.product+'\\','+l.id+',\\'revoke\\')">Deactivate</button>':'<button onclick="act(\\''+l.product+'\\','+l.id+',\\'activate\\')">Restore</button>')+
        '<button class="ghost" onclick="act(\\''+l.product+'\\','+l.id+',\\'extend\\',{days:30})">+30d</button>'+
        (machines.length?'<button class="ghost" onclick="act(\\''+l.product+'\\','+l.id+',\\'reset-machine\\')">Reset PC</button>':'')+
      '</div></td>';
    tb.appendChild(tr);
  }
}
if(TOKEN){ show('app',true); boot().catch(()=>{ show('app',false); show('gate',true); }); } else show('gate',true);
</script>
</body></html>
`;

// ---------------------------------------------------------------------------
// static files
// ---------------------------------------------------------------------------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript',
               '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function serveStatic(res, name) {
  const file = path.join(PUBLIC_DIR, path.normalize(name).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, {'content-type':'text/plain'}); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/api/verify' && req.method === 'POST') return verify(req, res, PRODUCTS.ftf);
  if (p === '/api/hourly/verify' && req.method === 'POST') return verify(req, res, PRODUCTS.hourly);
  if (p.startsWith('/api/admin/')) return admin(req, res, url).catch(err => {
    console.error(err); json(res, 500, { error: 'server error' });
  });
  if (p.startsWith('/api/reseller/')) return reseller(req, res, url).catch(err => {
    console.error(err); json(res, 500, { error: 'server error' });
  });
  if (p === '/health') return json(res, 200, { ok: true, product: PRODUCT,
                                               licences: PRODUCTS.ftf.db.licences.length,
                                               hourlyLicences: PRODUCTS.hourly.db.licences.length });
  if (p === '/' || p === '/admin' || p === '/admin.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(ADMIN_HTML);
  }
  if (p === '/partner' || p === '/partner.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(PARTNER_HTML);
  }
  return serveStatic(res, p);
});

for (const prod of Object.values(PRODUCTS)) loadDb(prod);
loadAux();
server.listen(PORT, () => console.log('licence server listening on ' + PORT));
