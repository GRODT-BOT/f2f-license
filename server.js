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
// Overnight Bot Readiness
//
// Scores how suitable tonight's market is for the overnight bot, 0-100, from a
// maintained calendar of the high-impact scheduled events that actually move
// the overnight/European session: Fed (FOMC), ECB, US CPI, US PCE and the US
// jobs report (NFP). These are the official published schedules, so the score
// updates itself by date with no external call. Market-"feel" factors the
// server can't know (trend, volatility) stay as optional manual toggles on the
// page. Read-only, public, and fully separate from licensing.
// ---------------------------------------------------------------------------
const CAL_FOMC = ['2026-01-28','2026-03-18','2026-04-29','2026-06-17','2026-07-29','2026-09-16','2026-10-28','2026-12-09',
                  '2027-01-27','2027-03-17','2027-04-28','2027-06-09','2027-07-28','2027-09-15','2027-10-27','2027-12-08'];
const CAL_ECB  = ['2026-02-05','2026-03-19','2026-04-30','2026-06-11','2026-07-23','2026-09-10','2026-10-29','2026-12-17',
                  '2027-02-04','2027-03-18','2027-04-29','2027-06-10','2027-07-22','2027-09-09','2027-10-28','2027-12-16'];
const CAL_CPI  = ['2026-11-10','2026-12-10','2027-01-13','2027-02-11','2027-03-10','2027-04-13','2027-05-12'];
const CAL_PCE  = ['2026-11-25','2026-12-23'];

function isoDay(d){ return d.toISOString().slice(0,10); }
function firstFriday(y, m){ // m is 0-11
  const d = new Date(Date.UTC(y, m, 1));
  const shift = (5 - d.getUTCDay() + 7) % 7; // 5 = Friday
  return new Date(Date.UTC(y, m, 1 + shift));
}
function nfpSet(){ // US jobs report = first Friday of each month, computed
  const s = new Set();
  const now = new Date();
  for (let k = -2; k <= 15; k++){
    const dt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + k, 1));
    s.add(isoDay(firstFriday(dt.getUTCFullYear(), dt.getUTCMonth())));
  }
  return s;
}
const EVENT_DEFS = [
  { type:'FOMC', label:'Fed rate decision (FOMC)',       set:new Set(CAL_FOMC), today:-38, prev:-20 },
  { type:'ECB',  label:'ECB rate decision',              set:new Set(CAL_ECB),  today:-34, prev:-18 },
  { type:'CPI',  label:'US CPI inflation report',        set:new Set(CAL_CPI),  today:-22, prev:-10 },
  { type:'NFP',  label:'US jobs report (NFP)',           set:nfpSet(),          today:-20, prev:-8  },
  { type:'PCE',  label:'US PCE inflation (Fed gauge)',   set:new Set(CAL_PCE),  today:-16, prev:-6  }
];
const READINESS_BASE = 72;

function etParts(date){
  const f = new Intl.DateTimeFormat('en-US', { timeZone:'America/New_York',
    year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', hour12:false });
  const o = {}; for (const part of f.formatToParts(date)) o[part.type] = part.value;
  return { y:+o.year, m:+o.month, d:+o.day, h:(o.hour === '24' ? 0 : +o.hour) };
}
function shiftISO(y, m, d, delta){ return isoDay(new Date(Date.UTC(y, m - 1, d + delta))); }

function targetDateISO(){
  const p = etParts(new Date());
  // before 7am ET the live session is the one ending this morning; otherwise
  // "tonight" is the session that trades into tomorrow.
  return shiftISO(p.y, p.m, p.d, p.h < 7 ? 0 : 1);
}

function readinessFor(targetISO){
  const dt = new Date(targetISO + 'T12:00:00Z');
  const wd = dt.getUTCDay(); // 0 Sun .. 6 Sat
  const weekday = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][wd];
  if (wd === 6 || wd === 0)
    return { date:targetISO, weekday, closed:true, score:null, base:READINESS_BASE, events:[],
             note:'Market is closed overnight (weekend) — the bot does not trade.' };
  const [ty, tm, td] = targetISO.split('-').map(Number);
  const prevISO = shiftISO(ty, tm, td, -1);
  let score = READINESS_BASE; const events = [];
  for (const e of EVENT_DEFS){
    if (e.set.has(targetISO)) { score += e.today; events.push({ type:e.type, label:e.label, when:'tonight', pts:e.today }); }
    else if (e.set.has(prevISO)) { score += e.prev; events.push({ type:e.type, label:e.label, when:'yesterday', pts:e.prev }); }
  }
  score = Math.max(0, Math.min(100, score));
  return { date:targetISO, weekday, closed:false, score, base:READINESS_BASE, events };
}

function apiReadiness(req, res, url){
  const q = url.searchParams.get('date');
  const target = (q && /^\d{4}-\d{2}-\d{2}$/.test(q)) ? q : targetDateISO();
  return json(res, 200, readinessFor(target));
}

// ---------------------------------------------------------------------------
// Readiness pages - two brands, one engine. Spanish copy; colours per brand.
// Flat to Funded (cyan on navy) at /readiness, El Gogosero (pink) at /gogo.
// ---------------------------------------------------------------------------
const THEME_FTF = {
  brand:'Flat to Funded', mark:'F2F', markText:'#06202a',
  markGrad:'linear-gradient(135deg,#56fcfd,#6fc5cd)',
  bg:'#0b0f14', panel:'#111820', panel2:'#151d27', line:'#1e2a36',
  fg:'#dbe6ef', muted:'#7d8fa1', dim:'#5f7183',
  accent:'#56fcfd', accent2:'#6fc5cd', accentDim:'#0d4a52',
  glow:'rgba(86,252,253,.10)',
  green:'#3de8a8', yellow:'#ffc861', red:'#ff5c72',
  footer:'FLAT TO FUNDED · MNQ NOCTURNO · Herramienta de riesgo, no asesoría financiera.'
};
const THEME_GOGO = {
  brand:'El Gogosero', mark:'EG', markText:'#2a041b',
  markGrad:'linear-gradient(135deg,#ff2d9a,#ff5cb0)',
  bg:'#0a0710', panel:'#160d18', panel2:'#20102a', line:'#331a3a',
  fg:'#fdeaf6', muted:'#c79fba', dim:'#8f6b86',
  accent:'#ff2d9a', accent2:'#22d3ee', accentDim:'#7a1450',
  glow:'rgba(255,45,154,.12)',
  green:'#22e07b', yellow:'#f5c24b', red:'#ff5c7a',
  footer:'EL GOGOSERO · MNQ NOCTURNO · Herramienta de riesgo, no asesoría financiera.'
};

function makeReadinessPage(t){ return `<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Preparación del Bot Nocturno — ${t.brand}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;700&display=swap">
<style>
:root{
  --bg:${t.bg};--panel:${t.panel};--panel2:${t.panel2};--line:${t.line};
  --fg:${t.fg};--muted:${t.muted};--dim:${t.dim};
  --accent:${t.accent};--accent2:${t.accent2};--accent-dim:${t.accentDim};
  --green:${t.green};--yellow:${t.yellow};--red:${t.red};--gray:${t.dim};
  --disp:"Chakra Petch",system-ui,sans-serif;--body:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",ui-monospace,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--body);line-height:1.5;
  background-image:radial-gradient(1100px 500px at 80% -10%,${t.glow},transparent 60%);}
.wrap{max-width:860px;margin:0 auto;padding:26px 18px 46px}
.brand{display:flex;align-items:center;gap:11px;font-family:var(--disp);font-weight:700;letter-spacing:3px;text-transform:uppercase;font-size:13px;color:var(--accent)}
.brand .mk{width:28px;height:28px;border-radius:7px;display:grid;place-items:center;background:${t.markGrad};color:${t.markText};font-weight:800;font-size:12px}
h1{font-family:var(--disp);font-weight:700;font-size:clamp(25px,5vw,37px);margin:14px 0 4px;letter-spacing:.5px}
.lede{color:var(--muted);max-width:60ch;margin:0;font-size:14.5px}
.asof{color:var(--dim);font-size:12.5px;font-family:var(--mono);margin-top:8px;letter-spacing:.3px}
.sublink{margin-top:12px;font-size:12.5px}
.sublink a{color:var(--accent2);text-decoration:none;border-bottom:1px dotted var(--accent-dim)}
.hero{display:grid;grid-template-columns:300px 1fr;gap:22px;align-items:center;background:linear-gradient(180deg,var(--panel),var(--bg));border:1px solid var(--line);border-radius:20px;padding:24px;margin:18px 0;box-shadow:0 10px 40px rgba(0,0,0,.45)}
.gaugewrap{position:relative;width:300px;height:300px;margin:0 auto}
.gaugewrap svg{width:300px;height:300px;transform:rotate(135deg)}
.gc{fill:none;stroke-linecap:round}
.gtrack{stroke:rgba(255,255,255,.06);stroke-width:22}
.gval{stroke-width:22;transition:stroke-dashoffset .6s cubic-bezier(.3,1,.4,1),stroke .3s}
.greadout{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.gnum{font-family:var(--mono);font-weight:700;font-size:70px;line-height:1;font-variant-numeric:tabular-nums}
.gpct{font-family:var(--mono);font-size:20px;color:var(--muted);margin-top:-2px}
.gcap{font-family:var(--disp);letter-spacing:2px;text-transform:uppercase;font-size:11px;color:var(--dim);margin-top:8px}
.verdict{display:flex;flex-direction:column;gap:12px}
.vbadge{display:inline-flex;align-items:center;gap:10px;align-self:flex-start;font-family:var(--disp);font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:18px;padding:10px 16px;border-radius:12px;border:1px solid}
.vdot{width:12px;height:12px;border-radius:50%}
.vaction{font-size:15px}.vsub{font-size:13px;color:var(--muted)}
.zones{display:flex;gap:7px;margin-top:4px;flex-wrap:wrap}
.zchip{font-family:var(--mono);font-size:11px;padding:4px 9px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:16px 0}
.panel h2{font-family:var(--disp);font-size:14px;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);margin:0 0 4px}
.panel h2 .sm{color:var(--accent2);font-size:11px;letter-spacing:1px}
.panel .hint{color:var(--dim);font-size:12.5px;margin:0 0 14px}
.evt{display:flex;align-items:center;gap:12px;padding:11px 13px;border:1px solid var(--line);border-radius:12px;background:var(--bg);margin-bottom:9px}
.evt .tag{font-family:var(--mono);font-weight:700;font-size:11px;padding:4px 9px;border-radius:7px;background:rgba(255,92,114,.16);color:var(--red);flex:0 0 auto;letter-spacing:.5px}
.evt .en{flex:1;min-width:0;font-size:13.5px;font-weight:600}
.evt .ew{font-family:var(--mono);font-size:11px;color:var(--dim)}
.evt .ep{font-family:var(--mono);font-weight:700;font-size:13px;color:var(--red)}
.clearcal{display:flex;align-items:center;gap:11px;padding:13px;border:1px solid var(--accent-dim);border-radius:12px;background:rgba(61,232,168,.07);color:var(--green);font-size:13.5px;font-weight:600}
.toggles{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grp{font-family:var(--mono);font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:var(--dim);margin:14px 0 8px}
.tg{display:flex;align-items:flex-start;gap:11px;padding:12px 13px;border:1px solid var(--line);border-radius:12px;background:var(--bg);cursor:pointer;user-select:none;transition:border-color .15s,background .15s}
.tg:hover{border-color:var(--accent-dim)}
.tg.on{background:var(--panel2);border-color:var(--accent-dim)}
.tg .sw{width:38px;height:22px;border-radius:999px;background:var(--panel2);flex:0 0 auto;position:relative;border:1px solid var(--line);transition:background .15s;margin-top:1px}
.tg .sw::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--dim);transition:transform .17s,background .17s}
.tg.on .sw{background:var(--accent-dim);border-color:var(--accent)}
.tg.on .sw::after{transform:translateX(16px);background:var(--accent)}
.tg .meta{flex:1;min-width:0;display:flex;flex-direction:column}
.tg .nm{font-size:13.5px;font-weight:600}
.tg .wt{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:2px}
.tg.risk.on .wt{color:var(--red)}.tg.good.on .wt{color:var(--green)}
.bd{display:flex;flex-direction:column}
.bdrow{display:flex;justify-content:space-between;align-items:center;gap:12px;font-family:var(--mono);font-size:13px;padding:7px 0;border-bottom:1px solid var(--line)}
.bdrow:last-child{border-bottom:0}
.bdrow .d{color:var(--green);font-weight:700}.bdrow .u{color:var(--red);font-weight:700}.bdrow .base{color:var(--muted)}
.bdtot{display:flex;justify-content:space-between;margin-top:10px;padding-top:12px;border-top:1px solid var(--line);font-family:var(--disp);letter-spacing:1px;text-transform:uppercase;font-size:14px}
.bdtot b{font-family:var(--mono);font-size:20px}
.note{color:var(--muted);font-size:12.5px;line-height:1.6}.note b{color:var(--fg)}
.foot{color:var(--dim);font-size:11.5px;margin-top:20px;text-align:center;font-family:var(--mono);letter-spacing:.3px}
@media(max-width:720px){.hero{grid-template-columns:1fr}.toggles{grid-template-columns:1fr}}
</style></head><body>
<div class="wrap">
  <div class="brand"><span class="mk">${t.mark}</span> ${t.brand}</div>
  <h1>Preparación del Bot Nocturno</h1>
  <p class="lede">Una lectura en vivo de si el mercado de esta noche le conviene al bot nocturno. El calendario económico se revisa solo; agrega abajo cómo se siente el mercado.</p>
  <div class="asof" id="asof">Leyendo el calendario de esta noche…</div>
  <div class="sublink" id="sublink"></div>

  <div class="hero">
    <div class="gaugewrap">
      <svg viewBox="0 0 300 300" aria-hidden="true">
        <circle class="gc gtrack" cx="150" cy="150" r="128"></circle>
        <circle class="gc gval" id="gval" cx="150" cy="150" r="128"></circle>
      </svg>
      <div class="greadout"><div>
        <div class="gnum" id="gnum" style="color:var(--gray)">–</div>
        <div class="gpct">/ 100</div>
        <div class="gcap">Puntaje de condiciones</div>
      </div></div>
    </div>
    <div class="verdict">
      <span class="vbadge" id="vbadge"><span class="vdot" id="vdot"></span><span id="vtext">Cargando</span></span>
      <div class="vaction" id="vaction"></div>
      <div class="vsub" id="vsub"></div>
      <div class="zones">
        <span class="zchip"><b style="color:var(--green)">70–100</b> &nbsp;Verde · opéralo</span>
        <span class="zchip"><b style="color:var(--yellow)">50–69</b> &nbsp;Amarillo · con cuidado</span>
        <span class="zchip"><b style="color:var(--red)">0–49</b> &nbsp;Rojo · no operar</span>
      </div>
    </div>
  </div>

  <div class="panel">
    <h2>Calendario de esta noche <span class="sm">· auto</span></h2>
    <p class="hint">Eventos programados de alto impacto cerca de la sesión de esta noche, cargados automáticamente.</p>
    <div id="calbox"></div>
  </div>

  <div class="panel">
    <h2>Cómo se siente el mercado <span class="sm">· opcional</span></h2>
    <p class="hint">El calendario es automático. Esto es tu criterio sobre la sesión anterior — activa lo que sea cierto para ajustar el puntaje.</p>
    <div class="grp">Riesgo — baja el puntaje</div>
    <div class="toggles" id="riskBox"></div>
    <div class="grp">Calma — sube el puntaje</div>
    <div class="toggles" id="goodBox"></div>
  </div>

  <div class="panel">
    <h2>Desglose del puntaje</h2>
    <div class="bd" id="breakdown"></div>
    <div class="bdtot"><span>Puntaje final</span><b id="bdfinal">–</b></div>
  </div>

  <div class="panel">
    <h2>Cómo leerlo</h2>
    <p class="note"><b>Verde (70+):</b> mercado tranquilo y en rango — el mejor ambiente del bot. Opéralo normal.<br>
    <b>Amarillo (50–69):</b> señales mixtas. Opera con menos tamaño y un tope de pérdida diaria ajustado.<br>
    <b>Rojo (menos de 50):</b> mercado movido por noticias o en tendencia — el tipo de noche que borró la semana pasada. Mantén el bot apagado o espera golpes.</p>
    <p class="note" style="margin-top:14px">Empieza en 72 (una noche normal) y resta por los eventos programados de la Fed, el BCE, el CPI, el empleo y el PCE cerca de la sesión de esta noche. Es una ayuda para decidir, <b>no una predicción</b>. Ningún puntaje garantiza ganar, y el bot puede perder en una noche verde. En una noche roja (de noticias), lo más seguro es simplemente no operarlo.</p>
  </div>

  <div class="foot">${t.footer}</div>
</div>

<script>
var MANUAL=[
  {id:"trend",nm:"La sesión anterior tuvo tendencia fuerte (un solo lado)",wt:-16,on:false,kind:"risk"},
  {id:"vol",nm:"Volatilidad alta / rangos amplios",wt:-12,on:false,kind:"risk"},
  {id:"calm",nm:"Sesión anterior tranquila, en rango",wt:10,on:false,kind:"good"},
  {id:"quiet",nm:"Mercado tranquilo hasta ahora esta noche",wt:8,on:false,kind:"good"}
];
var LBL={FOMC:"Decisión de tasas de la Fed (FOMC)",ECB:"Decisión de tasas del BCE",CPI:"Inflación de EE.UU. (CPI)",NFP:"Reporte de empleo de EE.UU. (NFP)",PCE:"Inflación PCE de EE.UU. (indicador de la Fed)"};
var DIAS=["domingo","lunes","martes","miércoles","jueves","viernes","sábado"];
var MESES=["enero","febrero","marzo","abril","mayo","junio","julio","agosto","septiembre","octubre","noviembre","diciembre"];
var CAL=null;
var C=2*Math.PI*128, ARC=C*0.75;
var gval=document.getElementById("gval");
document.querySelector(".gtrack").style.strokeDasharray=ARC+" "+C;
gval.style.strokeDasharray=ARC+" "+C;
function clamp(v){return Math.max(0,Math.min(100,v));}
function zone(s){
  if(s>=70) return {c:"var(--green)",label:"Adelante",action:"Buenas condiciones — opera el bot normalmente esta noche.",sub:"El mercado tranquilo y en rango es donde el bot gana."};
  if(s>=50) return {c:"var(--yellow)",label:"Precaución",action:"Mercado mixto — opera con menos tamaño y un tope de pérdida diaria ajustado.",sub:"Se puede operar, pero protege las primeras ganancias y no persigas el mercado."};
  return {c:"var(--red)",label:"No operar",action:"Riesgo alto por noticias — mantén el bot apagado o espera golpes.",sub:"Este es el tipo de noche que borró las ganancias de la semana pasada."};
}
function el(tag,cls,html){var e=document.createElement(tag);if(cls)e.className=cls;if(html!=null)e.innerHTML=html;return e;}
function fecha(){var d=new Date(CAL.date+"T12:00:00Z");return DIAS[d.getUTCDay()]+" "+d.getUTCDate()+" de "+MESES[d.getUTCMonth()]+" de "+d.getUTCFullYear();}
function render(){
  var gnum=document.getElementById("gnum");
  var vb=document.getElementById("vbadge"), vdot=document.getElementById("vdot");
  if(!CAL) return;
  if(CAL.closed){
    gval.style.strokeDashoffset=ARC; gnum.textContent="–"; gnum.style.color="var(--gray)";
    vb.style.borderColor="var(--gray)"; vb.style.color="var(--gray)"; vb.style.background="transparent";
    vdot.style.background="var(--gray)"; vdot.style.boxShadow="none";
    document.getElementById("vtext").textContent="Cerrado";
    document.getElementById("vaction").textContent="Mercado cerrado esta noche — el bot no opera.";
    document.getElementById("vsub").textContent="";
    document.getElementById("bdfinal").textContent="–";
    document.getElementById("asof").textContent="Para la noche del "+fecha()+"  ·  fin de semana — mercado cerrado";
    return;
  }
  var score=clamp(CAL.score + MANUAL.reduce(function(a,f){return a+(f.on?f.wt:0);},0));
  var z=zone(score);
  gval.style.strokeDashoffset=ARC*(1-score/100); gval.style.stroke=z.c;
  gnum.textContent=score; gnum.style.color=z.c;
  document.getElementById("bdfinal").textContent=score;
  vb.style.borderColor=z.c; vb.style.color=z.c;
  vb.style.background="color-mix(in srgb,"+z.c+" 12%, transparent)";
  vdot.style.background=z.c; vdot.style.boxShadow="0 0 12px "+z.c;
  document.getElementById("vtext").textContent=z.label;
  document.getElementById("vaction").textContent=z.action;
  document.getElementById("vsub").textContent=z.sub;
  document.getElementById("asof").textContent="Para la noche del "+fecha()+"  ·  calendario cargado automáticamente";
  var bd=document.getElementById("breakdown"); bd.innerHTML="";
  bd.appendChild(row("Base (noche normal)", CAL.base, "base"));
  CAL.events.forEach(function(e){ bd.appendChild(row((LBL[e.type]||e.label)+" ("+(e.when==="tonight"?"esta noche":"ayer")+")", e.pts, "u")); });
  MANUAL.forEach(function(f){ if(f.on) bd.appendChild(row(f.nm, f.wt, f.wt<0?"u":"d")); });
}
function row(label,val,t){
  var r=el("div","bdrow");
  var sign=(val>0&&t!=="base")?"+":"";
  r.appendChild(el("span",(t==="base"?"base":""),label));
  r.appendChild(el("span",(t==="u"?"u":(t==="d"?"d":"base")),sign+val));
  return r;
}
function renderCal(){
  var box=document.getElementById("calbox"); box.innerHTML="";
  if(!CAL||CAL.closed){ box.appendChild(el("div","clearcal","Mercado cerrado esta noche — no hay sesión.")); return; }
  if(!CAL.events.length){ box.appendChild(el("div","clearcal","✓  Calendario despejado — no hay eventos importantes cerca de la sesión de esta noche.")); return; }
  CAL.events.forEach(function(e){
    var r=el("div","evt");
    r.appendChild(el("span","tag",e.type));
    var m=el("span","en",(LBL[e.type]||e.label));
    m.appendChild(el("span","ew","<br>"+(e.when==="tonight"?"programado para la sesión de esta noche":"ocurrió el día anterior — el mercado aún lo digiere")));
    r.appendChild(m);
    r.appendChild(el("span","ep",e.pts+" pts"));
    box.appendChild(r);
  });
}
function buildToggles(){
  var rb=document.getElementById("riskBox"), gb=document.getElementById("goodBox");
  MANUAL.forEach(function(f){
    var d=el("div","tg "+f.kind);
    d.innerHTML='<span class="sw"></span><span class="meta"><span class="nm">'+f.nm+'</span><span class="wt">'+(f.wt>0?"+":"")+f.wt+' pts</span></span>';
    d.addEventListener("click",function(){ f.on=!f.on; d.classList.toggle("on",f.on); render(); });
    (f.kind==="risk"?rb:gb).appendChild(d);
  });
}
buildToggles();
fetch("/api/readiness").then(function(r){return r.json();}).then(function(j){
  CAL=j; renderCal(); render();
}).catch(function(){
  document.getElementById("asof").textContent="No se pudo leer el calendario — usando solo los factores manuales.";
  CAL={date:new Date().toISOString().slice(0,10),closed:false,score:72,base:72,events:[]};
  renderCal(); render();
});
</script>
</body></html>
`; }

const READINESS_HTML = makeReadinessPage(THEME_FTF).replace('<div class="sublink" id="sublink"></div>', '<div class="sublink"><a href="/gogo">Ver versión El Gogosero →</a></div>');
const GOGO_HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>El Gogosero - Preparacion del Bot</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Monoton&family=Chakra+Petch:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@500;700&display=swap">
<style>
:root{
  --bg:#0a0510;--panel:#160a1c;--panel2:#20102a;--line:#3a1540;
  --fg:#fdeaf6;--muted:#c79fba;--dim:#8f6b86;
  --pink:#ff2d9a;--pink2:#ff5cb0;--cyan:#22d3ee;
  --green:#22e07b;--yellow:#f5c24b;--red:#ff4d6d;--gray:#8f6b86;
  --disp:"Chakra Petch",system-ui,sans-serif;--body:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--fg);font-family:var(--body);overflow-x:hidden;position:relative;min-height:100vh}
.bgwrap{position:fixed;inset:0;overflow:hidden;z-index:0;pointer-events:none}
.gw{position:absolute;inset:0;background:radial-gradient(900px 500px at 50% -8%,rgba(255,45,154,.28),transparent 60%),radial-gradient(700px 500px at 85% 20%,rgba(34,211,238,.12),transparent 60%)}
.grid{position:absolute;left:-20%;right:-20%;bottom:-10%;height:48%;background-image:linear-gradient(rgba(255,45,154,.5) 1px,transparent 1px),linear-gradient(90deg,rgba(255,45,154,.4) 1px,transparent 1px);background-size:52px 52px;transform:perspective(420px) rotateX(70deg);transform-origin:bottom;mask-image:linear-gradient(to top,#000 10%,transparent 85%);animation:grid 7s linear infinite;opacity:.55}
@keyframes grid{from{background-position-y:0}to{background-position-y:52px}}
.beam{position:absolute;top:-30%;left:50%;width:48%;height:160%;transform-origin:top center;background:linear-gradient(to bottom,rgba(255,92,176,.16),transparent 70%);filter:blur(6px);mix-blend-mode:screen}
.beam.a{animation:sweepA 9s ease-in-out infinite}
.beam.b{background:linear-gradient(to bottom,rgba(34,211,238,.13),transparent 70%);animation:sweepB 11s ease-in-out infinite}
@keyframes sweepA{0%,100%{transform:translateX(-50%) rotate(-24deg)}50%{transform:translateX(-50%) rotate(20deg)}}
@keyframes sweepB{0%,100%{transform:translateX(-50%) rotate(22deg)}50%{transform:translateX(-50%) rotate(-20deg)}}
.rain{position:fixed;inset:0;z-index:1;pointer-events:none;overflow:hidden}
.bill{position:absolute;top:-8%;animation:fall linear forwards;will-change:transform;filter:drop-shadow(0 0 6px rgba(34,224,123,.5))}
@keyframes fall{to{transform:translateY(118vh) rotate(360deg)}}

.wrap{position:relative;z-index:2;max-width:760px;margin:0 auto;padding:28px 18px 60px}
.hero{text-align:center}
.badge{font-family:var(--mono);font-size:11px;letter-spacing:4px;color:var(--cyan);text-transform:uppercase;margin-bottom:8px;text-shadow:0 0 8px rgba(34,211,238,.8)}
.neon{font-family:"Monoton",cursive;font-size:clamp(32px,8vw,60px);color:#ffd8ef;line-height:1.05;letter-spacing:2px;text-shadow:0 0 6px #fff,0 0 14px var(--pink),0 0 30px var(--pink),0 0 60px var(--pink2),0 0 90px var(--pink);animation:flicker 4.5s infinite}
@keyframes flicker{0%,18%,22%,25%,53%,57%,100%{opacity:1}20%,24%,55%{opacity:.55}}
.tag{font-family:var(--disp);letter-spacing:3px;text-transform:uppercase;font-size:12px;color:var(--pink2);margin-top:6px;text-shadow:0 0 10px rgba(255,45,154,.7)}
.asof{color:var(--dim);font-size:12.5px;font-family:var(--mono);margin-top:10px}
.stage{position:relative;width:330px;height:330px;max-width:86vw;margin:22px auto 4px}
.bulbs{position:absolute;inset:0}
.bulb{position:absolute;width:11px;height:11px;border-radius:50%;left:50%;top:50%;margin:-5.5px;background:var(--pink);box-shadow:0 0 10px var(--pink),0 0 18px var(--pink)}
@keyframes chase{0%,100%{opacity:.25;box-shadow:0 0 4px var(--pink)}50%{opacity:1;box-shadow:0 0 14px var(--pink),0 0 24px var(--pink2)}}
.gauge{position:absolute;inset:34px}
.gauge svg{width:100%;height:100%;transform:rotate(135deg)}
.gc{fill:none;stroke-linecap:round}
.gtrack{stroke:rgba(255,255,255,.07);stroke-width:20}
.gval{stroke-width:20;filter:drop-shadow(0 0 10px currentColor);transition:stroke-dashoffset .8s cubic-bezier(.2,1,.3,1),stroke .4s}
.readout{position:absolute;inset:34px;display:grid;place-items:center;text-align:center}
.score{font-family:var(--mono);font-weight:700;font-size:74px;line-height:1;animation:pulse 2.4s ease-in-out infinite;text-shadow:0 0 18px currentColor}
@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.04)}}
.of{font-family:var(--mono);color:var(--muted);font-size:16px;margin-top:-2px}
.gcap{font-family:var(--disp);letter-spacing:2px;text-transform:uppercase;font-size:10px;color:var(--dim);margin-top:6px}
.verdict{font-family:var(--disp);font-weight:700;letter-spacing:3px;text-transform:uppercase;font-size:clamp(22px,6vw,32px);margin:8px 0 2px;animation:buzz 3s infinite}
@keyframes buzz{0%,92%,96%,100%{opacity:1}94%{opacity:.6}}
.vsub{color:var(--muted);font-size:14px;max-width:46ch;margin:4px auto 0}
.zones{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin:16px 0 4px}
.zchip{font-family:var(--mono);font-size:11px;padding:5px 11px;border-radius:999px;border:1px solid var(--line);color:var(--muted);background:rgba(0,0,0,.25)}

.panels{margin-top:30px;text-align:left}
.panel{background:linear-gradient(180deg,var(--panel),rgba(10,5,16,.6));border:1px solid var(--line);border-radius:16px;padding:20px;margin:16px 0;box-shadow:0 0 22px rgba(255,45,154,.07),inset 0 0 30px rgba(255,45,154,.03)}
.panel h2{font-family:var(--disp);font-size:14px;letter-spacing:1.5px;text-transform:uppercase;color:var(--pink);margin:0 0 4px;text-shadow:0 0 10px rgba(255,45,154,.5)}
.panel h2 .sm{color:var(--cyan);font-size:11px;letter-spacing:1px;text-shadow:0 0 8px rgba(34,211,238,.5)}
.panel .hint{color:var(--dim);font-size:12.5px;margin:0 0 14px}
.evt{display:flex;align-items:center;gap:12px;padding:11px 13px;border:1px solid var(--line);border-radius:12px;background:rgba(0,0,0,.3);margin-bottom:9px}
.evt .etag{font-family:var(--mono);font-weight:700;font-size:11px;padding:4px 9px;border-radius:7px;background:rgba(255,77,109,.18);color:var(--red);flex:0 0 auto;letter-spacing:.5px}
.evt .en{flex:1;min-width:0;font-size:13.5px;font-weight:600}
.evt .ew{font-family:var(--mono);font-size:11px;color:var(--dim)}
.evt .ep{font-family:var(--mono);font-weight:700;font-size:13px;color:var(--red)}
.clearcal{display:flex;align-items:center;gap:11px;padding:13px;border:1px solid rgba(34,224,123,.4);border-radius:12px;background:rgba(34,224,123,.08);color:var(--green);font-size:13.5px;font-weight:600;text-shadow:0 0 8px rgba(34,224,123,.4)}
.toggles{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grp{font-family:var(--mono);font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:var(--dim);margin:14px 0 8px}
.tg{display:flex;align-items:flex-start;gap:11px;padding:12px 13px;border:1px solid var(--line);border-radius:12px;background:rgba(0,0,0,.3);cursor:pointer;user-select:none;transition:border-color .15s,background .15s}
.tg:hover{border-color:var(--pink)}
.tg.on{background:var(--panel2);border-color:var(--pink)}
.tg .sw{width:38px;height:22px;border-radius:999px;background:var(--panel2);flex:0 0 auto;position:relative;border:1px solid var(--line);transition:background .15s;margin-top:1px}
.tg .sw::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--dim);transition:transform .17s,background .17s}
.tg.on .sw{background:rgba(255,45,154,.3);border-color:var(--pink)}
.tg.on .sw::after{transform:translateX(16px);background:var(--pink);box-shadow:0 0 10px var(--pink)}
.tg .meta{flex:1;min-width:0;display:flex;flex-direction:column}
.tg .nm{font-size:13.5px;font-weight:600}
.tg .wt{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:2px}
.tg.risk.on .wt{color:var(--red)}.tg.good.on .wt{color:var(--green)}
.bd{display:flex;flex-direction:column}
.bdrow{display:flex;justify-content:space-between;align-items:center;gap:12px;font-family:var(--mono);font-size:13px;padding:7px 0;border-bottom:1px solid rgba(255,45,154,.1)}
.bdrow:last-child{border-bottom:0}
.bdrow .u{color:var(--red);font-weight:700}.bdrow .d{color:var(--green);font-weight:700}.bdrow .base{color:var(--muted)}
.bdtot{display:flex;justify-content:space-between;margin-top:10px;padding-top:12px;border-top:1px solid var(--line);font-family:var(--disp);letter-spacing:1px;text-transform:uppercase;font-size:14px}
.bdtot b{font-family:var(--mono);font-size:20px}
.note{color:var(--muted);font-size:12.5px;line-height:1.6}.note b{color:var(--fg)}
.foot{color:var(--dim);font-size:11px;margin-top:24px;text-align:center;font-family:var(--mono);letter-spacing:1px}
@media(max-width:620px){.toggles{grid-template-columns:1fr}}
</style></head><body>
<div class="bgwrap"><div class="gw"></div><div class="beam a"></div><div class="beam b"></div><div class="grid"></div></div>
<div class="rain" id="rain"></div>

<div class="wrap">
  <div class="hero">
    <div class="badge">&#9733; VIP &#183; Sala de Control &#9733;</div>
    <div class="neon">EL GOGOSERO</div>
    <div class="tag">Semaforo del Bot Nocturno</div>
    <div class="asof" id="asof">Leyendo el calendario de esta noche&#8230;</div>

    <div class="stage">
      <div class="bulbs" id="bulbs"></div>
      <div class="gauge"><svg viewBox="0 0 300 300"><circle class="gc gtrack" cx="150" cy="150" r="130"></circle><circle class="gc gval" id="gval" cx="150" cy="150" r="130"></circle></svg></div>
      <div class="readout"><div>
        <div class="score" id="score" style="color:var(--gray)">&#8211;</div>
        <div class="of">/ 100</div>
        <div class="gcap">Puntaje de condiciones</div>
      </div></div>
    </div>

    <div class="verdict" id="verdict" style="color:var(--gray)">Cargando</div>
    <div class="vsub" id="vsub"></div>

    <div class="zones">
      <span class="zchip"><b style="color:var(--green)">70&#8211;100</b> Verde &#183; op&#233;ralo</span>
      <span class="zchip"><b style="color:var(--yellow)">50&#8211;69</b> Amarillo &#183; con cuidado</span>
      <span class="zchip"><b style="color:var(--red)">0&#8211;49</b> Rojo &#183; no operar</span>
    </div>
  </div>

  <div class="panels">
    <div class="panel">
      <h2>Calendario de esta noche <span class="sm">&#183; auto</span></h2>
      <p class="hint">Eventos programados de alto impacto cerca de la sesi&#243;n de esta noche, cargados autom&#225;ticamente.</p>
      <div id="calbox"></div>
    </div>
    <div class="panel">
      <h2>C&#243;mo se siente el mercado <span class="sm">&#183; opcional</span></h2>
      <p class="hint">El calendario es autom&#225;tico. Esto es tu criterio sobre la sesi&#243;n anterior &#8212; activa lo que sea cierto para ajustar el puntaje.</p>
      <div class="grp">Riesgo &#8212; baja el puntaje</div>
      <div class="toggles" id="riskBox"></div>
      <div class="grp">Calma &#8212; sube el puntaje</div>
      <div class="toggles" id="goodBox"></div>
    </div>
    <div class="panel">
      <h2>Desglose del puntaje</h2>
      <div class="bd" id="breakdown"></div>
      <div class="bdtot"><span>Puntaje final</span><b id="bdfinal">&#8211;</b></div>
    </div>
    <div class="panel">
      <h2>C&#243;mo leerlo</h2>
      <p class="note"><b>Verde (70+):</b> mercado tranquilo y en rango &#8212; el mejor ambiente del bot. Op&#233;ralo normal.<br>
      <b>Amarillo (50&#8211;69):</b> se&#241;ales mixtas. Opera con menos tama&#241;o y un tope de p&#233;rdida diaria ajustado.<br>
      <b>Rojo (menos de 50):</b> mercado movido por noticias o en tendencia &#8212; el tipo de noche que borr&#243; la semana pasada. Mant&#233;n el bot apagado o espera golpes.</p>
      <p class="note" style="margin-top:14px">Empieza en 72 (una noche normal) y resta por los eventos programados de la Fed, el BCE, el CPI, el empleo y el PCE cerca de la sesi&#243;n de esta noche. Es una ayuda para decidir, <b>no una predicci&#243;n</b>. Ning&#250;n puntaje garantiza ganar, y el bot puede perder en una noche verde. En una noche roja (de noticias), lo m&#225;s seguro es simplemente no operarlo.</p>
    </div>
    <div class="foot">EL GOGOSERO &#183; MNQ NOCTURNO &#183; Herramienta de riesgo, no asesor&#237;a financiera.</div>
  </div>
</div>

<script>
var bulbs=document.getElementById("bulbs"),N=40,R=163;
for(var i=0;i<N;i++){var a=i/N*2*Math.PI,b=document.createElement("div");b.className="bulb";b.style.transform="translate("+Math.cos(a)*R+"px,"+Math.sin(a)*R+"px)";b.style.animation="chase 1.2s linear infinite";b.style.animationDelay=(i*0.03)+"s";bulbs.appendChild(b);}
var C=2*Math.PI*130,ARC=C*0.75,gval=document.getElementById("gval");
document.querySelector(".gtrack").style.strokeDasharray=ARC+" "+C;gval.style.strokeDasharray=ARC+" "+C;
var MANUAL=[
 {id:"trend",nm:"La sesión anterior tuvo tendencia fuerte (un solo lado)",wt:-16,on:false,kind:"risk"},
 {id:"vol",nm:"Volatilidad alta / rangos amplios",wt:-12,on:false,kind:"risk"},
 {id:"calm",nm:"Sesión anterior tranquila, en rango",wt:10,on:false,kind:"good"},
 {id:"quiet",nm:"Mercado tranquilo hasta ahora esta noche",wt:8,on:false,kind:"good"}
];
var LBL={FOMC:"Decisión de tasas de la Fed (FOMC)",ECB:"Decisión de tasas del BCE",CPI:"Inflación de EE.UU. (CPI)",NFP:"Reporte de empleo de EE.UU. (NFP)",PCE:"Inflación PCE de EE.UU. (indicador de la Fed)"};
var DIAS=["domingo","lunes","martes","miércoles","jueves","viernes","sábado"];
var MESES=["enero","febrero","marzo","abril","mayo","junio","julio","agosto","septiembre","octubre","noviembre","diciembre"];
var CAL=null,rainTimer=null;
function clamp(v){return Math.max(0,Math.min(100,v));}
function zone(s){
 if(s>=70) return {c:"var(--green)",label:"Adelante",sub:"Mercado tranquilo y en rango — la mejor noche para el bot.",green:true};
 if(s>=50) return {c:"var(--yellow)",label:"Precaución",sub:"Mercado mixto — opera con menos tamaño y cuida las ganancias.",green:false};
 return {c:"var(--red)",label:"No operar",sub:"Noche de noticias — mantén el bot apagado o espera golpes.",green:false};
}
function el(t,c,h){var e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;}
function fecha(){var d=new Date(CAL.date+"T12:00:00Z");return DIAS[d.getUTCDay()]+" "+d.getUTCDate()+" de "+MESES[d.getUTCMonth()]+" de "+d.getUTCFullYear();}
function stopRain(){if(rainTimer){clearInterval(rainTimer);rainTimer=null;}}
function startRain(){if(rainTimer)return;rainTimer=setInterval(dropBill,170);}
function dropBill(){var r=document.getElementById("rain"),e=el("div","bill");e.textContent=Math.random()<.5?"💵":"💸";e.style.left=(Math.random()*100)+"vw";var dur=3+Math.random()*2.5;e.style.animationDuration=dur+"s";e.style.fontSize=(18+Math.random()*16)+"px";r.appendChild(e);setTimeout(function(){e.remove();},dur*1000+200);}
function row(label,val,t){var r=el("div","bdrow");var sign=(val>0&&t!=="base")?"+":"";r.appendChild(el("span",(t==="base"?"base":""),label));r.appendChild(el("span",(t==="u"?"u":(t==="d"?"d":"base")),sign+val));return r;}
function render(){
 var gnum=document.getElementById("score"),vd=document.getElementById("verdict");
 if(!CAL)return;
 if(CAL.closed){
  stopRain();gval.style.strokeDashoffset=ARC;gnum.textContent="–";gnum.style.color="var(--gray)";
  vd.textContent="Cerrado";vd.style.color="var(--gray)";vd.style.textShadow="none";
  document.getElementById("vsub").textContent="Mercado cerrado esta noche — el bot no opera.";
  document.getElementById("bdfinal").textContent="–";
  document.getElementById("asof").textContent="Para la noche del "+fecha()+"  ·  fin de semana — mercado cerrado";
  return;
 }
 var score=clamp(CAL.score+MANUAL.reduce(function(a,f){return a+(f.on?f.wt:0);},0));
 var z=zone(score);
 gval.style.strokeDashoffset=ARC*(1-score/100);gval.style.stroke=z.c;
 gnum.textContent=score;gnum.style.color=z.c;
 document.getElementById("bdfinal").textContent=score;
 vd.textContent=z.label;vd.style.color=z.c;vd.style.textShadow="0 0 10px "+z.c+",0 0 26px "+z.c;
 document.getElementById("vsub").textContent=z.sub;
 document.getElementById("asof").textContent="Para la noche del "+fecha()+"  ·  calendario cargado automáticamente";
 if(z.green)startRain();else stopRain();
 var bd=document.getElementById("breakdown");bd.innerHTML="";
 bd.appendChild(row("Base (noche normal)",CAL.base,"base"));
 CAL.events.forEach(function(e){bd.appendChild(row((LBL[e.type]||e.label)+" ("+(e.when==="tonight"?"esta noche":"ayer")+")",e.pts,"u"));});
 MANUAL.forEach(function(f){if(f.on)bd.appendChild(row(f.nm,f.wt,f.wt<0?"u":"d"));});
}
function renderCal(){
 var box=document.getElementById("calbox");box.innerHTML="";
 if(!CAL||CAL.closed){box.appendChild(el("div","clearcal","Mercado cerrado esta noche — no hay sesión."));return;}
 if(!CAL.events.length){box.appendChild(el("div","clearcal","✓  Calendario despejado — no hay eventos importantes cerca de la sesión de esta noche."));return;}
 CAL.events.forEach(function(e){
  var r=el("div","evt");r.appendChild(el("span","etag",e.type));
  var m=el("span","en",(LBL[e.type]||e.label));
  m.appendChild(el("span","ew","<br>"+(e.when==="tonight"?"programado para la sesión de esta noche":"ocurrió el día anterior — el mercado aún lo digiere")));
  r.appendChild(m);r.appendChild(el("span","ep",e.pts+" pts"));box.appendChild(r);
 });
}
function buildToggles(){
 var rb=document.getElementById("riskBox"),gb=document.getElementById("goodBox");
 MANUAL.forEach(function(f){
  var d=el("div","tg "+f.kind);
  d.innerHTML='<span class="sw"></span><span class="meta"><span class="nm">'+f.nm+'</span><span class="wt">'+(f.wt>0?"+":"")+f.wt+' pts</span></span>';
  d.addEventListener("click",function(){f.on=!f.on;d.classList.toggle("on",f.on);render();});
  (f.kind==="risk"?rb:gb).appendChild(d);
 });
}
buildToggles();
fetch("/api/readiness").then(function(r){return r.json();}).then(function(j){CAL=j;renderCal();render();}).catch(function(){
 document.getElementById("asof").textContent="No se pudo leer el calendario — usando solo los factores manuales.";
 CAL={date:new Date().toISOString().slice(0,10),closed:false,score:72,base:72,events:[]};renderCal();render();
});
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
  // The public branded domain (elgogosero.com) serves only the El Gogosero page;
  // the licensing admin stays reachable only on the private railway URL.
  const host = (req.headers.host || '').toLowerCase();
  const publicSite = host.indexOf('elgogosero.com') !== -1;

  if (p === '/api/verify' && req.method === 'POST') return verify(req, res, PRODUCTS.ftf);
  if (p === '/api/hourly/verify' && req.method === 'POST') return verify(req, res, PRODUCTS.hourly);
  if (p.startsWith('/api/admin/')) {
    if (publicSite) return json(res, 404, { error: 'not found' });
    return admin(req, res, url).catch(err => {
      console.error(err); json(res, 500, { error: 'server error' });
    });
  }
  if (p.startsWith('/api/reseller/')) return reseller(req, res, url).catch(err => {
    console.error(err); json(res, 500, { error: 'server error' });
  });
  if (p === '/health') return json(res, 200, { ok: true, product: PRODUCT,
                                               licences: PRODUCTS.ftf.db.licences.length,
                                               hourlyLicences: PRODUCTS.hourly.db.licences.length });
  if (p === '/api/readiness' && req.method === 'GET') return apiReadiness(req, res, url);
  if (p === '/readiness' || p === '/readiness.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(READINESS_HTML);
  }
  if (p === '/gogo' || p === '/gogo.html' || p === '/elgogosero') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(GOGO_HTML);
  }
  if (p === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(publicSite ? GOGO_HTML : ADMIN_HTML);
  }
  if (p === '/admin' || p === '/admin.html') {
    if (publicSite) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('Not found'); }
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
