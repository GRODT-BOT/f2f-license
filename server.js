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

if (!ADMIN_TOKEN) console.warn('WARNING: ADMIN_TOKEN not set - admin API is locked out.');
if (!PRIVATE_KEY) console.warn('WARNING: RSA_PRIVATE_KEY not set - answers cannot be signed.');

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------
let db = { nextId: 1, licences: [], checks: [] };
let writing = Promise.resolve();

function loadDb() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(DB_FILE)) {
      db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      db.checks = db.checks || [];
      console.log('loaded ' + db.licences.length + ' licences from ' + DB_FILE);
    } else {
      console.log('no licence file yet, starting empty at ' + DB_FILE);
    }
  } catch (err) {
    // Never start with a blank slate over a file we failed to parse - that
    // would silently wipe every customer on the next save.
    console.error('FATAL: could not read ' + DB_FILE, err);
    process.exit(1);
  }
}

// Serialised, atomic: write a temp file then rename, so a crash mid-write
// cannot leave a truncated licence file behind.
function saveDb() {
  writing = writing.then(async () => {
    const tmp = DB_FILE + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(db, null, 2));
    await fsp.rename(tmp, DB_FILE);
  }).catch(err => console.error('save failed', err));
  return writing;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1

function newKey() {
  const g = [];
  for (let i = 0; i < 4; i++) {
    let s = '';
    for (let j = 0; j < 5; j++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
    g.push(s);
  }
  return 'FTF-' + g.join('-');
}

// The exact string that gets signed. The C# side rebuilds this from the JSON
// fields and verifies against it, so this order must never drift from the
// strategy's BuildPayload().
function payloadString(o) {
  return [PRODUCT, o.key, o.machine, o.allowed ? '1' : '0',
          o.expires || '', o.issued, o.nonce].join('|');
}

function sign(s) {
  if (!PRIVATE_KEY) return '';
  try {
    return crypto.sign('sha256', Buffer.from(s, 'utf8'), PRIVATE_KEY).toString('base64');
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

function logCheck(entry) {
  db.checks.unshift(entry);
  if (db.checks.length > 500) db.checks.length = 500;
}

// ---------------------------------------------------------------------------
// the endpoint the strategy calls
// ---------------------------------------------------------------------------
async function verify(req, res) {
  let body;
  try { body = await readBody(req); }
  catch (e) { return json(res, 400, { error: 'bad request' }); }

  const key = String(body.key || '').trim().toUpperCase();
  const machine = String(body.machine || '').trim().slice(0, 128);
  const version = String(body.version || '').slice(0, 32);
  const issued = new Date().toISOString();
  const nonce = crypto.randomBytes(12).toString('hex');

  const answer = (allowed, reason, expires) => {
    const out = { product: PRODUCT, key, machine, allowed, expires: expires || '',
                  issued, nonce, reason };
    out.signature = sign(payloadString(out));
    logCheck({ at: issued, key, machine, version, allowed, reason });
    saveDb();
    return json(res, 200, out);
  };

  if (!key) return answer(false, 'No licence key entered.');
  if (!machine) return answer(false, 'No machine id supplied.');

  const lic = db.licences.find(l => l.key === key);
  if (!lic) return answer(false, 'Licence key not recognised.');
  if (!lic.active) return answer(false, 'This licence has been deactivated. Contact support.');
  if (lic.expiresAt && new Date(lic.expiresAt) < new Date())
    return answer(false, 'This licence expired on ' + lic.expiresAt.slice(0, 10) + '.');

  lic.machines = lic.machines || [];
  const known = lic.machines.find(m => m.id === machine);
  if (known) {
    known.lastSeen = issued;
  } else if (lic.machines.length >= MAX_MACHINES) {
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
  const parts = url.pathname.split('/').filter(Boolean); // api admin licences [id] [action]

  if (parts[2] === 'checks' && req.method === 'GET')
    return json(res, 200, { checks: db.checks.slice(0, 200) });

  if (parts[2] !== 'licences') return json(res, 404, { error: 'not found' });

  if (req.method === 'GET' && parts.length === 3)
    return json(res, 200, { licences: db.licences, maxMachines: MAX_MACHINES });

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
      key: newKey(),
      email,
      note: String(body.note || '').trim().slice(0, 200),
      active: true,
      expiresAt: Number.isFinite(days) && days > 0
        ? new Date(Date.now() + days * 86400000).toISOString() : null,
      createdAt: new Date().toISOString(),
      machines: [],
      lastCheck: null
    };
    db.licences.unshift(lic);
    await saveDb();
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
    else if (action === 'delete') db.licences = db.licences.filter(l => l.id !== id);
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

    await saveDb();
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: 'not found' });
}

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

  if (p === '/api/verify' && req.method === 'POST') return verify(req, res);
  if (p.startsWith('/api/admin/')) return admin(req, res, url).catch(err => {
    console.error(err); json(res, 500, { error: 'server error' });
  });
  if (p === '/health') return json(res, 200, { ok: true, product: PRODUCT,
                                               licences: db.licences.length });
  if (p === '/' || p === '/admin') { res.writeHead(302, { location: '/admin.html' }); return res.end(); }
  return serveStatic(res, p);
});

loadDb();
server.listen(PORT, () => console.log('licence server listening on ' + PORT));
