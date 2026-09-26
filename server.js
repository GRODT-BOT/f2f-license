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
    </nav>
    <div style="margin-left:auto"><button class="ghost" onclick="signOut()">Sign out</button></div>
  </header>

  <main>
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
      '<td>' + l.email + (l.note ? '<br><span class="dim" style="font-size:12px">' + l.note + '</span>' : '') + '</td>' +
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

setProduct(PRODUCT);
if (TOKEN) { api('/api/admin/licences').then(()=>{ show('app',true); load(); })
                                       .catch(()=>{ show('gate',true); }); }
else show('gate', true);
</script>
</body>
</html>
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
  if (p === '/health') return json(res, 200, { ok: true, product: PRODUCT,
                                               licences: PRODUCTS.ftf.db.licences.length,
                                               hourlyLicences: PRODUCTS.hourly.db.licences.length });
  if (p === '/' || p === '/admin' || p === '/admin.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(ADMIN_HTML);
  }
  return serveStatic(res, p);
});

for (const prod of Object.values(PRODUCTS)) loadDb(prod);
server.listen(PORT, () => console.log('licence server listening on ' + PORT));
