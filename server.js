const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Database = require('better-sqlite3');

/* ===== Settings from environment (set these on Render) ===== */
const {
  BOT_TOKEN, STRAVA_CLIENT_ID, STRAVA_CLIENT_SECRET,
  BASE_URL,          // this server's public URL, e.g. https://wiut-runners.onrender.com
  ALLOWED_ORIGIN,    // your GitHub Pages origin, e.g. https://username.github.io
  STATE_SECRET,      // any long random string
  DB_PATH = './data.db', PORT = 3000,
} = process.env;
const ADMIN_ID = Number(process.env.ADMIN_ID || 971206160);
for (const k of ['BOT_TOKEN','STRAVA_CLIENT_ID','STRAVA_CLIENT_SECRET','BASE_URL','ALLOWED_ORIGIN','STATE_SECRET'])
  if (!process.env[k]) { console.error('Missing env var: ' + k); process.exit(1); }

/* ===== Database ===== */
const db = new Database(DB_PATH);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, female INTEGER DEFAULT 0,
  strava_id INTEGER, access TEXT, refresh TEXT, expires INTEGER);
CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, date TEXT, time TEXT, km REAL, sec INTEGER);
CREATE INDEX IF NOT EXISTS idx_act_user ON activities(user_id);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
`);
const DEFAULTS = { cap: 350, thr: 30, tail: 0.35, fem: 1.12, ref: 6 };
const getSettings = () => { const r = db.prepare("SELECT v FROM settings WHERE k='s'").get(); return r ? { ...DEFAULTS, ...JSON.parse(r.v) } : DEFAULTS; };
const points = (a, female, S) => {
  const p = a.sec / 60 / a.km;
  const deff = a.km <= S.thr ? a.km : S.thr + (a.km - S.thr) * S.tail;
  return Math.min(deff * Math.pow(S.ref / p, 1.5) * 5 * (female ? S.fem : 1), S.cap);
};

/* ===== Telegram initData check ===== */
function verifyInitData(initData) {
  if (!initData) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash'); if (!hash) return null;
  p.delete('hash');
  const str = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const h = crypto.createHmac('sha256', secret).update(str).digest('hex');
  if (h.length !== hash.length || !crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash))) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}
const displayName = u => u.first_name + (u.last_name ? ' ' + u.last_name[0] + '.' : '');

function auth(req, res, next) {
  const u = verifyInitData(req.get('X-Telegram-Init-Data'));
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  db.prepare(`INSERT INTO users(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name`).run(u.id, displayName(u));
  req.tg = u; req.user = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  next();
}
const adminOnly = (req, res, next) => (req.tg.id === ADMIN_ID ? next() : res.status(403).json({ error: 'forbidden' }));

/* ===== Strava ===== */
const sign = s => crypto.createHmac('sha256', STATE_SECRET).update(s).digest('hex');
const makeState = id => { const b = `${id}.${Date.now()}`; return `${b}.${sign(b)}`; };
function readState(st) {
  const [id, ts, sig] = String(st || '').split('.');
  if (!sig || sign(`${id}.${ts}`) !== sig || Date.now() - Number(ts) > 15 * 60 * 1000) return null;
  return Number(id);
}

async function stravaToken(body) {
  const r = await fetch('https://www.strava.com/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: STRAVA_CLIENT_ID, client_secret: STRAVA_CLIENT_SECRET, ...body }),
  });
  if (!r.ok) throw new Error('strava token ' + r.status);
  return r.json();
}
async function accessToken(user) {
  if (user.expires > Date.now() / 1000 + 60) return user.access;
  const t = await stravaToken({ grant_type: 'refresh_token', refresh_token: user.refresh });
  db.prepare('UPDATE users SET access=?, refresh=?, expires=? WHERE id=?').run(t.access_token, t.refresh_token, t.expires_at, user.id);
  return t.access_token;
}
async function syncUser(user) {
  const token = await accessToken(user);
  const ins = db.prepare(`INSERT INTO activities(id,user_id,name,date,time,km,sec) VALUES(?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET name=excluded.name,date=excluded.date,time=excluded.time,km=excluded.km,sec=excluded.sec`);
  for (let page = 1; page <= 5; page++) {
    const r = await fetch(`https://www.strava.com/api/v3/athlete/activities?per_page=100&page=${page}`, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error('strava activities ' + r.status);
    const list = await r.json();
    if (!list.length) break;
    for (const a of list) {
      if ((a.sport_type || a.type) !== 'Run' || !a.distance || !a.moving_time) continue;
      ins.run(a.id, user.id, a.name, a.start_date_local.slice(0, 10), a.start_date_local.slice(11, 16), a.distance / 1000, a.moving_time);
    }
    if (list.length < 100) break;
  }
}
const userActs = id => db.prepare('SELECT id,name,date,time,km,sec FROM activities WHERE user_id=? ORDER BY date DESC,time DESC').all(id);

/* ===== App ===== */
const app = express();
app.use(cors({ origin: ALLOWED_ORIGIN, allowedHeaders: ['Content-Type', 'X-Telegram-Init-Data'] }));
app.use(express.json());
app.get('/health', (_, res) => res.send('ok'));

app.get('/auth/strava/start', (req, res) => {
  const u = verifyInitData(req.query.init_data);
  if (!u) return res.status(401).send('Open this from the Telegram bot.');
  const q = new URLSearchParams({
    client_id: STRAVA_CLIENT_ID, redirect_uri: BASE_URL + '/auth/strava/callback', response_type: 'code',
    approval_prompt: 'auto', scope: 'read,activity:read_all', state: makeState(u.id),
  });
  res.redirect('https://www.strava.com/oauth/authorize?' + q);
});

app.get('/auth/strava/callback', async (req, res) => {
  const page = msg => res.send(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="background:#17181b;color:#fff;font:20px sans-serif;display:grid;place-items:center;height:100vh;text-align:center">${msg}</body>`);
  try {
    const id = readState(req.query.state);
    if (!id || req.query.error) return page('Connection cancelled.<br>Return to Telegram and try again.');
    if (!String(req.query.scope || '').includes('activity:read')) return page('Please allow access to your activities.<br>Return to Telegram and try again.');
    const t = await stravaToken({ grant_type: 'authorization_code', code: req.query.code });
    db.prepare('UPDATE users SET strava_id=?, female=?, access=?, refresh=?, expires=? WHERE id=?')
      .run(t.athlete.id, t.athlete.sex === 'F' ? 1 : 0, t.access_token, t.refresh_token, t.expires_at, id);
    syncUser(db.prepare('SELECT * FROM users WHERE id=?').get(id)).catch(console.error);
    page('Strava connected ✓<br>Return to Telegram.');
  } catch (e) { console.error(e); page('Something went wrong.<br>Return to Telegram and try again.'); }
});

app.get('/api/me', auth, (req, res) => {
  const u = req.user;
  res.json({ name: u.name, female: !!u.female, connected: !!u.strava_id, activities: userActs(u.id), settings: getSettings() });
});

app.post('/api/strava/sync', auth, async (req, res) => {
  if (!req.user.strava_id) return res.status(400).json({ error: 'not connected' });
  try { await syncUser(req.user); res.json({ activities: userActs(req.user.id) }); }
  catch (e) { console.error(e); res.status(502).json({ error: 'sync failed' }); }
});

app.get('/api/leaderboard', auth, (req, res) => {
  const S = getSettings();
  const runners = db.prepare('SELECT id,name,female FROM users WHERE strava_id IS NOT NULL').all().map(u => {
    const acts = userActs(u.id);
    return { id: u.id, name: u.name, runs: acts.length, km: acts.reduce((s, a) => s + a.km, 0), pts: acts.reduce((s, a) => s + points(a, u.female, S), 0) };
  }).filter(r => r.runs > 0).sort((a, b) => b.pts - a.pts);
  res.json({ runners });
});

app.post('/api/admin/settings', auth, adminOnly, (req, res) => {
  const n = {}; 
  for (const k of Object.keys(DEFAULTS)) {
    const v = Number(req.body[k]);
    if (!Number.isFinite(v) || v < 0 || (k !== 'tail' && v === 0)) return res.status(400).json({ error: 'invalid ' + k });
    n[k] = v;
  }
  db.prepare("INSERT INTO settings(k,v) VALUES('s',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(n));
  res.json(n);
});
// Points are calculated live from saved runs, so this just confirms.
app.post('/api/admin/recalculate', auth, adminOnly, (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log('Server on ' + PORT));
