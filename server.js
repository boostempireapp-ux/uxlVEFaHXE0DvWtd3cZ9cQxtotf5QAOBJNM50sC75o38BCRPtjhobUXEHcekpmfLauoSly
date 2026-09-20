const express  = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const { randomUUID, createHash, createHmac, timingSafeEqual } = require('crypto');
const path     = require('path');
const https    = require('https');
const http     = require('http');

const app  = express();
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://boostempireapp_db_user:iLtBIzCxsdt8A7Wu@cluster0.3dj2qi7.mongodb.net/?appName=Cluster0';
const DB_NAME   = 'boostempire';

const BOT_SECRET = process.env.BOT_SECRET || 'changeme-set-BOT_SECRET-env-var';

// ── DISCORD WEBHOOK ───────────────────────────────────────────────────────────
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK
  || 'https://canary.discord.com/api/webhooks/1551110595401613343/13goaUq_9wCAnKdtmiHLsaoK8Vy_ZNtkDgcZtdkzesrbtVhipyXvR4X3qPE0vjxAbGEx';

function sendDiscordAlert(embed) {
  if (!DISCORD_WEBHOOK) return;
  try {
    const body = JSON.stringify({ embeds: [{ ...embed, timestamp: new Date().toISOString() }] });
    const url  = new URL(DISCORD_WEBHOOK);
    const req  = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    });
    req.on('error', () => {});
    req.write(body);
    req.end();
  } catch {}
}

function webhookBanned(key, reason, ip, appName) {
  sendDiscordAlert({
    title: '🔨 Key Banned',
    color: 0xFF0000,
    fields: [
      { name: 'Key',    value: `\`${key}\``,      inline: true },
      { name: 'App',    value: appName || '—',     inline: true },
      { name: 'IP',     value: ip || '—',          inline: true },
      { name: 'Reason', value: reason,             inline: false },
    ]
  });
}

function webhookHwidFlood(key, count, ip, appName) {
  sendDiscordAlert({
    title: '⚠️ HWID Flood → Key Auto-Frozen',
    color: 0xFF8C00,
    fields: [
      { name: 'Key',        value: `\`${key}\``,  inline: true },
      { name: 'App',        value: appName || '—', inline: true },
      { name: 'Mismatches', value: String(count),  inline: true },
      { name: 'IP',         value: ip || '—',      inline: true },
    ]
  });
}

function webhookIPBlocked(ip, reason) {
  sendDiscordAlert({
    title: '🚫 IP Permanently Blocked',
    color: 0x8B0000,
    fields: [
      { name: 'IP',     value: ip,     inline: true },
      { name: 'Reason', value: reason, inline: true },
    ]
  });
}

function webhookConcurrentSession(key, prevIP, newIP, appName) {
  sendDiscordAlert({
    title: '👥 Key Sharing Detected → Auto-Frozen',
    color: 0xFF6600,
    fields: [
      { name: 'Key',       value: `\`${key}\``,  inline: true },
      { name: 'App',       value: appName || '—', inline: true },
      { name: 'First IP',  value: prevIP,          inline: true },
      { name: 'Second IP', value: newIP,           inline: true },
    ]
  });
}

// ── TOTP 2FA (no external dependencies) ──────────────────────────────────────
const B32_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32Decode(s) {
  const str = s.replace(/=+$/, '').toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of str) {
    const i = B32_ALPHA.indexOf(c); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); }
  }
  return Buffer.from(out);
}

function b32Encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += B32_ALPHA[(val >> bits) & 31]; }
  }
  if (bits > 0) out += B32_ALPHA[(val << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += '=';
  return out;
}

function totpGenSecret() {
  const bytes = [];
  for (let i = 0; i < 20; i++) bytes.push(Math.floor(Math.random() * 256));
  return b32Encode(Buffer.from(bytes));
}

function totpCode(secret, windowOffset = 0) {
  const key     = b32Decode(secret);
  const counter = BigInt(Math.floor(Date.now() / 1000 / 30) + windowOffset);
  const buf     = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter);
  const mac    = createHmac('sha1', key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code   = ((mac[offset] & 0x7f) << 24 | mac[offset+1] << 16 | mac[offset+2] << 8 | mac[offset+3]) % 1_000_000;
  return code.toString().padStart(6, '0');
}

function totpVerify(secret, token) {
  if (!secret || !token) return false;
  const t = String(token).replace(/\s/g, '');
  for (let w = -1; w <= 1; w++) if (totpCode(secret, w) === t) return true;
  return false;
}

function totpUri(secret, label = 'BoostEmpire Admin') {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=BoostEmpire&algorithm=SHA1&digits=6&period=30`;
}

// ── MONGODB CONNECTION ────────────────────────────────────────────────────────
let db;
let keysCol, logsCol, adminCol, appsCol, blocksCol, resellersCol, detectionsCol, adminAuditCol;

async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db             = client.db(DB_NAME);
  keysCol        = db.collection('keys');
  logsCol        = db.collection('logs');
  adminCol       = db.collection('admin');
  appsCol        = db.collection('apps');
  blocksCol      = db.collection('blocks');
  resellersCol   = db.collection('resellers');
  detectionsCol  = db.collection('detections');
  adminAuditCol  = db.collection('adminAudit');

  await keysCol.createIndex({ key: 1 }, { unique: true });
  await logsCol.createIndex({ timestamp: -1 });
  await appsCol.createIndex({ publicKey: 1 }, { unique: true });
  await blocksCol.createIndex({ ip: 1 }, { unique: true });
  await resellersCol.createIndex({ username: 1 }, { unique: true });
  await detectionsCol.createIndex({ timestamp: -1 });
  await adminAuditCol.createIndex({ timestamp: -1 });

  const adminDoc  = await adminCol.findOne({ _id: 'admin' });
  const ADMIN_HASH = '730aa79139462fd34d63c453a7d8b76da661b1800c6b716ebedd9428f0ce0d7b';
  if (!adminDoc) {
    await adminCol.insertOne({
      _id: 'admin', password: ADMIN_HASH, adminToken: null,
      twoFAEnabled: false, twoFASecret: null, twoFAPending: null,
      allowedCountries: []
    });
  } else {
    const update = {};
    if (adminDoc.password !== ADMIN_HASH) {
      update.password = ADMIN_HASH; update.adminToken = null;
      console.log('[auth] Admin password updated on restart');
    }
    if (!('adminToken'      in adminDoc)) update.adminToken      = null;
    if (!('twoFAEnabled'    in adminDoc)) update.twoFAEnabled    = false;
    if (!('twoFASecret'     in adminDoc)) update.twoFASecret     = null;
    if (!('twoFAPending'    in adminDoc)) update.twoFAPending    = null;
    if (!('allowedCountries' in adminDoc)) update.allowedCountries = [];
    if (Object.keys(update).length) await adminCol.updateOne({ _id: 'admin' }, { $set: update });
  }
  console.log('[mongodb] Connected to MongoDB Atlas — data is persistent');
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function genKey()          { return 'BE-' + randomUUID().toUpperCase().replace(/-/g,'').substring(0,20); }
function genSessionToken() { return randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function genPubKey()       { return 'pk_' + randomUUID().replace(/-/g,''); }
function genSecKey()       { return 'sk_' + randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function hashString(s)     { return createHash('sha256').update(s).digest('hex'); }
function safeCompare(a, b) {
  try { return timingSafeEqual(Buffer.from(String(a)), Buffer.from(String(b))); }
  catch { return false; }
}

const CF_IP_RANGES = [
  '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.',
  '141.101.64.', '108.162.192.', '190.93.240.', '188.114.96.',
  '197.234.240.', '198.41.128.', '162.158.', '104.16.',
  '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
  '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
  '172.64.', '172.65.', '172.66.', '172.67.', '172.68.',
  '172.69.', '172.70.', '172.71.',
  '131.0.72.', '2400:cb00:', '2606:4700:', '2803:f800:',
  '2405:b500:', '2405:8100:', '2a06:98c0:', '2c0f:f248:'
];
function isCloudflareIP(ip) { return CF_IP_RANGES.some(r => ip.startsWith(r)); }

function getIP(req) {
  const cfIP = req.headers['cf-connecting-ip'];
  const socketRaw = (req.socket.remoteAddress || req.connection.remoteAddress || '').replace(/^::ffff:/, '');
  if (cfIP && isCloudflareIP(socketRaw)) return cfIP.trim();
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  const realIP = req.headers['x-real-ip'];
  if (realIP) return realIP.trim();
  if (socketRaw === '127.0.0.1' || socketRaw === '::1' || socketRaw === '') {
    const clientReported = (req.body && req.body.real_ip) || '';
    if (clientReported && clientReported !== '127.0.0.1') return clientReported.trim();
  }
  return socketRaw;
}

// ── RENDER FREE-TIER KEEP-ALIVE ───────────────────────────────────────────────
const SERVICE_URL      = process.env.SERVICE_URL || '';
const PING_INTERVAL_MS = 30 * 1000;

function startKeepAlive() {
  const pingUrl = `http://localhost:${PORT}/health`;
  let failStreak = 0;
  function ping() {
    const req = http.get(pingUrl, { timeout: 10000 }, (res) => {
      const alive = res.statusCode >= 200 && res.statusCode < 400;
      if (alive) {
        if (failStreak > 0) console.log(`[keep-alive] ✅  Back online after ${failStreak} failed ping(s) — ${new Date().toISOString()}`);
        failStreak = 0; res.resume();
      } else {
        failStreak++;
        console.warn(`[keep-alive] ⚠️  Ping returned HTTP ${res.statusCode} (streak: ${failStreak}) — ${new Date().toISOString()}`);
      }
    });
    req.on('timeout', () => { failStreak++; req.destroy(); });
    req.on('error',   () => { failStreak++; });
  }
  setInterval(ping, PING_INTERVAL_MS);
  console.log(`[keep-alive] 🔄  Self-ping started → ${pingUrl} every ${PING_INTERVAL_MS / 1000}s`);
}

function fetchPublicIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', (r) => {
      let d=''; r.on('data', c=>d+=c); r.on('end', ()=>{ try { resolve(JSON.parse(d).ip); } catch { resolve(null); } });
    }).on('error', ()=>resolve(null));
  });
}
async function resolveRealIP(req) {
  const ip = getIP(req);
  if (ip !== '127.0.0.1' && ip !== '::1') return ip;
  return (await fetchPublicIP().catch(()=>null)) || ip;
}

function log(appId, keyVal, hwid, appName, action, result, ip, details='') {
  logsCol.insertOne({
    appId: appId||null, key: keyVal, hwid: hwid||null,
    app_name: appName||'Unknown', action, result,
    ip: ip||null, details, timestamp: new Date().toISOString()
  }).catch(()=>{});
}

// ── ADMIN ACTION AUDIT LOG ────────────────────────────────────────────────────
function auditLog(ip, action, details = {}) {
  adminAuditCol.insertOne({
    ip: ip || '—', action, ...details,
    timestamp: new Date().toISOString()
  }).catch(() => {});
}

// ── IP GEO LOOKUP (country allowlist) ────────────────────────────────────────
const geoCache   = new Map();
const GEO_TTL_MS = 60 * 60 * 1000; // 1 hour

function getIPCountry(ip) {
  const cached = geoCache.get(ip);
  if (cached && Date.now() - cached.t < GEO_TTL_MS) return Promise.resolve(cached.c);
  return new Promise((resolve) => {
    const req = https.get(`https://ip-api.com/json/${ip}?fields=countryCode`, { timeout: 3000 }, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try { const c = JSON.parse(d).countryCode || null; geoCache.set(ip, { c, t: Date.now() }); resolve(c); }
        catch { resolve(null); }
      });
    });
    req.on('error',   () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// ── RATE LIMITER / REPLAY PROTECTION ─────────────────────────────────────────
const nonceCache  = new Map();
const NONCE_TTL   = 5 * 60 * 1000;
const TS_SKEW_MAX = 5 * 60 * 1000;
setInterval(() => { const n=Date.now(); for(const[k,v] of nonceCache) if(n>v) nonceCache.delete(k); }, 60_000);

// ── PER-KEY HWID MISMATCH FLOOD AUTO-FREEZE ───────────────────────────────────
const keyMismatch        = new Map();
const MISMATCH_FREEZE_AT = 8;
const MISMATCH_WINDOW    = 10 * 60 * 1000;
function trackKeyMismatch(key) {
  const now = Date.now();
  const rec = keyMismatch.get(key) || { count: 0, windowStart: now };
  if (now - rec.windowStart > MISMATCH_WINDOW) { rec.count = 1; rec.windowStart = now; }
  else rec.count++;
  keyMismatch.set(key, rec);
  return rec.count;
}

// ── CONCURRENT SESSION DETECTION (key sharing) ────────────────────────────────
const recentAuthIPs        = new Map(); // key -> { ip, time }
const CONCURRENT_WINDOW_MS = 10 * 1000; // 10 seconds

function checkConcurrentIP(key, ip) {
  const prev = recentAuthIPs.get(key);
  const now  = Date.now();
  if (prev && prev.ip !== ip && (now - prev.time) < CONCURRENT_WINDOW_MS) return prev.ip;
  recentAuthIPs.set(key, { ip, time: now });
  return null; // no conflict
}

// ── HWID RESET LOCKOUT ────────────────────────────────────────────────────────
const HWID_RESET_LIMIT     = 5;
const HWID_RESET_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function recordHwidReset(key) {
  const now          = new Date().toISOString();
  const windowStart  = new Date(Date.now() - HWID_RESET_WINDOW_MS).toISOString();
  await keysCol.updateOne({ key }, { $push: { hwidResets: { $each: [now], $slice: -20 } } });
  const doc    = await keysCol.findOne({ key }, { projection: { hwidResets: 1 } });
  const recent = (doc?.hwidResets || []).filter(t => t >= windowStart);
  if (recent.length >= HWID_RESET_LIMIT) {
    await keysCol.updateOne({ key }, { $set: { status: 'frozen' } });
    activeSessions.delete(key);
    return true; // auto-frozen
  }
  return false;
}

// ── REQUEST HMAC SIGNING (optional per-app) ───────────────────────────────────
function validateHmac(req, appDoc) {
  if (!appDoc?.hmacSecret) return true; // not configured — skip
  const sig      = req.headers['x-signature'] || '';
  if (!sig) return false;
  const body     = JSON.stringify(req.body);
  const expected = 'sha256=' + createHmac('sha256', appDoc.hmacSecret).update(body).digest('hex');
  return safeCompare(sig, expected);
}

const activeSessions = new Map();
const rateLimitMap   = new Map();
const failCounts     = new Map();
const RATE_WINDOW    = 60 * 1000;
const RATE_MAX       = 30;
const BLOCK_AFTER    = 80;

async function rateLimit(req, res, next) {
  const ip  = getIP(req);
  const now = Date.now();
  const blocked = await blocksCol.findOne({ ip });
  if (blocked) return res.status(429).json({ success:false, code:'IP_BLOCKED', message:'Your IP has been permanently blocked due to abuse' });
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const hits = rateLimitMap.get(ip).filter(t => now - t < RATE_WINDOW);
  hits.push(now);
  rateLimitMap.set(ip, hits);
  if (hits.length > RATE_MAX) {
    log(null,'—',null,'RATELIMIT','AUTH','RATE_LIMITED',ip,`${hits.length} requests in 60s`);
    return res.status(429).json({ success:false, code:'RATE_LIMITED', message:'Too many requests — slow down', retry_after:60 });
  }
  next();
}

async function trackFail(ip) {
  const count = (failCounts.get(ip)||0)+1;
  failCounts.set(ip, count);
  if (count >= BLOCK_AFTER) {
    const exists = await blocksCol.findOne({ ip });
    if (!exists) {
      const reason = 'Auto-blocked: too many failed auth attempts';
      await blocksCol.insertOne({ ip, reason, blockedAt: new Date().toISOString() });
      webhookIPBlocked(ip, reason);
    }
  }
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token) return res.status(401).json({ success:false, message:'Unauthorized' });
  const doc = await adminCol.findOne({ _id: 'admin' });
  if (!doc || !doc.adminToken || !safeCompare(token, doc.adminToken))
    return res.status(401).json({ success:false, message:'Unauthorized' });
  req.adminIP = getIP(req);
  next();
}

async function requireReseller(req, res, next) {
  const token = req.headers['x-reseller-token'] || req.query.token;
  if (!token) return res.status(401).json({ success:false, message:'Unauthorized' });
  const doc = await resellersCol.findOne({ sessionToken: token });
  if (!doc || !doc.active)
    return res.status(401).json({ success:false, message:'Unauthorized or account suspended' });
  req.reseller = doc;
  next();
}

function requireAdminOrReseller(req, res, next) {
  const adminToken    = req.headers['x-admin-token'] || req.query.token;
  const resellerToken = req.headers['x-reseller-token'];
  if (adminToken) return requireAdmin(req, res, next);
  if (resellerToken) return requireReseller(req, res, next);
  return res.status(401).json({ success:false, message:'Unauthorized' });
}

// ── EXPRESS SETUP ─────────────────────────────────────────────────────────────
app.set('trust proxy', true);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS,PATCH');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, x-admin-token, x-reseller-token, x-public-key, x-secret-key, x-request-id, x-timestamp, CF-Connecting-IP, x-bot-token, x-signature');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── HONEYPOT ENDPOINTS ────────────────────────────────────────────────────────
// Only a scanner or reverse-engineer would ever hit these fake routes.
// Any IP that does gets permanently banned immediately.
const HONEYPOT_PATHS = [
  '/api/v2/auth', '/api/v1/auth', '/api/v1/validate',
  '/panel/login', '/api/check', '/api/admin/getkeys',
  '/api/crack', '/api/bypass', '/api/v2/validate', '/api/v1/login'
];
for (const hPath of HONEYPOT_PATHS) {
  app.all(hPath, async (req, res) => {
    try {
      const ip     = getIP(req);
      const exists = await blocksCol.findOne({ ip });
      if (!exists) {
        const reason = `Honeypot triggered: ${hPath}`;
        await blocksCol.insertOne({ ip, reason, blockedAt: new Date().toISOString() });
        webhookIPBlocked(ip, reason);
        log(null, '—', null, 'HONEYPOT', 'PROBE', 'PERMABANNED', ip, reason);
      }
    } catch {}
    res.status(403).json({ success: false, message: 'Forbidden' });
  });
}

// ── PUBLIC ────────────────────────────────────────────────────────────────────
app.get('/api/myip', (req, res) => res.json({ ip: getIP(req) }));
app.get('/health',   (req, res) => res.json({ status:'ok', storage:'mongodb' }));
app.get('/',         (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── AUTH ──────────────────────────────────────────────────────────────────────
function authJitter() { return new Promise(r => setTimeout(r, 80 + Math.floor(Math.random() * 270))); }

app.post('/api/auth', rateLimit, async (req, res) => {
  await authJitter();
  const { key, hwid, app_name } = req.body;
  const publicKey = req.headers['x-public-key'] || req.body.public_key;
  const ip        = await resolveRealIP(req);

  if (!publicKey||typeof publicKey!=='string'||publicKey.length>200)
    return res.json({ success:false, code:'NO_PUBLIC_KEY', message:'Missing or invalid public API key' });
  if (!key||typeof key!=='string'||key.length>100)
    return res.json({ success:false, code:'NO_KEY', message:'Missing or invalid license key' });
  if (!hwid||typeof hwid!=='string'||hwid.length>200)
    return res.json({ success:false, code:'NO_HWID', message:'Missing or invalid HWID' });

  // Enhanced HWID validation
  const SUSPICIOUS_HWID_PAT = /^(0+|f+|a+|1+|deadbeef|cafebabe|test|fake|crack|bypass|debug|cheat|null|none|unknown|demo|frida|x64dbg|olly|cheatengine|ida|hook|inject|dump|unpack|patch)/i;
  if (hwid.length < 8 || SUSPICIOUS_HWID_PAT.test(hwid)) {
    log(null,key,hwid,app_name,'AUTH','INVALID_HWID',ip,'Suspicious HWID pattern');
    await trackFail(ip);
    return res.json({ success:false, code:'INVALID_HWID', message:'Invalid hardware ID' });
  }
  if (new Set(hwid.replace(/-/g,'')).size < 4) {
    log(null,key,hwid,app_name,'AUTH','INVALID_HWID',ip,'Low-entropy HWID');
    await trackFail(ip);
    return res.json({ success:false, code:'INVALID_HWID', message:'Invalid hardware ID' });
  }

  // Timestamp + nonce replay protection
  const clientTs = parseInt(req.headers['x-timestamp'] || req.body.ts || '0', 10);
  if (clientTs && Math.abs(Date.now() - clientTs) > TS_SKEW_MAX) {
    log(null,key,hwid,app_name,'AUTH','REPLAY_REJECTED',ip,'Timestamp expired');
    await trackFail(ip);
    return res.json({ success:false, code:'REPLAY_REJECTED', message:'Request timestamp expired' });
  }
  const nonce = req.headers['x-request-id'] || req.body.nonce;
  if (nonce && typeof nonce === 'string' && nonce.length >= 8 && nonce.length <= 128) {
    if (nonceCache.has(nonce)) {
      log(null,key,hwid,app_name,'AUTH','REPLAY_REJECTED',ip,'Duplicate nonce');
      await trackFail(ip);
      return res.json({ success:false, code:'REPLAY_REJECTED', message:'Duplicate request' });
    }
    nonceCache.set(nonce, Date.now() + NONCE_TTL);
  }

  const appDoc = await appsCol.findOne({ publicKey });
  if (!appDoc) {
    await trackFail(ip);
    log(null,key,hwid,app_name,'AUTH','INVALID_PUBLIC_KEY',ip,'Unknown public key');
    return res.json({ success:false, code:'INVALID_PUBLIC_KEY', message:'Invalid public API key' });
  }
  if (!appDoc.active) return res.json({ success:false, code:'APP_DISABLED', message:'This application is disabled' });

  // ── HMAC signature check (optional per-app) ───────────────────────────────
  if (!validateHmac(req, appDoc)) {
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','INVALID_SIGNATURE',ip,'HMAC mismatch');
    await trackFail(ip);
    return res.json({ success:false, code:'INVALID_SIGNATURE', message:'Request signature invalid' });
  }

  // ── Country allowlist ─────────────────────────────────────────────────────
  const adminCfg        = await adminCol.findOne({ _id: 'admin' }, { projection: { allowedCountries: 1 } });
  const allowedCountries = adminCfg?.allowedCountries || [];
  if (allowedCountries.length > 0) {
    const country = await getIPCountry(ip);
    if (country && !allowedCountries.includes(country)) {
      log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','GEO_BLOCKED',ip,`Country: ${country}`);
      await trackFail(ip);
      return res.json({ success:false, code:'GEO_BLOCKED', message:'Access not allowed from your region' });
    }
  }

  const doc = await keysCol.findOne({ key, appId: String(appDoc._id) });
  if (!doc) {
    await trackFail(ip);
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','INVALID_KEY',ip,'Key not found');
    return res.json({ success:false, code:'INVALID_KEY', message:'License key not found' });
  }
  if (doc.status==='banned') {
    await trackFail(ip);
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','BANNED',ip);
    return res.json({ success:false, code:'BANNED', message:'This license key has been banned' });
  }
  if (doc.status==='frozen') {
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','FROZEN',ip);
    return res.json({ success:false, code:'FROZEN', message:'This license key has been temporarily frozen' });
  }
  if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','EXPIRED',ip);
    return res.json({ success:false, code:'EXPIRED', message:'License key has expired' });
  }

  // ── CPU multi-machine detection ───────────────────────────────────────────
  const cpu = req.body.cpu||'';
  if (cpu && doc.lastCpu && doc.lastCpu !== cpu) {
    const lastAuthTime = doc.lastUsed ? new Date(doc.lastUsed).getTime() : 0;
    if (Date.now() - lastAuthTime < 60000) {
      await keysCol.updateOne({ key }, { $set:{ status:'banned' } });
      activeSessions.delete(key);
      webhookBanned(key, 'Multi-machine CPU detection', ip, appDoc.name);
      log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','BANNED',ip,'Multi-machine detected');
      return res.json({ success:false, code:'BANNED', message:'License key banned for multi-machine use' });
    }
  }
  if (cpu) await keysCol.updateOne({ key }, { $set:{ lastCpu:cpu } });

  // ── HWID check ────────────────────────────────────────────────────────────
  const hwidHash = hashString(hwid + String(appDoc._id));
  if (doc.hwid) {
    if (!safeCompare(doc.hwid, hwidHash)) {
      await trackFail(ip);
      const mCount = trackKeyMismatch(key);
      log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','HWID_MISMATCH',ip,`Attempt #${mCount} | Tried: ${hwid}`);
      if (mCount >= MISMATCH_FREEZE_AT && doc.status === 'active') {
        await keysCol.updateOne({ key }, { $set:{ status:'frozen' } });
        activeSessions.delete(key);
        webhookHwidFlood(key, mCount, ip, appDoc.name);
        log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','AUTO_FROZEN',ip,`Auto-frozen after ${mCount} HWID mismatches`);
        keyMismatch.delete(key);
      }
      return res.json({ success:false, code:'HWID_MISMATCH', message:'HWID mismatch — please contact support' });
    }
  } else {
    await keysCol.updateOne({ key }, { $set:{ hwid:hwidHash, hwidRaw:hwid } });
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','HWID_BOUND',ip,'HWID locked');
  }

  // ── Concurrent session / key sharing detection ────────────────────────────
  const conflictIP = checkConcurrentIP(key, ip);
  if (conflictIP) {
    await keysCol.updateOne({ key }, { $set: { status: 'frozen' } });
    activeSessions.delete(key);
    webhookConcurrentSession(key, conflictIP, ip, appDoc.name);
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','CONCURRENT_FREEZE',ip,`Key sharing: prev IP ${conflictIP}`);
    return res.json({ success:false, code:'CONCURRENT_SESSION', message:'License key frozen: concurrent session detected (key sharing)' });
  }

  failCounts.delete(ip);
  const sessionToken = genSessionToken();
  activeSessions.set(key, { token: sessionToken, appId: String(appDoc._id) });
  await keysCol.updateOne({ key }, { $set:{ lastUsed: new Date().toISOString() } });
  log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','SUCCESS',ip,'Authenticated');

  // ── Expiry warning ────────────────────────────────────────────────────────
  let expiresInDays = null;
  if (doc.expiresAt) {
    const msLeft  = new Date(doc.expiresAt).getTime() - Date.now();
    expiresInDays = Math.max(0, Math.ceil(msLeft / 86400000));
  }

  res.json({
    success: true, code: 'OK', message: 'Authenticated successfully',
    session_token: sessionToken,
    data: {
      app: appDoc.name, product: doc.product, label: doc.label,
      expires_at:      doc.expiresAt || null,
      expires_in_days: expiresInDays,   // null = never expires; 0 = today
      hwid_locked: true
    }
  });
});

// ── HEARTBEAT ─────────────────────────────────────────────────────────────────
app.post('/api/heartbeat', rateLimit, async (req, res) => {
  const { key, session_token } = req.body;
  if (!key||!session_token) return res.json({ valid:false, code:'MISSING_PARAMS' });
  const session = activeSessions.get(key);
  if (!session||session.token!==session_token) return res.json({ valid:false, code:'KICKED', message:'Your session has been terminated by an administrator.' });
  const doc = await keysCol.findOne({ key });
  if (!doc) return res.json({ valid:false, code:'INVALID_KEY' });
  if (doc.status==='banned') { activeSessions.delete(key); return res.json({ valid:false, code:'BANNED', message:'Your license key has been banned.' }); }
  if (doc.status==='frozen') { activeSessions.delete(key); return res.json({ valid:false, code:'FROZEN', message:'Your license key has been temporarily frozen.' }); }
  if (doc.expiresAt&&new Date(doc.expiresAt)<new Date()) { activeSessions.delete(key); return res.json({ valid:false, code:'EXPIRED', message:'Your license key has expired.' }); }
  return res.json({ valid:true, code:'OK' });
});

// ── ADMIN: 2FA SETUP / VERIFY / DISABLE ──────────────────────────────────────
// POST /api/admin/2fa/setup — generate a pending secret, return QR URI
app.post('/api/admin/2fa/setup', requireAdmin, async (req, res) => {
  const secret  = totpGenSecret();
  const uri     = totpUri(secret);
  const qrUrl   = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`;
  await adminCol.updateOne({ _id: 'admin' }, { $set: { twoFAPending: secret } });
  auditLog(req.adminIP, '2FA_SETUP_INITIATED', {});
  res.json({ success: true, secret, uri, qr_url: qrUrl,
    message: 'Scan the QR code in Google Authenticator, then call /api/admin/2fa/verify with your 6-digit code' });
});

// POST /api/admin/2fa/verify — confirm TOTP code and enable 2FA
app.post('/api/admin/2fa/verify', requireAdmin, async (req, res) => {
  const { totp } = req.body;
  const doc = await adminCol.findOne({ _id: 'admin' });
  if (!doc?.twoFAPending)
    return res.json({ success: false, message: 'No pending 2FA setup — call /api/admin/2fa/setup first' });
  if (!totpVerify(doc.twoFAPending, totp))
    return res.json({ success: false, message: 'Invalid TOTP code — try again' });
  await adminCol.updateOne({ _id: 'admin' }, {
    $set: { twoFAEnabled: true, twoFASecret: doc.twoFAPending, twoFAPending: null }
  });
  auditLog(req.adminIP, '2FA_ENABLED', {});
  res.json({ success: true, message: '2FA is now enabled on the admin panel' });
});

// POST /api/admin/2fa/disable — disable 2FA (requires current TOTP to confirm)
app.post('/api/admin/2fa/disable', requireAdmin, async (req, res) => {
  const { totp } = req.body;
  const doc = await adminCol.findOne({ _id: 'admin' });
  if (!doc?.twoFAEnabled) return res.json({ success: false, message: '2FA is not enabled' });
  if (!totpVerify(doc.twoFASecret, totp))
    return res.json({ success: false, message: 'Invalid TOTP code — cannot disable 2FA without it' });
  await adminCol.updateOne({ _id: 'admin' }, { $set: { twoFAEnabled: false, twoFASecret: null, twoFAPending: null } });
  auditLog(req.adminIP, '2FA_DISABLED', {});
  res.json({ success: true, message: '2FA has been disabled' });
});

// GET /api/admin/2fa/status
app.get('/api/admin/2fa/status', requireAdmin, async (req, res) => {
  const doc = await adminCol.findOne({ _id: 'admin' }, { projection: { twoFAEnabled: 1 } });
  res.json({ success: true, enabled: !!doc?.twoFAEnabled });
});

// ── ADMIN: APPS ───────────────────────────────────────────────────────────────
app.get('/api/admin/apps', requireAdmin, async (req, res) => {
  const apps = await appsCol.find({}).sort({ createdAt:-1 }).toArray();
  res.json({ success:true, apps });
});
app.post('/api/admin/apps', requireAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.json({ success:false, message:'App name required' });
  const doc = { name, description:description||'', publicKey:genPubKey(), secretKey:genSecKey(), active:true, createdAt:new Date().toISOString() };
  const result = await appsCol.insertOne(doc);
  auditLog(req.adminIP, 'CREATE_APP', { appName: name });
  res.json({ success:true, app:{ ...doc, _id:result.insertedId } });
});
app.delete('/api/admin/apps/:id', requireAdmin, async (req, res) => {
  const appDoc = await appsCol.findOne({ _id: new ObjectId(req.params.id) });
  await appsCol.deleteOne({ _id: new ObjectId(req.params.id) });
  auditLog(req.adminIP, 'DELETE_APP', { appId: req.params.id, appName: appDoc?.name });
  res.json({ success:true });
});
app.post('/api/admin/apps/:id/toggle', requireAdmin, async (req, res) => {
  const doc = await appsCol.findOne({ _id: new ObjectId(req.params.id) });
  if (!doc) return res.json({ success:false, message:'Not found' });
  const newActive = !doc.active;
  await appsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set:{ active: newActive } });
  auditLog(req.adminIP, newActive ? 'ENABLE_APP' : 'DISABLE_APP', { appId: req.params.id, appName: doc.name });
  res.json({ success:true, active: newActive });
});
app.post('/api/admin/apps/:id/rotate', requireAdmin, async (req, res) => {
  const newPub = genPubKey(), newSec = genSecKey();
  await appsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set:{ publicKey:newPub, secretKey:newSec } });
  auditLog(req.adminIP, 'ROTATE_APP_KEYS', { appId: req.params.id });
  res.json({ success:true, publicKey:newPub, secretKey:newSec });
});
// POST /api/admin/apps/:id/set-hmac — set or clear the HMAC signing secret
app.post('/api/admin/apps/:id/set-hmac', requireAdmin, async (req, res) => {
  const { hmacSecret } = req.body; // pass null/empty to disable
  const val = hmacSecret && String(hmacSecret).trim() ? String(hmacSecret).trim() : null;
  await appsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { hmacSecret: val } });
  auditLog(req.adminIP, val ? 'SET_HMAC_SECRET' : 'CLEAR_HMAC_SECRET', { appId: req.params.id });
  res.json({ success: true, hmacEnabled: !!val });
});

// ── ADMIN: KEYS ───────────────────────────────────────────────────────────────
app.get('/api/admin/keys', requireAdmin, async (req, res) => {
  const filter = req.query.appId ? { appId:req.query.appId } : {};
  const keys   = await keysCol.find(filter).sort({ createdAt:-1 }).toArray();
  res.json({ success:true, keys });
});
app.post('/api/admin/generate', requireAdmin, async (req, res) => {
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success:false, message:'Select an app first' });
  const appDoc = await appsCol.findOne({ _id: new ObjectId(appId) });
  if (!appDoc) return res.json({ success:false, message:'App not found' });
  count = Math.min(parseInt(count)||1, 500);
  const docs=[], keys=[];
  for (let i=0;i<count;i++) {
    const key=genKey();
    const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
    docs.push({ key, appId:String(appDoc._id), appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null, createdBy:'admin', hwidResets:[] });
    keys.push(key);
  }
  await keysCol.insertMany(docs);
  auditLog(req.adminIP, 'GENERATE_KEYS', { count, appName: appDoc.name, product, label });
  res.json({ success:true, keys });
});
app.delete('/api/admin/keys/:key', requireAdmin, async (req, res) => {
  await keysCol.deleteOne({ key:req.params.key });
  auditLog(req.adminIP, 'DELETE_KEY', { key: req.params.key });
  res.json({ success:true });
});
app.post('/api/admin/keys/:key/reset-hwid', requireAdmin, async (req, res) => {
  const froze = await recordHwidReset(req.params.key);
  await keysCol.updateOne({ key:req.params.key }, { $set:{ hwid:null, hwidRaw:null, uses:0 } });
  activeSessions.delete(req.params.key);
  log(null,req.params.key,'—','ADMIN','HWID_RESET','SUCCESS','admin','Admin reset HWID');
  auditLog(req.adminIP, 'RESET_HWID', { key: req.params.key, autoFrozen: froze });
  res.json({ success:true, auto_frozen: froze,
    message: froze ? `Key auto-frozen: exceeded ${HWID_RESET_LIMIT} HWID resets in ${HWID_RESET_WINDOW_MS/86400000} days` : 'HWID reset successfully' });
});
app.post('/api/admin/keys/:key/toggle', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Not found' });
  const s = doc.status==='active' ? 'banned' : 'active';
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:s } });
  if (s==='banned') {
    activeSessions.delete(req.params.key);
    log(null,req.params.key,'—','ADMIN','BAN','SUCCESS','admin','Admin banned key');
    webhookBanned(req.params.key, 'Banned by admin', req.adminIP, doc.appName);
  }
  auditLog(req.adminIP, s === 'banned' ? 'BAN_KEY' : 'UNBAN_KEY', { key: req.params.key });
  res.json({ success:true, status:s });
});
app.post('/api/admin/keys/:key/freeze', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Key not found' });
  if (doc.status==='banned') return res.json({ success:false, message:'Key is banned, cannot freeze' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'frozen' } });
  activeSessions.delete(req.params.key);
  log(null,req.params.key,'—','ADMIN','FREEZE','SUCCESS','admin','Key frozen');
  auditLog(req.adminIP, 'FREEZE_KEY', { key: req.params.key });
  res.json({ success:true, status:'frozen' });
});
app.post('/api/admin/keys/:key/unfreeze', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Key not found' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'active' } });
  log(null,req.params.key,'—','ADMIN','UNFREEZE','SUCCESS','admin','Key unfrozen');
  auditLog(req.adminIP, 'UNFREEZE_KEY', { key: req.params.key });
  res.json({ success:true, status:'active' });
});

// ── ADMIN: LOGS / BLOCKS / STATS ──────────────────────────────────────────────
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const filter={};
  if (req.query.result) filter.result=req.query.result;
  if (req.query.appId)  filter.appId=req.query.appId;
  const logs = await logsCol.find(filter).sort({ timestamp:-1 }).limit(500).toArray();
  res.json({ success:true, logs });
});
app.delete('/api/admin/logs', requireAdmin, async (req, res) => {
  await logsCol.deleteMany({});
  auditLog(req.adminIP, 'CLEAR_LOGS', {});
  res.json({ success:true });
});
app.get('/api/admin/blocks', requireAdmin, async (req, res) => {
  const blocks = await blocksCol.find({}).sort({ blockedAt:-1 }).toArray();
  res.json({ success:true, blocks });
});
app.delete('/api/admin/blocks/:ip', requireAdmin, async (req, res) => {
  await blocksCol.deleteOne({ ip:req.params.ip });
  failCounts.delete(req.params.ip);
  auditLog(req.adminIP, 'UNBLOCK_IP', { ip: req.params.ip });
  res.json({ success:true });
});
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const hr = new Date(Date.now()-3600000).toISOString();
  const [total, active, banned, used, recentAuths, hwidBlocks, totalApps, blockedIPs, totalResellers] = await Promise.all([
    keysCol.countDocuments({}),
    keysCol.countDocuments({ status:'active' }),
    keysCol.countDocuments({ status:'banned' }),
    keysCol.countDocuments({ uses:{ $gt:0 } }),
    logsCol.countDocuments({ timestamp:{ $gt:hr } }),
    logsCol.countDocuments({ result:'HWID_MISMATCH' }),
    appsCol.countDocuments({}),
    blocksCol.countDocuments({}),
    resellersCol.countDocuments({}),
  ]);
  res.json({ success:true, stats:{ total,active,banned,used,recentAuths,hwidBlocks,totalApps,blockedIPs,totalResellers } });
});

// Admin login brute-force tracking
const adminLoginFails   = new Map();
const ADMIN_LOCKOUT_FAILS = 10;
const ADMIN_LOCKOUT_MS    = 15 * 60 * 1000;

// ── ADMIN: HWID MISMATCHES ────────────────────────────────────────────────────
app.get('/api/admin/hwid-mismatches', requireAdmin, async (req, res) => {
  const mismatches = await logsCol.find({ result:'HWID_MISMATCH' }).sort({ timestamp:-1 }).limit(400).toArray();
  const enriched = await Promise.all(mismatches.map(async l => {
    const keyDoc = await keysCol.findOne({ key: l.key });
    return {
      ...l,
      keyStatus : keyDoc ? keyDoc.status    : 'deleted',
      keyLabel  : keyDoc ? (keyDoc.label  || '') : '',
      hwidBound : keyDoc ? (keyDoc.hwidRaw || '') : '',
      appName   : l.app_name || 'Unknown',
    };
  }));
  res.json({ success:true, mismatches:enriched });
});

// ── ADMIN: LOGIN (with 2FA support) ───────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  const ip  = getIP(req);
  const now = Date.now();
  const failRec = adminLoginFails.get(ip) || { count: 0, lastFail: 0 };
  if (failRec.count >= ADMIN_LOCKOUT_FAILS && now - failRec.lastFail < ADMIN_LOCKOUT_MS) {
    return res.status(429).json({ success: false, message: 'Too many failed attempts — wait 15 minutes' });
  }
  await authJitter();
  const doc   = await adminCol.findOne({ _id: 'admin' });
  const match = doc && safeCompare(hashString(req.body.password), doc.password);
  if (!match) {
    failRec.count++;
    failRec.lastFail = now;
    adminLoginFails.set(ip, failRec);
    auditLog(ip, 'ADMIN_LOGIN_FAIL', { reason: 'Wrong password' });
    return res.json({ success: false, message: 'Wrong password' });
  }
  // Password correct — check 2FA if enabled
  if (doc.twoFAEnabled) {
    const { totp } = req.body;
    if (!totp) {
      // Let client know 2FA is needed; don't issue token yet
      return res.json({ success: false, code: 'TOTP_REQUIRED', message: '2FA code required' });
    }
    if (!totpVerify(doc.twoFASecret, totp)) {
      failRec.count++;
      failRec.lastFail = now;
      adminLoginFails.set(ip, failRec);
      auditLog(ip, 'ADMIN_LOGIN_FAIL', { reason: 'Bad TOTP' });
      return res.json({ success: false, message: 'Invalid 2FA code' });
    }
  }
  adminLoginFails.delete(ip);
  const token = genSessionToken();
  await adminCol.updateOne({ _id: 'admin' }, { $set: { adminToken: token } });
  auditLog(ip, 'ADMIN_LOGIN_SUCCESS', {});
  res.json({ success: true, token });
});

app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.json({ success:false, message:'Min 6 chars' });
  const newToken = genSessionToken();
  await adminCol.updateOne({ _id:'admin' }, {
    $set: { password: hashString(newPassword), adminToken: newToken }
  });
  auditLog(req.adminIP, 'CHANGE_PASSWORD', {});
  res.json({ success:true, token: newToken });
});

// ── ADMIN: AUDIT LOG ──────────────────────────────────────────────────────────
// GET /api/admin/audit?limit=100&skip=0
app.get('/api/admin/audit', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const skip  = parseInt(req.query.skip) || 0;
  const [docs, total] = await Promise.all([
    adminAuditCol.find({}).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
    adminAuditCol.countDocuments({}),
  ]);
  res.json({ success: true, audit: docs, total });
});

// DELETE /api/admin/audit — clear audit log (this action itself is logged first)
app.delete('/api/admin/audit', requireAdmin, async (req, res) => {
  auditLog(req.adminIP, 'CLEAR_AUDIT_LOG', {});
  await adminAuditCol.deleteMany({});
  res.json({ success: true });
});

// ── ADMIN: CONFIG (country allowlist, etc.) ───────────────────────────────────
app.get('/api/admin/config', requireAdmin, async (req, res) => {
  const doc = await adminCol.findOne({ _id: 'admin' }, { projection: { allowedCountries: 1, twoFAEnabled: 1 } });
  res.json({ success: true, allowedCountries: doc?.allowedCountries || [], twoFAEnabled: !!doc?.twoFAEnabled });
});

// POST /api/admin/config { allowedCountries: ['US','CA','GB'] }  — empty array = disabled (all allowed)
app.post('/api/admin/config', requireAdmin, async (req, res) => {
  const { allowedCountries } = req.body;
  if (!Array.isArray(allowedCountries))
    return res.json({ success: false, message: 'allowedCountries must be an array of ISO-2 country codes' });
  const clean = allowedCountries.map(c => String(c).toUpperCase().trim()).filter(c => /^[A-Z]{2}$/.test(c));
  await adminCol.updateOne({ _id: 'admin' }, { $set: { allowedCountries: clean } });
  auditLog(req.adminIP, 'UPDATE_COUNTRY_ALLOWLIST', { allowedCountries: clean });
  res.json({ success: true, allowedCountries: clean,
    message: clean.length ? `Auth restricted to: ${clean.join(', ')}` : 'Country allowlist disabled (all regions allowed)' });
});

// ── ADMIN: RESELLERS ──────────────────────────────────────────────────────────
const DEFAULT_PERMISSIONS = { viewKeys:false, viewHWID:false, viewIP:false, viewLogs:false, viewBlocks:false, generateKeys:false, banKeys:false, freezeKeys:false, resetHWID:false, deleteKeys:false, viewStats:false };

app.get('/api/admin/resellers', requireAdmin, async (req, res) => {
  const docs = await resellersCol.find({}).sort({ createdAt:-1 }).toArray();
  const safe = docs.map(({ password, ...r }) => r);
  res.json({ success:true, resellers:safe });
});
app.post('/api/admin/resellers', requireAdmin, async (req, res) => {
  const { username, password, displayName, keyQuota, permissions, notes, allowedApps } = req.body;
  if (!username||!password) return res.json({ success:false, message:'Username and password required' });
  if (password.length<6) return res.json({ success:false, message:'Password must be at least 6 characters' });
  const perms = Object.assign({}, DEFAULT_PERMISSIONS, permissions||{});
  const doc = { username:username.toLowerCase().trim(), password:hashString(password), displayName:displayName||username, active:true, keyQuota:parseInt(keyQuota)||0, keysGenerated:0, permissions:perms, allowedApps:Array.isArray(allowedApps)?allowedApps:[], notes:notes||'', sessionToken:null, createdAt:new Date().toISOString(), lastLogin:null };
  try {
    const result = await resellersCol.insertOne(doc);
    const { password:p, ...safe } = { ...doc, _id:result.insertedId };
    auditLog(req.adminIP, 'CREATE_RESELLER', { username: doc.username });
    res.json({ success:true, reseller:safe });
  } catch(e) {
    res.json({ success:false, message: e.message.includes('duplicate') ? 'Username already exists' : e.message });
  }
});
app.patch('/api/admin/resellers/:id', requireAdmin, async (req, res) => {
  const { displayName, password, keyQuota, permissions, notes, active, allowedApps } = req.body;
  const update = {};
  if (displayName  !== undefined) update.displayName  = displayName;
  if (notes        !== undefined) update.notes        = notes;
  if (keyQuota     !== undefined) update.keyQuota     = parseInt(keyQuota)||0;
  if (active       !== undefined) update.active       = !!active;
  if (permissions  !== undefined) update.permissions  = Object.assign({}, DEFAULT_PERMISSIONS, permissions);
  if (allowedApps  !== undefined) update.allowedApps  = Array.isArray(allowedApps) ? allowedApps : [];
  if (password && password.length>=6) update.password = hashString(password);
  const result = await resellersCol.updateOne({ _id:new ObjectId(req.params.id) }, { $set:update });
  if (!result.matchedCount) return res.json({ success:false, message:'Reseller not found' });
  auditLog(req.adminIP, 'EDIT_RESELLER', { resellerId: req.params.id });
  res.json({ success:true });
});
app.delete('/api/admin/resellers/:id', requireAdmin, async (req, res) => {
  const doc = await resellersCol.findOne({ _id: new ObjectId(req.params.id) });
  await resellersCol.deleteOne({ _id:new ObjectId(req.params.id) });
  auditLog(req.adminIP, 'DELETE_RESELLER', { resellerId: req.params.id, username: doc?.username });
  res.json({ success:true });
});
app.post('/api/admin/resellers/:id/toggle', requireAdmin, async (req, res) => {
  const doc = await resellersCol.findOne({ _id:new ObjectId(req.params.id) });
  if (!doc) return res.json({ success:false, message:'Not found' });
  const newActive = !doc.active;
  await resellersCol.updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ active: newActive } });
  auditLog(req.adminIP, newActive ? 'ENABLE_RESELLER' : 'SUSPEND_RESELLER', { username: doc.username });
  res.json({ success:true, active: newActive });
});

// ── RESELLER AUTH ─────────────────────────────────────────────────────────────
app.post('/api/reseller/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username||!password) return res.json({ success:false, message:'Username and password required' });
  const doc = await resellersCol.findOne({ username:username.toLowerCase().trim() });
  if (!doc||!safeCompare(hashString(password), doc.password)) return res.json({ success:false, message:'Invalid credentials' });
  if (!doc.active) return res.json({ success:false, message:'Your reseller account is suspended.' });
  const token = genSessionToken();
  await resellersCol.updateOne({ _id:doc._id }, { $set:{ sessionToken:token, lastLogin:new Date().toISOString() } });
  res.json({ success:true, token, reseller:{ username:doc.username, displayName:doc.displayName, permissions:doc.permissions, keyQuota:doc.keyQuota, keysGenerated:doc.keysGenerated } });
});
app.post('/api/reseller/logout', requireReseller, async (req, res) => {
  await resellersCol.updateOne({ _id:req.reseller._id }, { $set:{ sessionToken:null } });
  res.json({ success:true });
});

// ── RESELLER: STATS ───────────────────────────────────────────────────────────
app.get('/api/reseller/stats', requireReseller, async (req, res) => {
  const r = req.reseller;
  const [totalKeys, activeKeys, bannedKeys] = await Promise.all([
    keysCol.countDocuments({ createdBy:r.username }),
    keysCol.countDocuments({ createdBy:r.username, status:'active' }),
    keysCol.countDocuments({ createdBy:r.username, status:'banned' }),
  ]);
  res.json({ success:true, stats:{ totalKeys, activeKeys, bannedKeys, keyQuota:r.keyQuota, keysGenerated:r.keysGenerated, slotsLeft:r.keyQuota>0?Math.max(0,r.keyQuota-r.keysGenerated):null } });
});

// ── RESELLER: KEYS ────────────────────────────────────────────────────────────
app.get('/api/reseller/keys', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const allowed = req.reseller.allowedApps || [];
  const filter = { createdBy:req.reseller.username };
  if (req.query.appId) {
    if (allowed.length > 0 && !allowed.includes(String(req.query.appId))) return res.status(403).json({ success:false, message:'You do not have access to this app' });
    filter.appId = req.query.appId;
  } else if (allowed.length > 0) {
    filter.appId = { $in: allowed };
  }
  const docs   = await keysCol.find(filter).sort({ createdAt:-1 }).toArray();
  const perm   = req.reseller.permissions;
  const masked = docs.map(k => { const out={...k}; if (!perm.viewHWID) { delete out.hwid; delete out.hwidRaw; } return out; });
  res.json({ success:true, keys:masked });
});
app.post('/api/reseller/generate', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.generateKeys) return res.status(403).json({ success:false, message:'Access denied' });
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success:false, message:'Select an app first' });
  const allowed = req.reseller.allowedApps || [];
  if (allowed.length > 0 && !allowed.includes(String(appId))) return res.status(403).json({ success:false, message:'You do not have access to this app' });
  count = Math.min(parseInt(count)||1, 100);
  if (req.reseller.keyQuota > 0) {
    const remaining = req.reseller.keyQuota - req.reseller.keysGenerated;
    if (count > remaining) return res.json({ success:false, message:`Quota exceeded. You have ${remaining} key slot(s) remaining.` });
  }
  const appDoc = await appsCol.findOne({ _id:new ObjectId(appId) });
  if (!appDoc) return res.json({ success:false, message:'App not found' });
  const docs=[], keys=[];
  for (let i=0;i<count;i++) {
    const key=genKey();
    const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
    docs.push({ key, appId:String(appDoc._id), appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null, createdBy:req.reseller.username, hwidResets:[] });
    keys.push(key);
  }
  await keysCol.insertMany(docs);
  await resellersCol.updateOne({ _id:req.reseller._id }, { $inc:{ keysGenerated:count } });
  res.json({ success:true, keys });
});

// ── RESELLER: KEY ACTIONS ─────────────────────────────────────────────────────
async function resellerOwnsKey(reseller, key) {
  return keysCol.findOne({ key, createdBy:reseller.username });
}
app.post('/api/reseller/keys/:key/toggle', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.banKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  const s = doc.status==='active'?'banned':'active';
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:s } });
  if (s==='banned') activeSessions.delete(req.params.key);
  res.json({ success:true, status:s });
});
app.post('/api/reseller/keys/:key/freeze', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.freezeKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  if (doc.status==='banned') return res.json({ success:false, message:'Key is banned, cannot freeze' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'frozen' } });
  activeSessions.delete(req.params.key);
  res.json({ success:true, status:'frozen' });
});
app.post('/api/reseller/keys/:key/unfreeze', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.freezeKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'active' } });
  res.json({ success:true, status:'active' });
});
app.post('/api/reseller/keys/:key/reset-hwid', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.resetHWID) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  const froze = await recordHwidReset(req.params.key);
  await keysCol.updateOne({ key:req.params.key }, { $set:{ hwid:null, hwidRaw:null, uses:0 } });
  activeSessions.delete(req.params.key);
  res.json({ success:true, auto_frozen: froze });
});
app.delete('/api/reseller/keys/:key', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.deleteKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  await keysCol.deleteOne({ key:req.params.key });
  res.json({ success:true });
});

// ── RESELLER: LOGS / BLOCKS / APPS ───────────────────────────────────────────
app.get('/api/reseller/logs', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewLogs) return res.status(403).json({ success:false, message:'Access denied' });
  const myKeys   = await keysCol.find({ createdBy:req.reseller.username }, { projection:{ key:1 } }).toArray();
  const myKeySet = new Set(myKeys.map(k=>k.key));
  const filter   = {};
  if (req.query.result) filter.result = req.query.result;
  const docs   = await logsCol.find(filter).sort({ timestamp:-1 }).limit(300).toArray();
  const perm   = req.reseller.permissions;
  const masked = docs.filter(l=>myKeySet.has(l.key)).map(l => {
    const out={...l};
    if (!perm.viewIP)   out.ip='—';
    if (!perm.viewHWID) out.hwid='—';
    return out;
  });
  res.json({ success:true, logs:masked });
});
app.get('/api/reseller/blocks', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewBlocks) return res.status(403).json({ success:false, message:'Access denied' });
  const docs   = await blocksCol.find({}).sort({ blockedAt:-1 }).toArray();
  const perm   = req.reseller.permissions;
  const masked = docs.map(b => perm.viewIP ? b : { ...b, ip:'—' });
  res.json({ success:true, blocks:masked });
});
app.get('/api/reseller/apps', requireReseller, async (req, res) => {
  const allowed = req.reseller.allowedApps || [];
  const filter  = { active:true };
  if (allowed.length > 0) filter._id = { $in: allowed.map(id => { try { return new ObjectId(id); } catch { return null; } }).filter(Boolean) };
  const docs = await appsCol.find(filter).sort({ createdAt:-1 }).toArray();
  const safe = docs.map(({ secretKey, ...a }) => a);
  res.json({ success:true, apps:safe });
});

// ── BACKUP / RESTORE ──────────────────────────────────────────────────────────
app.get('/api/admin/backup', requireAdmin, async (req, res) => {
  const [apps, keys, resellers, blocks, admin] = await Promise.all([
    appsCol.find({}).toArray(),
    keysCol.find({}).toArray(),
    resellersCol.find({}).toArray(),
    blocksCol.find({}).toArray(),
    adminCol.find({}).toArray(),
  ]);
  auditLog(req.adminIP, 'BACKUP_EXPORT', {});
  res.setHeader('Content-Disposition', `attachment; filename="backup-${Date.now()}.json"`);
  res.json({ version:2, exportedAt:new Date().toISOString(), apps, keys, resellers, blocks, admin });
});
app.post('/api/admin/restore', requireAdmin, async (req, res) => {
  const { apps=[], keys=[], resellers=[], blocks=[], admin=[] } = req.body;
  async function insertNew(col, docs) {
    let inserted=0, skipped=0;
    for (const doc of docs) {
      const exists = await col.findOne({ _id:doc._id });
      if (exists) { skipped++; continue; }
      try { await col.insertOne(doc); inserted++; } catch {}
    }
    return { inserted, skipped };
  }
  const [a,k,r,b,ad] = await Promise.all([
    insertNew(appsCol, apps), insertNew(keysCol, keys),
    insertNew(resellersCol, resellers), insertNew(blocksCol, blocks),
    insertNew(adminCol, admin),
  ]);
  auditLog(req.adminIP, 'BACKUP_RESTORE', { apps: a, keys: k });
  res.json({ success:true, restored:{ apps:a, keys:k, resellers:r, blocks:b, admin:ad } });
});

// ── DETECTION REPORTING ───────────────────────────────────────────────────────
app.post('/api/detection', rateLimit, async (req, res) => {
  const publicKey = req.headers['x-public-key'] || req.body.public_key;
  const ip        = await resolveRealIP(req);
  if (!publicKey || typeof publicKey !== 'string')
    return res.json({ success: false, code: 'NO_PUBLIC_KEY' });
  const appDoc = await appsCol.findOne({ publicKey });
  if (!appDoc) return res.json({ success: false, code: 'INVALID_PUBLIC_KEY' });
  const { key='', trigger='UNKNOWN', processes=[], status='WARNED', hwid='', real_ip='' } = req.body;
  const resolvedIP = real_ip || ip;
  const doc = {
    appId: String(appDoc._id), appName: appDoc.name,
    key: key||'—', hwid: hwid||'—', ip: resolvedIP,
    trigger, processes, status, timestamp: new Date().toISOString(),
  };
  await detectionsCol.insertOne(doc);
  if (status === 'BSOD_TRIGGERED' && key) {
    await keysCol.updateOne({ key, appId: String(appDoc._id) }, { $set: { status: 'banned' } });
    activeSessions.delete(key);
    webhookBanned(key, `Anti-cheat detection: ${trigger}`, resolvedIP, appDoc.name);
    log(appDoc._id, key, hwid, appDoc.name, 'DETECTION', 'BANNED', resolvedIP,
        `Auto-banned: ${trigger} — ${processes.map(p=>p.name).join(', ')}`);
  }
  res.json({ success: true, code: 'LOGGED' });
});

// GET /api/admin/detections
app.get('/api/admin/detections', requireAdmin, async (req, res) => {
  const filter = {};
  if (req.query.status)  filter.status  = req.query.status;
  if (req.query.trigger) filter.trigger = req.query.trigger;
  if (req.query.key)     filter.key     = req.query.key;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const skip  = parseInt(req.query.skip) || 0;
  const [docs, total] = await Promise.all([
    detectionsCol.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
    detectionsCol.countDocuments(filter),
  ]);
  res.json({ success: true, detections: docs, total });
});
app.delete('/api/admin/detections/:id', requireAdmin, async (req, res) => {
  await detectionsCol.deleteOne({ _id: new ObjectId(req.params.id) });
  res.json({ success: true });
});
app.delete('/api/admin/detections', requireAdmin, async (req, res) => {
  const result = await detectionsCol.deleteMany({});
  auditLog(req.adminIP, 'CLEAR_DETECTIONS', { deleted: result.deletedCount });
  res.json({ success: true, deleted: result.deletedCount });
});

// ── DISCORD BOT API ───────────────────────────────────────────────────────────
function requireBot(req, res, next) {
  const token = req.headers['x-bot-token'];
  if (!token || token !== BOT_SECRET)
    return res.status(401).json({ success: false, message: 'Invalid bot token' });
  next();
}

app.get('/api/bot/stats', requireBot, async (req, res) => {
  const hr = new Date(Date.now() - 3600000).toISOString();
  const [total, active, banned, frozen, used, recentAuths, hwidBlocks, totalApps, blockedIPs, totalResellers] = await Promise.all([
    keysCol.countDocuments({}),
    keysCol.countDocuments({ status: 'active' }),
    keysCol.countDocuments({ status: 'banned' }),
    keysCol.countDocuments({ status: 'frozen' }),
    keysCol.countDocuments({ uses: { $gt: 0 } }),
    logsCol.countDocuments({ timestamp: { $gt: hr } }),
    logsCol.countDocuments({ result: 'HWID_MISMATCH' }),
    appsCol.countDocuments({}),
    blocksCol.countDocuments({}),
    resellersCol.countDocuments({}),
  ]);
  res.json({ success: true, stats: { total, active, banned, frozen, used, recentAuths, hwidBlocks, totalApps, blockedIPs, totalResellers } });
});
app.get('/api/bot/apps', requireBot, async (req, res) => {
  const apps = await appsCol.find({}).sort({ createdAt: -1 }).toArray();
  res.json({ success: true, apps: apps.map(({ secretKey, ...a }) => a) });
});
app.post('/api/bot/genkey', requireBot, async (req, res) => {
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success: false, message: 'appId required' });
  const appDoc = await appsCol.findOne({ _id: new ObjectId(appId) });
  if (!appDoc) return res.json({ success: false, message: 'App not found' });
  count = Math.min(parseInt(count) || 1, 500);
  const docs=[], keys=[];
  for (let i=0;i<count;i++) {
    const key=genKey();
    const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
    docs.push({ key, appId:String(appDoc._id), appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null, createdBy:'discord-bot', hwidResets:[] });
    keys.push(key);
  }
  await keysCol.insertMany(docs);
  res.json({ success: true, keys });
});
app.get('/api/bot/keyinfo/:key', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  res.json({ success: true, key: doc });
});
app.get('/api/bot/keys', requireBot, async (req, res) => {
  const filter = req.query.appId ? { appId: req.query.appId } : {};
  const limit  = Math.min(parseInt(req.query.limit) || 25, 100);
  const keys   = await keysCol.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
  const total  = await keysCol.countDocuments(filter);
  res.json({ success: true, keys, total });
});
app.post('/api/bot/keys/:key/ban', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  if (doc.status === 'banned') return res.json({ success: true, status: 'banned', note: 'Already banned' });
  await keysCol.updateOne({ key: req.params.key }, { $set: { status: 'banned' } });
  activeSessions.delete(req.params.key);
  webhookBanned(req.params.key, 'Banned via Discord bot', 'discord-bot', doc.appName);
  log(null, req.params.key, '—', 'BOT', 'BAN', 'SUCCESS', 'discord-bot');
  res.json({ success: true, status: 'banned' });
});
app.post('/api/bot/keys/:key/unban', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  await keysCol.updateOne({ key: req.params.key }, { $set: { status: 'active' } });
  log(null, req.params.key, '—', 'BOT', 'UNBAN', 'SUCCESS', 'discord-bot');
  res.json({ success: true, status: 'active' });
});
app.post('/api/bot/keys/:key/freeze', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  if (doc.status === 'banned') return res.json({ success: false, message: 'Key is banned, cannot freeze' });
  await keysCol.updateOne({ key: req.params.key }, { $set: { status: 'frozen' } });
  activeSessions.delete(req.params.key);
  res.json({ success: true, status: 'frozen' });
});
app.post('/api/bot/keys/:key/unfreeze', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  await keysCol.updateOne({ key: req.params.key }, { $set: { status: 'active' } });
  res.json({ success: true, status: 'active' });
});
app.post('/api/bot/keys/:key/reset-hwid', requireBot, async (req, res) => {
  const doc = await keysCol.findOne({ key: req.params.key });
  if (!doc) return res.json({ success: false, message: 'Key not found' });
  const froze = await recordHwidReset(req.params.key);
  await keysCol.updateOne({ key: req.params.key }, { $set: { hwid: null, hwidRaw: null, uses: 0 } });
  activeSessions.delete(req.params.key);
  res.json({ success: true, auto_frozen: froze });
});
app.delete('/api/bot/keys/:key', requireBot, async (req, res) => {
  const result = await keysCol.deleteOne({ key: req.params.key });
  if (!result.deletedCount) return res.json({ success: false, message: 'Key not found' });
  activeSessions.delete(req.params.key);
  res.json({ success: true });
});
app.get('/api/bot/logs', requireBot, async (req, res) => {
  const filter = {};
  if (req.query.result) filter.result = req.query.result;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const logs  = await logsCol.find(filter).sort({ timestamp: -1 }).limit(limit).toArray();
  res.json({ success: true, logs });
});
app.get('/api/bot/blocks', requireBot, async (req, res) => {
  const blocks = await blocksCol.find({}).sort({ blockedAt: -1 }).toArray();
  res.json({ success: true, blocks });
});
app.delete('/api/bot/blocks/:ip', requireBot, async (req, res) => {
  await blocksCol.deleteOne({ ip: req.params.ip });
  failCounts.delete(req.params.ip);
  res.json({ success: true });
});

// ── START ─────────────────────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  BoostEmpire KeyAuth  |  http://localhost:${PORT}`);
    console.log(`  Storage: MongoDB Atlas (persistent)\n`);
    startKeepAlive();
  });
}).catch(err => {
  console.error('[FATAL] MongoDB connection failed:', err.message);
  process.exit(1);
});
