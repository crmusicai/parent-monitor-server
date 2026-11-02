/**
 * Parent Monitor Server — multi-tenant registry, pairing, heartbeat/events,
 * and WebRTC signalling relay for the Parental Monitoring App.
 * v2 ("Private Call", ../SPEC-V2.md): generalized sessions (listen/camera/call),
 * chat, media files, and invite-link pairing on top of the v1 protocol.
 *
 * Source of truth: ../SPEC.md + ../SPEC-V2.md
 *
 * Run: PORT=8080 node server.js
 * Storage: data.json next to this file (env DATA_FILE overrides), atomic writes.
 * Tenancy rule: every child belongs to exactly one parentId and EVERY
 * read/write/signalling path verifies it. Cross-parent access -> 403/404.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATA_FILE = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : path.join(__dirname, 'data.json');

const PAIRING_TTL_MS = 15 * 60 * 1000;
const EVENTS_CAP = 200;       // stored per child
const EVENTS_RETURN = 100;    // returned by GET events
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // invite link lifetime
const CHAT_CAP = 200;                            // messages kept per parent-child pair
const MEDIA_MAX_BYTES = 10 * 1024 * 1024;        // media upload cap (413 above)
const MEDIA_MAX_FILES = 200;                     // stored media files kept (oldest pruned)
// Ring timeout for unaccepted calls (45 s per SPEC-V2; env override exists for tests).
const RING_TIMEOUT_MS = parseInt(process.env.RING_TIMEOUT_MS || '45000', 10);
const MEDIA_DIR = path.join(path.dirname(DATA_FILE), 'media');

// ---------------------------------------------------------------- storage
function blankData() {
  return { parents: [], tokens: {}, pairingCodes: {}, children: [], invites: {}, chats: {}, media: {} };
}
function loadData() {
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!d || typeof d !== 'object') return blankData();
    return {
      parents: Array.isArray(d.parents) ? d.parents : [],
      tokens: d.tokens && typeof d.tokens === 'object' ? d.tokens : {},
      pairingCodes: d.pairingCodes && typeof d.pairingCodes === 'object' ? d.pairingCodes : {},
      children: Array.isArray(d.children) ? d.children : [],
      invites: d.invites && typeof d.invites === 'object' ? d.invites : {},
      chats: d.chats && typeof d.chats === 'object' ? d.chats : {},
      media: d.media && typeof d.media === 'object' ? d.media : {},
    };
  } catch { return blankData(); }
}
const data = loadData();
function save() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE); // atomic replace
}

// ---------------------------------------------------------------- live state
const liveChildren = new Map();  // childId -> ws
const liveParents = new Map();   // parentId -> Set<ws>
const sessions = new Map();      // sessionId -> {id, parentId, childId, parentWs, childWs, sig, dbg}
const childDebug = new Map();    // childId -> [debug strings] (diagnostics, memory-only)
const parentDebug = new Map();   // parentId -> [debug strings] (diagnostics, memory-only)
const lastSessions = [];         // archived session summaries after close (diagnostics)

// ---------------------------------------------------------------- helpers
function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => { body += d; if (body.length > 1_000_000) req.destroy(); });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
// Raw-body reader for media uploads: drains the request fully even when it
// exceeds the cap (so the client gets a clean 413 instead of a hang).
function readRawBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0, tooLarge = false;
    req.on('data', d => {
      total += d.length;
      if (total > cap) { tooLarge = true; chunks.length = 0; return; }
      if (!tooLarge) chunks.push(d);
    });
    req.on('end', () => resolve({ buf: tooLarge ? null : Buffer.concat(chunks), size: total, tooLarge }));
    req.on('error', reject);
  });
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}
function checkPassword(password, parent) {
  try {
    const h = crypto.scryptSync(String(password), parent.salt, 64);
    const stored = Buffer.from(parent.passwordHash, 'hex');
    return h.length === stored.length && crypto.timingSafeEqual(h, stored);
  } catch { return false; }
}
function authParent(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const parentId = token ? data.tokens[token] : null;
  if (!parentId) return null;
  return data.parents.find(p => p.id === parentId) || null;
}
function authChild(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  return data.children.find(c => c.deviceToken === token) || null;
}
function childView(c) {
  return {
    id: c.id,
    name: c.name,
    model: c.model,
    online: liveChildren.has(c.id),
    lastSeen: c.lastSeen || null,
    battery: c.battery ?? null,
    permissions: c.permissions || null,
    lastLocation: c.lastLocation || null,
  };
}
function addEvent(child, type, detail) {
  child.events = child.events || [];
  child.events.push({ ts: new Date().toISOString(), type: String(type), detail: detail == null ? '' : String(detail) });
  if (child.events.length > EVENTS_CAP) child.events = child.events.slice(-EVENTS_CAP);
}
function findOwnChild(parent, id) {
  // Missing OR someone else's child both look the same to the caller: 404.
  const c = data.children.find(x => x.id === id);
  if (!c || c.parentId !== parent.id) return null;
  return c;
}
function sendWs(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}
function archiveSession(session) {
  lastSessions.push({ id: session.id.slice(0, 8), kind: session.kind || 'listen', childId: session.childId,
    sig: session.sig, dbg: session.dbg, closedAt: new Date().toISOString() });
  while (lastSessions.length > 5) lastSessions.shift();
}
function closeSession(session, notifyWsList, reason) {
  if (session.ringTimer) { clearTimeout(session.ringTimer); session.ringTimer = null; }
  sessions.delete(session.id);
  archiveSession(session);
  for (const peer of notifyWsList || []) {
    sendWs(peer, { type: 'session_closed', sessionId: session.id, reason: reason || 'closed' });
  }
}
function createSession(fields) {
  const session = Object.assign({
    id: crypto.randomBytes(16).toString('hex'),
    kind: 'listen', state: 'active', media: null, initiatorRole: null, ringTimer: null,
    parentWs: null, childWs: null,
    sig: { offer: 0, answer: 0, childIce: {}, parentIce: {} }, dbg: [],
  }, fields);
  sessions.set(session.id, session);
  return session;
}
// Sockets that are parties to a session. For a child-initiated call that has
// not been accepted yet, parentWs is unbound: every live parent socket is a
// potential party (they all got the invite and any of them may accept).
function peerSockets(session, excludeWs) {
  const out = new Set();
  if (session.parentWs) out.add(session.parentWs);
  else if (session.kind === 'call') {
    const set = liveParents.get(session.parentId);
    if (set) for (const w of set) out.add(w);
  }
  if (session.childWs) out.add(session.childWs);
  if (excludeWs) out.delete(excludeWs);
  return [...out];
}
// Busy rule (SPEC-V2 §1b): a parent or child already in ANY session
// (listen/camera/call) cannot join a new one.
function partyBusy(parentId, childId) {
  for (const s of sessions.values()) {
    if (s.parentId === parentId || s.childId === childId) return true;
  }
  return false;
}
function armRingTimer(session) {
  session.ringTimer = setTimeout(() => {
    if (!sessions.has(session.id)) return;
    closeSession(session, peerSockets(session), 'timeout');
  }, RING_TIMEOUT_MS);
  if (session.ringTimer.unref) session.ringTimer.unref();
}
function findInvite(pred) {
  return Object.values(data.invites).find(pred) || null;
}
function chatKey(parentId, childId) { return `${parentId}:${childId}`; }
function inviteUrl(req, token) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  return `${proto}://${host}/join/${token}`;
}
function inviteView(req, inv) {
  return { token: inv.token, code: inv.code, url: inviteUrl(req, inv.token), expiresAt: new Date(inv.expiresAt).toISOString() };
}

// ---------------------------------------------------------------- REST
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    // ---- server
    if (p === '/health' && req.method === 'GET') {
      return json(res, 200, { ok: true, parents: data.parents.length, children: data.children.length, online: liveChildren.size });
    }

    // ---- diagnostics (counts + state words only; no SDP bodies, no IPs)
    if (p === '/debug' && req.method === 'GET') {
      return json(res, 200, {
        ok: true,
        parents: data.parents.length, children: data.children.length, online: liveChildren.size,
        sessions: [...sessions.values()].map(s => ({
          id: s.id.slice(0, 8), kind: s.kind, state: s.state, childId: s.childId, sig: s.sig, dbg: s.dbg,
        })),
        lastSessions,
        childDebug: Object.fromEntries(childDebug),
        parentDebug: Object.fromEntries(parentDebug),
      });
    }

    // ---- child APK download (public; the file lives next to server.js)
    if (p === '/app.apk' && req.method === 'GET') {
      const apkPath = path.join(__dirname, 'PrivateCall.apk');
      if (!fs.existsSync(apkPath)) return json(res, 404, { error: 'app file not found' });
      const bytes = fs.readFileSync(apkPath);
      res.writeHead(200, { 'Content-Type': 'application/vnd.android.package-archive', 'Content-Length': bytes.length });
      return res.end(bytes);
    }

    // ---- invite landing page (public, SPEC-V2 §4)
    const joinMatch = p.match(/^\/join\/([^/]+)$/);
    if (joinMatch && req.method === 'GET') {
      const token = decodeURIComponent(joinMatch[1]);
      const inv = findInvite(i => i.token === token);
      const valid = !!inv && !inv.used && Date.now() <= inv.expiresAt;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      if (!valid) {
        return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Private Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Private Call</h1>
<p>This invite link is invalid or has expired.</p>
<p>Please ask the person who sent it to create a new link.</p>
</body></html>`);
      }
      const apkReady = fs.existsSync(path.join(__dirname, 'PrivateCall.apk'));
      const intentUrl = `intent://pair?token=${inv.token}#Intent;scheme=privatecall;package=com.crdigital.systemservice;end`;
      return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Private Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Private Call</h1>
<p>You have been invited to install <b>Private Call</b>.</p>
<p><a href="/app.apk" style="display:inline-block;background:#12805c;color:#fff;padding:16px 32px;border-radius:10px;text-decoration:none;font-size:20px">Download App</a></p>
${apkReady ? '' : '<p><i>Note: the app file is not available on the server yet.</i></p>'}
<p>After installing, tap below to connect automatically:</p>
<p><a href="${intentUrl}" style="display:inline-block;background:#1565c0;color:#fff;padding:16px 32px;border-radius:10px;text-decoration:none;font-size:20px">Open in App</a></p>
<p>Or open the app and enter this code:</p>
<p style="font-size:44px;font-weight:bold;letter-spacing:8px">${inv.code}</p>
</body></html>`);
    }

    // ---- parent auth
    if (p === '/api/parents/register' && req.method === 'POST') {
      const { name, phone, password } = await readBody(req).catch(() => null) || {};
      if (!name || !phone || !password) return json(res, 400, { error: 'name, phone and password required' });
      if (String(password).length < 6) return json(res, 400, { error: 'password must be at least 6 characters' });
      if (data.parents.some(x => x.phone === String(phone))) return json(res, 409, { error: 'phone already registered' });
      const salt = crypto.randomBytes(16).toString('hex');
      const parent = {
        id: crypto.randomBytes(8).toString('hex'),
        name: String(name), phone: String(phone),
        salt, passwordHash: hashPassword(password, salt),
        createdAt: new Date().toISOString(),
      };
      data.parents.push(parent);
      const token = newToken();
      data.tokens[token] = parent.id;
      save();
      return json(res, 201, { parentId: parent.id, token });
    }
    if (p === '/api/parents/login' && req.method === 'POST') {
      const { phone, password } = await readBody(req).catch(() => null) || {};
      const parent = data.parents.find(x => x.phone === String(phone || ''));
      if (!parent || !checkPassword(password || '', parent)) return json(res, 401, { error: 'bad credentials' });
      const token = newToken();
      data.tokens[token] = parent.id;
      save();
      return json(res, 200, { token });
    }
    if (p === '/api/parents/me' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, { parentId: parent.id, name: parent.name, phone: parent.phone });
    }

    // ---- pairing codes (parent)
    if (p === '/api/pairing-codes' && req.method === 'POST') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      // One active code per parent: a new code invalidates the parent's old one.
      for (const [code, rec] of Object.entries(data.pairingCodes)) {
        if (rec.parentId === parent.id) delete data.pairingCodes[code];
      }
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); } while (data.pairingCodes[code]);
      const expiresAt = new Date(Date.now() + PAIRING_TTL_MS).toISOString();
      data.pairingCodes[code] = { parentId: parent.id, expiresAt: Date.now() + PAIRING_TTL_MS };
      save();
      return json(res, 200, { code, expiresAt });
    }

    // ---- invite link (parent, SPEC-V2 §4): one active invite per parent
    if (p === '/api/invite' && req.method === 'POST') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); }
      while (data.pairingCodes[code] || findInvite(i => i.code === code && !i.used));
      const inv = {
        token: crypto.randomBytes(16).toString('hex'), // 32 hex chars
        code,
        parentId: parent.id,
        expiresAt: Date.now() + INVITE_TTL_MS,
        used: false,
        createdAt: new Date().toISOString(),
      };
      data.invites[parent.id] = inv; // create/replace
      save();
      return json(res, 200, inviteView(req, inv));
    }
    if (p === '/api/invite' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const inv = data.invites[parent.id];
      if (!inv || inv.used || Date.now() > inv.expiresAt) return json(res, 200, null);
      return json(res, 200, inviteView(req, inv));
    }
    if (p === '/api/invite' && req.method === 'DELETE') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      delete data.invites[parent.id];
      save();
      return json(res, 200, { ok: true });
    }

    // ---- child pairing (public; credential = v1 pairing code, invite code,
    //      or invite token — SPEC-V2 §4). All are single-use.
    if (p === '/api/children/pair' && req.method === 'POST') {
      const { code, token, name, model } = await readBody(req).catch(() => null) || {};
      let parentId = null;
      if (token) {
        const inv = findInvite(i => i.token === String(token));
        if (!inv || inv.used || Date.now() > inv.expiresAt) {
          return json(res, 400, { error: 'invalid or expired invite' });
        }
        inv.used = true; // single use
        parentId = inv.parentId;
      } else if (code) {
        const rec = data.pairingCodes[String(code)];
        if (rec) {
          if (Date.now() > rec.expiresAt) {
            delete data.pairingCodes[String(code)]; save();
            return json(res, 410, { error: 'pairing code expired' });
          }
          delete data.pairingCodes[String(code)]; // single use
          parentId = rec.parentId;
        } else {
          const inv = findInvite(i => i.code === String(code));
          if (!inv || inv.used || Date.now() > inv.expiresAt) {
            return json(res, 400, { error: 'invalid pairing code' });
          }
          inv.used = true; // single use
          parentId = inv.parentId;
        }
      }
      if (!parentId) return json(res, 400, { error: 'invalid pairing code' });
      const child = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId,
        name: name ? String(name) : (model ? String(model) : 'Child'),
        model: model ? String(model) : '',
        deviceToken: newToken(),
        createdAt: new Date().toISOString(),
        lastSeen: null, battery: null, permissions: null, lastLocation: null, appVersion: null,
        events: [],
      };
      data.children.push(child);
      save();
      return json(res, 201, { childId: child.id, deviceToken: child.deviceToken });
    }

    // ---- child heartbeat + events (deviceToken auth)
    if (p === '/api/children/heartbeat' && req.method === 'POST') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => null);
      if (!body) return json(res, 400, { error: 'bad json' });
      const prevPerms = child.permissions || null;
      if (typeof body.battery === 'number') child.battery = body.battery;
      if (body.permissions && typeof body.permissions === 'object') {
        // Tamper events on negative transitions true -> false (incl. admin).
        if (prevPerms) {
          for (const [key, val] of Object.entries(body.permissions)) {
            if (prevPerms[key] === true && val === false) {
              addEvent(child, 'tamper', `${key} disabled`);
            }
          }
        }
        child.permissions = { ...(prevPerms || {}), ...body.permissions };
      }
      if (body.location && typeof body.location.lat === 'number' && typeof body.location.lng === 'number') {
        child.lastLocation = {
          lat: body.location.lat, lng: body.location.lng,
          accuracy: body.location.accuracy ?? null,
          ts: body.location.ts ?? Date.now(),
        };
      }
      if (body.appVersion) child.appVersion = String(body.appVersion);
      child.lastSeen = new Date().toISOString();
      save();
      return json(res, 200, { ok: true });
    }
    if (p === '/api/children/events' && req.method === 'POST') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => null);
      if (!body || !body.type) return json(res, 400, { error: 'type required' });
      addEvent(child, body.type, body.detail);
      child.lastSeen = new Date().toISOString();
      save();
      return json(res, 200, { ok: true });
    }

    // ---- chat history (SPEC-V2 §2): parent by childId, child for its own pair
    if (p === '/api/chat' && req.method === 'GET') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, data.chats[chatKey(child.parentId, child.id)] || []);
    }
    const chatMatch = p.match(/^\/api\/chat\/([^/]+)$/);
    if (chatMatch && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const child = data.children.find(c => c.id === decodeURIComponent(chatMatch[1]));
      if (!child) return json(res, 404, { error: 'child not found' });
      if (child.parentId !== parent.id) return json(res, 403, { error: 'forbidden' });
      return json(res, 200, data.chats[chatKey(parent.id, child.id)] || []);
    }

    // ---- media files (SPEC-V2 §3): upload raw bytes, owner-only download
    if (p === '/api/media' && req.method === 'POST') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const { buf, size, tooLarge } = await readRawBody(req, MEDIA_MAX_BYTES);
      if (tooLarge) return json(res, 413, { error: 'file too large (max 10 MB)' });
      const mediaId = crypto.randomBytes(16).toString('hex');
      try { fs.mkdirSync(MEDIA_DIR, { recursive: true }); } catch {}
      fs.writeFileSync(path.join(MEDIA_DIR, mediaId), buf);
      data.media[mediaId] = {
        id: mediaId,
        ownerParentId: parent ? parent.id : child.parentId,
        uploaderChildId: child ? child.id : null,
        fileName: String(req.headers['x-file-name'] || 'file').slice(0, 200),
        contentType: String(req.headers['content-type'] || 'application/octet-stream'),
        size,
        ts: Date.now(),
      };
      // Prune oldest files beyond the cap.
      const idsByAge = Object.keys(data.media).sort((a, b) => data.media[a].ts - data.media[b].ts);
      while (idsByAge.length > MEDIA_MAX_FILES) {
        const old = idsByAge.shift();
        try { fs.unlinkSync(path.join(MEDIA_DIR, old)); } catch {}
        delete data.media[old];
      }
      save();
      return json(res, 201, { mediaId, size });
    }
    const mediaMatch = p.match(/^\/api\/media\/([^/]+)$/);
    if (mediaMatch && req.method === 'GET') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const rec = data.media[decodeURIComponent(mediaMatch[1])];
      if (!rec) return json(res, 404, { error: 'media not found' });
      // Owner-only: the owning parent, or that parent's child (for child
      // uploads, only the very child that uploaded it).
      let allowed = false;
      if (parent) allowed = parent.id === rec.ownerParentId;
      else if (child) allowed = child.parentId === rec.ownerParentId &&
        (rec.uploaderChildId === null || rec.uploaderChildId === child.id);
      if (!allowed) return json(res, 403, { error: 'forbidden' });
      let bytes;
      try { bytes = fs.readFileSync(path.join(MEDIA_DIR, rec.id)); }
      catch { return json(res, 404, { error: 'media file missing' }); }
      res.writeHead(200, { 'Content-Type': rec.contentType, 'Content-Length': bytes.length });
      return res.end(bytes);
    }

    // ---- children (parent, strictly owner-filtered)
    if (p === '/api/children' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, data.children.filter(c => c.parentId === parent.id).map(childView));
    }
    const childMatch = p.match(/^\/api\/children\/([^/]+)(\/events)?$/);
    if (childMatch && (req.method === 'PATCH' || req.method === 'DELETE' || req.method === 'GET')) {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const id = decodeURIComponent(childMatch[1]);
      const child = findOwnChild(parent, id);
      if (!child) return json(res, 404, { error: 'child not found' });
      if (childMatch[2] === '/events') {
        if (req.method !== 'GET') return json(res, 404, { error: 'not found' });
        return json(res, 200, (child.events || []).slice(-EVENTS_RETURN));
      }
      if (req.method === 'PATCH') {
        const body = await readBody(req).catch(() => null);
        if (!body || typeof body.name !== 'string' || !body.name.trim()) return json(res, 400, { error: 'name required' });
        child.name = body.name.trim();
        save();
        return json(res, 200, childView(child));
      }
      if (req.method === 'DELETE') {
        // Close any live session + socket for this child first.
        for (const s of [...sessions.values()]) {
          if (s.childId === child.id) closeSession(s, peerSockets(s), 'child_removed');
        }
        const cws = liveChildren.get(child.id);
        if (cws) { try { cws.close(); } catch {} liveChildren.delete(child.id); }
        data.children = data.children.filter(c => c.id !== child.id);
        save();
        return json(res, 200, { ok: true });
      }
      // GET /api/children/:id is not part of the API.
      return json(res, 404, { error: 'not found' });
    }

    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: 'server error' });
  }
});

// ---------------------------------------------------------------- WebSocket
const wss = new WebSocketServer({ server });
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const role = url.searchParams.get('role');

  if (role === 'parent') {
    const token = url.searchParams.get('token') || '';
    const parentId = data.tokens[token];
    const parent = parentId && data.parents.find(p => p.id === parentId);
    if (!parent) { sendWs(ws, { type: 'error', error: 'unauthorized' }); try { ws.close(4401); } catch {} return; }
    ws.role = 'parent'; ws.parentId = parent.id;
    if (!liveParents.has(parent.id)) liveParents.set(parent.id, new Set());
    liveParents.get(parent.id).add(ws);
    sendWs(ws, { type: 'connected', role: 'parent', parentId: parent.id });
  } else if (role === 'child') {
    const deviceToken = url.searchParams.get('deviceToken') || '';
    const child = data.children.find(c => c.deviceToken === deviceToken);
    if (!child) { sendWs(ws, { type: 'error', error: 'unauthorized' }); try { ws.close(4401); } catch {} return; }
    ws.role = 'child'; ws.childId = child.id; ws.parentId = child.parentId;
    const old = liveChildren.get(child.id);
    if (old && old !== ws) { try { old.close(); } catch {} }
    liveChildren.set(child.id, ws);
    child.lastSeen = new Date().toISOString();
    save();
    sendWs(ws, { type: 'connected', role: 'child', childId: child.id, parentId: child.parentId });
  } else {
    sendWs(ws, { type: 'error', error: 'bad role' });
    try { ws.close(4400); } catch {}
    return;
  }

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || typeof m.type !== 'string') return;

    // ---- parent starts listening
    if (m.type === 'listen_start' && ws.role === 'parent') {
      const childId = String(m.childId || '');
      const child = data.children.find(c => c.id === childId);
      if (!child) return sendWs(ws, { type: 'listen_error', childId, reason: 'not_found' });
      if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'listen_error', childId, reason: 'forbidden' });
      const cws = liveChildren.get(childId);
      if (!cws || cws.readyState !== 1) return sendWs(ws, { type: 'listen_error', childId, reason: 'offline' });
      if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'listen_error', childId, reason: 'busy' });
      const session = createSession({ kind: 'listen', parentId: ws.parentId, childId, parentWs: ws, childWs: cws, initiatorRole: 'parent' });
      sendWs(cws, { type: 'listen_start', sessionId: session.id, parentId: ws.parentId });
      sendWs(ws, { type: 'listen_ready', sessionId: session.id, childId });
      return;
    }

    // ---- parent (or child) stops listening
    if (m.type === 'listen_stop') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'listen') return;
      if (ws !== s.parentWs && ws !== s.childWs) return;
      sessions.delete(s.id);
      archiveSession(s);
      const other = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(other, { type: 'listen_stop', sessionId: s.id });
      return;
    }

    // ---- camera session (SPEC-V2 §1a): parent opens front/back camera on the
    //      child; child streams sendonly audio+video, no preview on the child.
    if (m.type === 'camera_start' && ws.role === 'parent') {
      const childId = String(m.childId || '');
      const facing = m.facing === 'front' ? 'front' : 'back';
      const child = data.children.find(c => c.id === childId);
      if (!child) return sendWs(ws, { type: 'camera_error', childId, reason: 'not_found' });
      if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'camera_error', childId, reason: 'forbidden' });
      const cws = liveChildren.get(childId);
      if (!cws || cws.readyState !== 1) return sendWs(ws, { type: 'camera_error', childId, reason: 'offline' });
      if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'camera_error', childId, reason: 'busy' });
      const s = createSession({ kind: 'camera', parentId: ws.parentId, childId, parentWs: ws, childWs: cws, initiatorRole: 'parent' });
      sendWs(cws, { type: 'camera_start', sessionId: s.id, parentId: ws.parentId, facing });
      sendWs(ws, { type: 'camera_started', sessionId: s.id, childId, facing });
      return;
    }
    if (m.type === 'camera_ready' && ws.role === 'child') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera' || ws !== s.childWs) return;
      sendWs(s.parentWs, { type: 'camera_ready', sessionId: s.id });
      return;
    }
    if (m.type === 'camera_switch' && ws.role === 'parent') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera' || ws !== s.parentWs) return;
      sendWs(s.childWs, { type: 'camera_switch', sessionId: s.id });
      return;
    }
    if (m.type === 'camera_stop') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera') return;
      if (ws !== s.parentWs && ws !== s.childWs) return;
      sessions.delete(s.id);
      archiveSession(s);
      const other = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(other, { type: 'camera_stop', sessionId: s.id });
      return;
    }

    // ---- two-way call (SPEC-V2 §1b): either side initiates; the invite goes
    //      to the child's socket, or to ALL of the parent's sockets when the
    //      child calls (the accepting parent socket becomes the session party).
    if (m.type === 'call_start') {
      const media = m.media === 'video' ? 'video' : 'audio';
      if (ws.role === 'parent') {
        const childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child) return sendWs(ws, { type: 'call_error', childId, reason: 'not_found' });
        if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'call_error', childId, reason: 'forbidden' });
        const cws = liveChildren.get(childId);
        if (!cws || cws.readyState !== 1) return sendWs(ws, { type: 'call_error', childId, reason: 'offline' });
        if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'call_busy', childId });
        const s = createSession({ kind: 'call', state: 'ringing', media, parentId: ws.parentId, childId, parentWs: ws, childWs: cws, initiatorRole: 'parent' });
        armRingTimer(s);
        sendWs(cws, { type: 'call_invite', sessionId: s.id, media, fromId: ws.parentId });
        return;
      }
      if (ws.role === 'child') {
        const pset = liveParents.get(ws.parentId);
        const parentOnline = !!pset && [...pset].some(x => x.readyState === 1);
        if (!parentOnline) return sendWs(ws, { type: 'call_error', reason: 'offline' });
        if (partyBusy(ws.parentId, ws.childId)) return sendWs(ws, { type: 'call_busy', childId: ws.childId });
        const s = createSession({ kind: 'call', state: 'ringing', media, parentId: ws.parentId, childId: ws.childId, parentWs: null, childWs: ws, initiatorRole: 'child' });
        armRingTimer(s);
        for (const pws of pset) sendWs(pws, { type: 'call_invite', sessionId: s.id, media, fromId: ws.childId });
        return;
      }
      return;
    }
    if (m.type === 'call_accept') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'call' || s.state !== 'ringing') return;
      if (s.initiatorRole === 'parent') {
        if (ws !== s.childWs) return; // only the invited child can accept
      } else {
        if (ws.role !== 'parent' || ws.parentId !== s.parentId) return;
        s.parentWs = ws; // the accepting socket becomes the parent-side party
      }
      if (s.ringTimer) { clearTimeout(s.ringTimer); s.ringTimer = null; }
      s.state = 'active';
      const initiator = s.initiatorRole === 'parent' ? s.parentWs : s.childWs;
      sendWs(initiator, { type: 'call_accepted', sessionId: s.id });
      return;
    }
    if (m.type === 'call_reject' || m.type === 'call_end' || m.type === 'call_cancel') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'call') return;
      const isParty = ws === s.parentWs || ws === s.childWs ||
        (s.initiatorRole === 'child' && ws.role === 'parent' && ws.parentId === s.parentId);
      if (!isParty) return;
      const reason = m.type === 'call_reject' ? 'rejected' : (m.type === 'call_cancel' ? 'cancelled' : 'ended');
      closeSession(s, peerSockets(s, ws), reason);
      return;
    }

    // ---- chat (SPEC-V2 §2): persist per pair, relay to the other party
    if (m.type === 'chat_send') {
      let parentId, childId;
      if (ws.role === 'parent') {
        childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child || child.parentId !== ws.parentId) return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        parentId = ws.parentId;
      } else if (ws.role === 'child') {
        parentId = ws.parentId; childId = ws.childId;
      } else return;
      const kind = (m.kind === 'photo' || m.kind === 'file') ? m.kind : 'text';
      const mediaId = m.mediaId ? String(m.mediaId) : null;
      if (kind !== 'text') {
        const rec = mediaId ? data.media[mediaId] : null;
        if (!rec || rec.ownerParentId !== parentId) return sendWs(ws, { type: 'chat_error', reason: 'bad_media' });
      }
      const msg = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId, childId, fromRole: ws.role, kind,
        body: m.body == null ? '' : String(m.body).slice(0, 4000),
        mediaId, ts: new Date().toISOString(),
      };
      const key = chatKey(parentId, childId);
      const arr = data.chats[key] || (data.chats[key] = []);
      arr.push(msg);
      if (arr.length > CHAT_CAP) data.chats[key] = arr.slice(-CHAT_CAP);
      save();
      const out = Object.assign({ type: 'chat_msg' }, msg);
      if (ws.role === 'parent') {
        sendWs(liveChildren.get(childId), out);
      } else {
        const set = liveParents.get(parentId);
        if (set) for (const pws of set) sendWs(pws, out);
      }
      return;
    }

    // ---- WebRTC signalling: relay ONLY between the two parties of the session
    if (m.type === 'signal') {
      const s = sessions.get(m.sessionId);
      if (!s) return sendWs(ws, { type: 'error', error: 'no such session' });
      if (ws !== s.parentWs && ws !== s.childWs) return;
      // Diagnostics tallies: message kinds + ICE candidate TYPES only.
      try {
        const pl = m.payload || {};
        if (pl.kind === 'offer') s.sig.offer++;
        else if (pl.kind === 'answer') s.sig.answer++;
        else if (pl.kind === 'ice') {
          const tmatch = / typ ([a-z]+)/.exec(String(pl.candidate || ''));
          const t = tmatch ? tmatch[1] : 'unknown';
          const bucket = ws.role === 'child' ? s.sig.childIce : s.sig.parentIce;
          bucket[t] = (bucket[t] || 0) + 1;
        }
      } catch {}
      const peer = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(peer, { type: 'signal', sessionId: s.id, payload: m.payload });
      return;
    }

    // ---- Bare offer/answer/ice (SPEC-V2 §1): relayed verbatim between the
    //      two session parties, in both directions, for every session kind.
    if (m.type === 'offer' || m.type === 'answer' || m.type === 'ice') {
      const s = sessions.get(m.sessionId);
      if (!s) return sendWs(ws, { type: 'error', error: 'no such session' });
      if (ws !== s.parentWs && ws !== s.childWs) return;
      try {
        if (m.type === 'offer') s.sig.offer++;
        else if (m.type === 'answer') s.sig.answer++;
        else {
          const tmatch = / typ ([a-z]+)/.exec(String(m.candidate || ''));
          const t = tmatch ? tmatch[1] : 'unknown';
          const bucket = ws.role === 'child' ? s.sig.childIce : s.sig.parentIce;
          bucket[t] = (bucket[t] || 0) + 1;
        }
      } catch {}
      const peer = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(peer, m);
      return;
    }

    // ---- RTC diagnostics from either party (short state words only)
    if (m.type === 'rtc_debug') {
      const state = String(m.state || '').slice(0, 80);
      if (!state) return;
      const s = sessions.get(m.sessionId);
      if (s && (ws === s.parentWs || ws === s.childWs)) {
        s.dbg.push(`${ws.role}:${state}`);
        if (s.dbg.length > 40) s.dbg = s.dbg.slice(-40);
      }
      // Mirror into per-party stores too, so the trail survives session close.
      if (ws.role === 'child' && ws.childId) {
        const arr = childDebug.get(ws.childId) || [];
        arr.push(state);
        childDebug.set(ws.childId, arr.slice(-30));
      } else if (ws.role === 'parent' && ws.parentId) {
        const arr = parentDebug.get(ws.parentId) || [];
        arr.push(state);
        parentDebug.set(ws.parentId, arr.slice(-30));
      }
      return;
    }

    // ---- child location: store + relay to owning parent(s)
    if (m.type === 'location' && ws.role === 'child') {
      const child = data.children.find(c => c.id === ws.childId);
      if (!child || typeof m.lat !== 'number' || typeof m.lng !== 'number') return;
      child.lastLocation = { lat: m.lat, lng: m.lng, accuracy: m.accuracy ?? null, ts: m.ts ?? Date.now() };
      child.lastSeen = new Date().toISOString();
      save();
      const msg = { type: 'location', childId: child.id, lat: m.lat, lng: m.lng, accuracy: m.accuracy ?? null, ts: child.lastLocation.ts };
      if (m.sessionId) msg.sessionId = m.sessionId;
      const set = liveParents.get(child.parentId);
      if (set) for (const pws of set) sendWs(pws, msg);
      return;
    }
  });

  ws.on('close', () => {
    if (ws.role === 'parent') {
      const set = liveParents.get(ws.parentId);
      if (set) { set.delete(ws); if (!set.size) liveParents.delete(ws.parentId); }
      for (const s of [...sessions.values()]) {
        if (s.parentWs === ws) closeSession(s, peerSockets(s), 'disconnect');
      }
    }
    if (ws.role === 'child') {
      if (liveChildren.get(ws.childId) === ws) liveChildren.delete(ws.childId);
      const child = data.children.find(c => c.id === ws.childId);
      if (child) { child.lastSeen = new Date().toISOString(); save(); }
      for (const s of [...sessions.values()]) {
        if (s.childWs === ws) closeSession(s, peerSockets(s), 'disconnect');
      }
    }
  });
});

try { fs.mkdirSync(MEDIA_DIR, { recursive: true }); } catch {}
server.listen(PORT, () => console.log(`parent-monitor server on :${PORT} (data: ${DATA_FILE})`));
