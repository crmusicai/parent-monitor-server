/**
 * Parent Monitor Server — multi-tenant registry, pairing, heartbeat/events,
 * and WebRTC signalling relay for the Parental Monitoring App.
 *
 * Source of truth: ../SPEC.md
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

// ---------------------------------------------------------------- storage
function blankData() {
  return { parents: [], tokens: {}, pairingCodes: {}, children: [] };
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
  lastSessions.push({ id: session.id.slice(0, 8), childId: session.childId,
    sig: session.sig, dbg: session.dbg, closedAt: new Date().toISOString() });
  while (lastSessions.length > 5) lastSessions.shift();
}
function closeSession(session, notifyWsList) {
  sessions.delete(session.id);
  archiveSession(session);
  for (const peer of notifyWsList) sendWs(peer, { type: 'session_closed', sessionId: session.id });
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
          id: s.id.slice(0, 8), childId: s.childId, sig: s.sig, dbg: s.dbg,
        })),
        lastSessions,
        childDebug: Object.fromEntries(childDebug),
        parentDebug: Object.fromEntries(parentDebug),
      });
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

    // ---- child pairing (public, code is the credential)
    if (p === '/api/children/pair' && req.method === 'POST') {
      const { code, name, model } = await readBody(req).catch(() => null) || {};
      const rec = code ? data.pairingCodes[String(code)] : null;
      if (!rec) return json(res, 400, { error: 'invalid pairing code' });
      if (Date.now() > rec.expiresAt) {
        delete data.pairingCodes[String(code)]; save();
        return json(res, 410, { error: 'pairing code expired' });
      }
      delete data.pairingCodes[String(code)]; // single use
      const child = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId: rec.parentId,
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
          if (s.childId === child.id) closeSession(s, [s.parentWs]);
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
      const sessionId = crypto.randomBytes(16).toString('hex');
      sessions.set(sessionId, { id: sessionId, parentId: ws.parentId, childId, parentWs: ws, childWs: cws,
        sig: { offer: 0, answer: 0, childIce: {}, parentIce: {} }, dbg: [] });
      sendWs(cws, { type: 'listen_start', sessionId, parentId: ws.parentId });
      sendWs(ws, { type: 'listen_ready', sessionId, childId });
      return;
    }

    // ---- parent (or child) stops listening
    if (m.type === 'listen_stop') {
      const s = sessions.get(m.sessionId);
      if (!s) return;
      if (ws !== s.parentWs && ws !== s.childWs) return;
      sessions.delete(s.id);
      archiveSession(s);
      const other = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(other, { type: 'listen_stop', sessionId: s.id });
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
          const bucket = ws === s.childWs ? s.sig.childIce : s.sig.parentIce;
          bucket[t] = (bucket[t] || 0) + 1;
        }
      } catch {}
      const peer = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(peer, { type: 'signal', sessionId: s.id, payload: m.payload });
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
        if (s.parentWs === ws) closeSession(s, [s.childWs]);
      }
    }
    if (ws.role === 'child') {
      if (liveChildren.get(ws.childId) === ws) liveChildren.delete(ws.childId);
      const child = data.children.find(c => c.id === ws.childId);
      if (child) { child.lastSeen = new Date().toISOString(); save(); }
      for (const s of [...sessions.values()]) {
        if (s.childWs === ws) closeSession(s, [s.parentWs]);
      }
    }
  });
});

server.listen(PORT, () => console.log(`parent-monitor server on :${PORT} (data: ${DATA_FILE})`));
