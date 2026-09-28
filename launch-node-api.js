'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');

const DATA_DIR = process.env.LAUNCH_CLUSTER_DATA_DIR || '/contract/contract_fs/seed/launch-storage';
const CHUNK_DIR = path.join(DATA_DIR, 'chunks');
const NODE_DATA_DIR = process.env.EVERSMARTNODE_DATA_DIR || '/var/lib/eversmartnode';
const AI_FILE = path.join(NODE_DATA_DIR, 'ai.json');
const SECRET_DIR = process.env.EVERSMARTNODE_SECRET_DIR || '/var/lib/eversmartnode/secrets';
const AI_KEY_FILE = process.env.EVERSMARTNODE_OLLAMA_API_KEY_FILE || path.join(SECRET_DIR, 'ollama-api.key');
const SUPERVISOR_CONF = process.env.EVERSMARTNODE_SUPERVISOR_CONF || '/etc/eversmartnode/supervisord.conf';
const AUTOCACHE = '/var/lib/eversmartnode/autocluster-status-cache.json';
const OLLAMA_URL = process.env.OLLAMA_INTERNAL_URL || 'http://127.0.0.1:11434';
const OLLAMA_HOME = process.env.OLLAMA_HOME || '/var/lib/eversmartnode/ollama';
const OLLAMA_BIN = process.env.EVERSMARTNODE_OLLAMA_BIN || path.join(OLLAMA_HOME, 'current', 'bin', 'ollama');
const OLLAMA_INSTALL_SCRIPT = process.env.EVERSMARTNODE_OLLAMA_INSTALL_SCRIPT || '/opt/eversmartnode/install-ollama.sh';
const OLLAMA_INSTALL_LOG = path.join(OLLAMA_HOME, 'install.log');
const AI_TAG_RELAY_SECRET = process.env.EVERSMARTNODE_AI_TAG_RELAY_SECRET || '/contract/cfg/launch-ai-tagging-relay.key';
const AI_TAG_RESULT_NAME = 'local-result.json';
const AI_TAG_ATTESTATION_NAME = 'signed-attestation.json';
const AI_TAG_NPL_WORK_NAME = 'npl-work.json';
const AI_TAG_WORKER_STATE_NAME = 'worker-state.json';
const AI_TAG_WORKER_LOG_NAME = 'worker.log';
const AI_TAG_FAILURES_NAME = 'failures.json';
const AI_TAG_MAX_MODEL_ATTEMPTS = 3;
const AI_TAG_FAILURE_COOLDOWN_MS = 15 * 60 * 1000;
const AI_TAG_LOCAL_RESULT_TYPE = 'launch_ai_local_result_v1';
const AI_TAG_ATTESTATION_TYPE = 'launch_ai_attestation_v1';
const AI_TAG_NPL_WORK_TYPE = 'launch_ai_work_npl_v1';
const AI_TAG_PREVIEW_BYTES = 48 * 1024;
const MAX_CHUNK = 16 * 1024 * 1024;
const MAX_BODY = 20 * 1024 * 1024;
const REPAIR_STATE_FILE = path.join(NODE_DATA_DIR, 'replica-repair.json');
const REPAIR_PROBE_TIMEOUT_MS = 4500;
const REPAIR_FETCH_TIMEOUT_MS = 15000;
const REPAIR_BACKOFF_MAX_MS = 5 * 60 * 1000;

// AI file tagging is ON by default. It can be disabled node-wide either by
// setting EVERSMARTNODE_AI_FILES_ENABLED=false in the backend environment or
// through the signed /api/launch/ai/files-enabled endpoint below. The
// environment variable is an operator override and wins over ai.json.
function envBool(value) {
  if (value == null || String(value).trim() === '') return null;
  const v = String(value).trim().toLowerCase();
  if (['1','true','yes','on','enabled'].includes(v)) return true;
  if (['0','false','no','off','disabled'].includes(v)) return false;
  return null;
}
function aiFilesBackendEnabled(meta = null) {
  const forced = envBool(process.env.EVERSMARTNODE_AI_FILES_ENABLED);
  if (forced !== null) return forced;
  const cfg = meta && typeof meta === 'object' ? meta : readJson(AI_FILE, {});
  return cfg.aiFilesEnabled !== false;
}

function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, value) { fs.mkdirSync(path.dirname(file), { recursive:true }); fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function safe(v, max = 4096) { return String(v == null ? '' : v).trim().slice(0, max); }
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}
function sendFile(res, file, type) {
  try {
    const b = fs.readFileSync(file);
    res.statusCode = 200;
    res.setHeader('Content-Type', type);
    res.setHeader('Content-Length', b.length);
    res.setHeader('Cache-Control', 'no-store');
    res.end(b);
    return true;
  } catch { return false; }
}
function hash(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function cleanHash(v) { const h = safe(v, 80).toLowerCase(); if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('Invalid chunk hash.'); return h; }
function chunkPath(h) { return path.join(CHUNK_DIR, h.slice(0, 2), h); }

function stateRoot() {
  const explicit = process.env.LAUNCH_CLUSTER_STATE_ROOT;
  if (explicit && fs.existsSync(explicit)) return explicit;
  const c = readJson(AUTOCACHE, null);
  if (c && c.stateRoot && fs.existsSync(c.stateRoot)) return c.stateRoot;
  for (const p of ['/contract/contract_fs/mnt/rw/state', '/contract/contract_fs/seed/state']) if (fs.existsSync(p)) return p;
  return null;
}

function normalizePubkey(v) {
  const p = safe(v, 256).toLowerCase();
  return /^ed[0-9a-f]{64}$/.test(p) ? p : null;
}

// The lightweight node API used to read only cluster.json. During bootstrap,
// endpoint metadata is often already canonical in auto.validators while cluster.json
// is still sparse. Merge both sources so /api/launch/nodes always exposes the same
// managed GPTCP1 inventory as the main control plane.
function clusterStatus() {
  const root = stateRoot();
  if (!root) return { phase:'unknown', targetManagedNodes:0, signerQuorum:0, nodes:[], managedNodes:[] };
  const auto = readJson(path.join(root, 'autocluster.state.json'), null) ||
    readJson(path.join(root, 'autocluster.json'), null) || readJson(AUTOCACHE, null)?.auto || null;
  const cluster = readJson(path.join(root, 'cluster.json'), null) || {};
  const bootstrap = normalizePubkey(auto && auto.bootstrapPubkey);
  const validatorMeta = new Map((Array.isArray(auto && auto.validators) ? auto.validators : [])
    .filter(v => v && normalizePubkey(v.publicKey || v.pubkey))
    .map(v => [normalizePubkey(v.publicKey || v.pubkey), v]));
  const unlSnapshot = new Set((Array.isArray(auto && auto.unlSnapshot) ? auto.unlSnapshot : []).map(normalizePubkey).filter(Boolean));

  const nodes = (Array.isArray(cluster.nodes) ? cluster.nodes : []).map(n => {
    const pubkey = normalizePubkey(n && n.pubkey);
    const meta = pubkey ? (validatorMeta.get(pubkey) || {}) : {};
    const isUnl = !!(n && n.isUnl) || (!!pubkey && unlSnapshot.has(pubkey)) || meta.isUnl === true;
    return {
      pubkey,
      domain: safe((n && n.domain) || meta.domain, 255) || null,
      userPort: Number((n && n.userPort) || meta.userPort) || null,
      peerPort: Number((n && (n.peerPort || n.meshPort)) || meta.peerPort) || null,
      gpTcp1Port: Number((n && (n.gpTcp1Port || n.gpTcpPort)) || meta.gpTcp1Port) || null,
      gpUdp1Port: Number((n && (n.gpUdp1Port || n.gpUdpPort)) || meta.gpUdp1Port) || null,
      isUnl,
      isBootstrap: !!bootstrap && pubkey === bootstrap,
      signerAddress: safe((n && n.signerAddress) || meta.signerAddress, 128) || null,
      host: safe((n && n.host) || meta.hostAddress, 128) || null
    };
  });

  return {
    phase: safe(auto && auto.phase, 64) || 'not-started',
    targetManagedNodes: Number(auto && auto.targetManagedNodes) || 0,
    signerQuorum: Number(auto && auto.signerQuorum) || 0,
    nodes,
    managedNodes: nodes.filter(n => !n.isBootstrap && n.isUnl)
  };
}

function localCommittedUnl() {
  const cfg = readJson('/contract/cfg/hp.cfg', null) || readJson('/contract/hp.cfg', null) || {};
  const raw = cfg.contract && Array.isArray(cfg.contract.unl) ? cfg.contract.unl : [];
  return raw.map(normalizePubkey).filter(Boolean);
}

function isFinalized() {
  const s = clusterStatus();
  const target = Math.max(1, s.targetManagedNodes || 1);
  if (s.managedNodes.length < target) return false;
  if (s.phase === 'autonomous') return true;
  // Bootstrap A can stop receiving contract executions immediately after its
  // REMOVE_UNL patch commits, leaving its local replicated phase briefly at
  // "handover". The local hp.cfg is authoritative for that final membership edge.
  if (s.phase === 'handover') {
    const root = stateRoot();
    const auto = root && (readJson(path.join(root, 'autocluster.state.json'), null) || readJson(path.join(root, 'autocluster.json'), null));
    const bootstrap = normalizePubkey(auto && auto.bootstrapPubkey);
    const committed = localCommittedUnl();
    return !!bootstrap && committed.length >= target && !committed.includes(bootstrap);
  }
  return false;
}

async function body(req, max = MAX_BODY) {
  const parts = []; let total = 0;
  for await (const p of req) {
    total += p.length;
    if (total > max) throw new Error('Request body too large.');
    parts.push(p);
  }
  return Buffer.concat(parts);
}

function pubKeyObject(pub) {
  const p = safe(pub, 80).toLowerCase().replace(/^0x/, '');
  const raw = p.startsWith('ed') ? p.slice(2) : p;
  if (!/^[0-9a-f]{64}$/.test(raw)) throw new Error('Invalid HotPocket public key.');
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({ key:Buffer.concat([prefix, Buffer.from(raw, 'hex')]), format:'der', type:'spki' });
}

function verifySignature(req, rawBody, adminOnly = false) {
  const pub = safe(req.headers['x-launch-public-key'], 80).toLowerCase();
  const ts = Number(req.headers['x-launch-timestamp']);
  const sig = safe(req.headers['x-launch-signature'], 256).toLowerCase();
  if (!pub || !Number.isFinite(ts) || Math.abs(Date.now() - ts) > 120000 || !/^[0-9a-f]{128}$/.test(sig)) throw new Error('Missing or invalid request signature.');
  const digest = hash(rawBody || Buffer.alloc(0));
  const pathname = new URL(req.url, 'https://local').pathname;
  const msg = `launch-node-v1|${req.method}|${pathname}|${ts}|${digest}`;
  if (!crypto.verify(null, Buffer.from(msg), pubKeyObject(pub), Buffer.from(sig, 'hex'))) throw new Error('Invalid request signature.');
  if (adminOnly) {
    const root = stateRoot();
    const auth = root && readJson(path.join(root, 'admin-auth.json'), null);
    const device = auth && auth.authorizedDevices && auth.authorizedDevices[pub];
    const user = device && auth.users && auth.users[device.userId];
    if (!device || !user || user.active === false || user.role !== 'head-admin' || Number(device.expiresAt || 0) <= Date.now()) throw new Error('Head-admin authorization required.');
  }
  return pub;
}

function inventory() {
  const out = [];
  if (!fs.existsSync(CHUNK_DIR)) return out;
  for (const dir of fs.readdirSync(CHUNK_DIR, { withFileTypes:true })) {
    if (!dir.isDirectory()) continue;
    const base = path.join(CHUNK_DIR, dir.name);
    for (const e of fs.readdirSync(base, { withFileTypes:true })) {
      if (!e.isFile() || !/^[0-9a-f]{64}$/.test(e.name)) continue;
      const f = path.join(base, e.name);
      try { const st = fs.statSync(f); out.push({ hash:e.name, size:st.size }); } catch {}
    }
  }
  return out;
}

function command(file, args, timeout = 120000) {
  return new Promise((resolve, reject) => execFile(file, args, { timeout, maxBuffer:4 * 1024 * 1024 }, (err, stdout, stderr) =>
    err ? reject(new Error(safe(stderr || err.message, 2000))) : resolve({ stdout:safe(stdout, 100000), stderr:safe(stderr, 100000) })));
}

function ensureAiApiKey(rotate = false) {
  if (!rotate) {
    try {
      const existing = fs.readFileSync(AI_KEY_FILE, 'utf8').trim();
      if (/^lcai_[A-Za-z0-9_-]{32,}$/.test(existing)) return existing;
    } catch {}
  }
  fs.mkdirSync(path.dirname(AI_KEY_FILE), { recursive:true, mode:0o700 });
  const key = `lcai_${crypto.randomBytes(32).toString('base64url')}`;
  const tmp = `${AI_KEY_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${key}\n`, { mode:0o600 });
  fs.renameSync(tmp, AI_KEY_FILE);
  try { fs.chmodSync(AI_KEY_FILE, 0o600); } catch {}
  return key;
}

function bearerKey(req) {
  const auth = safe(req.headers.authorization, 4096);
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : safe(req.headers['x-launch-ai-key'], 4096);
}

function verifyAiApiKey(req) {
  const supplied = bearerKey(req);
  if (!supplied) throw new Error('Missing AI API key.');
  const expected = ensureAiApiKey(false);
  const a = Buffer.from(supplied), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('Invalid AI API key.');
  return true;
}

async function parseJsonBody(req) {
  const b = await body(req, 2 * 1024 * 1024);
  let j = {};
  try { j = b.length ? JSON.parse(b.toString('utf8')) : {}; } catch { throw new Error('Invalid JSON body.'); }
  return { raw:b, json:j };
}

async function ollamaFetch(pathname, options = {}, timeout = 300000) {
  let r;
  try { r = await fetch(`${OLLAMA_URL}${pathname}`, { ...options, signal:AbortSignal.timeout(timeout) }); }
  catch (e) { throw new Error(`Ollama is not reachable at ${OLLAMA_URL}: ${e && e.message ? e.message : String(e)}`); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `Ollama HTTP ${r.status}`);
  return j;
}

function processAlive(pid) {
  const n = Number(pid);
  if (!Number.isInteger(n) || n < 2) return false;
  try { process.kill(n, 0); return true; } catch { return false; }
}

function tailFile(file, maxBytes = 12000) {
  try {
    const st = fs.statSync(file), start = Math.max(0, st.size - maxBytes), len = st.size - start;
    const fd = fs.openSync(file, 'r'); const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, start); fs.closeSync(fd);
    return b.toString('utf8').slice(-maxBytes);
  } catch { return ''; }
}

const AI_TAG_PROFILES = new Set(['balanced','broad','content','discovery']);
function taggingTemperature(value, fallback = 0.55) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.min(2, Math.round(n * 100) / 100)) : fallback;
}
function taggingProfile(value, fallback = 'balanced') {
  const p = safe(value, 32).toLowerCase();
  return AI_TAG_PROFILES.has(p) ? p : fallback;
}
function derivedTaggingSeed(pubkey = localNodePubkey()) {
  const source = safe(pubkey, 128) || 'eversmartnode-ai';
  return parseInt(crypto.createHash('sha256').update(source).digest('hex').slice(0, 8), 16) & 0x7fffffff;
}
function taggingSeed(value, fallback = derivedTaggingSeed()) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= 0x7fffffff ? n : fallback;
}
function taggingProfileInstruction(profile) {
  if (profile === 'broad') return 'Tagging style: prefer broad reusable categories, file purpose, and high-level domain labels. Do not mechanically split the filename into tags.';
  if (profile === 'content') return 'Tagging style: prefer concrete subjects, technologies, entities, and concepts visible in the file content. Use filename words only when they are genuinely descriptive.';
  if (profile === 'discovery') return 'Tagging style: prefer tags a person would actually search for later, including useful concepts and intent. Avoid merely copying filename fragments.';
  return 'Tagging style: balance broad categories, concrete subjects, and search usefulness. Do not mechanically split the filename into tags.';
}

function aiInstallGate() {
  const cluster = clusterStatus();
  const local = localNodePubkey();
  const target = Math.max(1, Number(cluster.targetManagedNodes || 0) || 1);
  const managedCount = Array.isArray(cluster.managedNodes) ? cluster.managedNodes.length : 0;
  const localNode = !!local && cluster.managedNodes.find(n => n.pubkey === local);
  const localManaged = !!localNode;
  // AI may be installed after the final managed validator set is assembled but
  // before Bootstrap A is removed. This is the optional pre-finalization step.
  const unlCreated = managedCount >= target && ['signing','ready-to-handover','handover','autonomous'].includes(cluster.phase);
  const localInUnl = !!(localNode && localNode.isUnl !== false);
  return {
    allowed: localManaged && localInUnl && unlCreated,
    localManaged,
    localInUnl,
    unlCreated,
    localNodePubkey:local,
    phase:cluster.phase,
    managedCount,
    targetManagedNodes:target,
    reason:!localManaged ? 'This instance is not a managed validator.' : (!localInUnl ? 'This managed instance is not in the committed UNL yet.' : (!unlCreated ? `Final managed UNL is not ready yet (${managedCount}/${target}, phase ${cluster.phase}).` : null))
  };
}

async function ollamaStatus() {
  let version = null, running = false, models = [];
  try { if (fs.existsSync(OLLAMA_BIN)) version = (await command(OLLAMA_BIN, ['--version'], 10000)).stdout || 'installed'; } catch {}
  try {
    const j = await ollamaFetch('/api/tags', { cache:'no-store' }, 4000);
    running = true;
    models = (j.models || []).map(x => x.name).filter(Boolean);
  } catch {}
  let meta = readJson(AI_FILE, {});
  const installed = !!version;
  if (meta.installing && !processAlive(meta.installPid)) {
    meta = { ...meta, installing:false, installPid:null, updatedAt:Date.now(), installFinishedAt:Date.now(), installResult:installed?'installed':'failed' };
    writeJson(AI_FILE, meta);
  }
  const gate = aiInstallGate();
  const taggingModel = safe(meta.taggingModel || meta.lastPulledModel || models[0] || '', 128) || null;
  const activeModelAvailable = !!taggingModel && models.includes(taggingModel);
  const taggingConfigured = !!(meta.taggingModel || meta.taggingTemperature != null || meta.taggingProfile || meta.taggingSeed != null);
  const activeTemperature = taggingTemperature(meta.taggingTemperature, 0.2);
  const activeProfile = taggingProfile(meta.taggingProfile, 'balanced');
  const activeSeed = taggingSeed(meta.taggingSeed);
  const aiFilesEnabled = aiFilesBackendEnabled(meta);
  const taggingEnabled = aiFilesEnabled && installed && running && activeModelAvailable && meta.enabled !== false;
  return {
    installed,
    version,
    running,
    models,
    aiInstance: installed,
    aiFilesEnabled,
    aiFilesEnvOverride:envBool(process.env.EVERSMARTNODE_AI_FILES_ENABLED),
    taggingEnabled,
    taggingModel,
    taggingConfigured,
    taggingTemperature:activeTemperature,
    taggingProfile:activeProfile,
    taggingSeed:activeSeed,
    activeModelAvailable,
    installing:!!meta.installing && processAlive(meta.installPid),
    installPid:meta.installing ? Number(meta.installPid || 0) || null : null,
    installResult:meta.installResult || null,
    installAllowed:gate.allowed,
    installGate:gate,
    installLog:tailFile(OLLAMA_INSTALL_LOG, 8000),
    apiKeyConfigured:fs.existsSync(AI_KEY_FILE),
    openAiBasePath:'/api/launch/ai/v1',
    taggingWorker:(() => { const p=aiTagLocalFiles(); const w=p&&readJson(p.worker,null); return w&&typeof w==='object'?w:{ state:'idle' }; })(),
    taggingWorkerLog:(() => { const p=aiTagLocalFiles(); return p&&p.log?tailFile(p.log, 24000):''; })(),
    updatedAt:Number(meta.updatedAt || meta.installedAt || 0) || null
  };
}

async function restartOllama() {
  if (!fs.existsSync(OLLAMA_BIN)) throw new Error('Ollama is not installed on this instance. Use Install Ollama first.');
  try {
    await command('/usr/bin/supervisorctl', ['-c', SUPERVISOR_CONF, 'restart', 'ollama'], 30000);
  } catch (e) {
    throw new Error(`Supervisor could not restart Ollama: ${e.message}`);
  }
  for (let i = 0; i < 40; i++) {
    try { await ollamaFetch('/api/tags', { cache:'no-store' }, 1500); return; } catch {}
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Ollama did not become ready after restart.');
}

function startOllamaInstall() {
  const gate = aiInstallGate();
  if (!gate.allowed) throw new Error(gate.reason || 'Ollama installation is not allowed yet.');
  const existing = readJson(AI_FILE, {});
  if (existing.installing && processAlive(existing.installPid)) return { started:false, alreadyRunning:true, pid:Number(existing.installPid), gate };
  if (!fs.existsSync(OLLAMA_INSTALL_SCRIPT)) throw new Error(`Ollama install script is missing: ${OLLAMA_INSTALL_SCRIPT}`);
  fs.mkdirSync(OLLAMA_HOME, { recursive:true });
  const logFd = fs.openSync(OLLAMA_INSTALL_LOG, 'a');
  const child = spawn(OLLAMA_INSTALL_SCRIPT, [], {
    detached:true,
    stdio:['ignore', logFd, logFd],
    env:{ ...process.env, OLLAMA_HOME, OLLAMA_MODELS:process.env.OLLAMA_MODELS || path.join(OLLAMA_HOME, 'models'), EVERSMARTNODE_OLLAMA_BIN:OLLAMA_BIN }
  });
  fs.closeSync(logFd);
  const startedAt = Date.now();
  writeJson(AI_FILE, { ...existing, enabled:true, installing:true, installPid:child.pid, installStartedAt:startedAt, updatedAt:startedAt, installResult:'installing' });
  child.on('exit', async code => {
    const done = Date.now(), installed = fs.existsSync(OLLAMA_BIN);
    writeJson(AI_FILE, { ...readJson(AI_FILE, {}), installing:false, installPid:null, installedAt:installed ? done : (readJson(AI_FILE, {}).installedAt || null), installFinishedAt:done, updatedAt:done, installResult:installed && code === 0 ? 'installed' : `failed:${code}` });
    if (installed && code === 0) { try { await restartOllama(); } catch {} }
  });
  child.unref();
  return { started:true, alreadyRunning:false, pid:child.pid, gate };
}

function nodeUrl(n) {
  if (!n || !n.domain || !n.gpTcp1Port) return null;
  const h = String(n.domain).includes(':') ? `[${n.domain}]` : n.domain;
  return `https://${h}:${Number(n.gpTcp1Port)}`;
}

function localNodePubkey() {
  const cfg = readJson('/contract/cfg/hp.cfg', null) || readJson('/contract/hp.cfg', null) || {};
  const cfgNode = cfg.node && typeof cfg.node === 'object' ? cfg.node : {};
  const fromCfg = normalizePubkey(cfgNode.public_key || cfgNode.publicKey || cfg.public_key || cfg.publicKey);
  if (fromCfg) return fromCfg;
  const root = stateRoot(); if (!root) return null;
  const health = readJson(path.resolve(root, '..', 'unl-health.json'), null);
  return normalizePubkey(health && (health.reporterPublicKey || health.pubkey || health.publicKey));
}

function manifestState() {
  const root = stateRoot();
  return root ? readJson(path.join(root, 'launch-files.json'), { files:{}, portalFinalized:false }) : { files:{}, portalFinalized:false };
}

function desiredNodes(fileId, chunkHash, count, nodes) {
  return [...nodes].filter(n => n && n.pubkey && nodeUrl(n)).sort((a, b) => {
    const aa = hash(Buffer.from(`${fileId}|${chunkHash}|${a.pubkey}`));
    const bb = hash(Buffer.from(`${fileId}|${chunkHash}|${b.pubkey}`));
    return aa.localeCompare(bb);
  }).slice(0, Math.max(1, Math.min(nodes.length, Number(count) || 1)));
}

let repairBusy = false;

function loadRepairState() {
  const s = readJson(REPAIR_STATE_FILE, null);
  return s && typeof s === 'object' ? s : { schema:2, attempts:{} };
}

function saveRepairState(value) {
  try {
    fs.mkdirSync(path.dirname(REPAIR_STATE_FILE), { recursive:true, mode:0o700 });
    const tmp = `${REPAIR_STATE_FILE}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode:0o600 });
    fs.renameSync(tmp, REPAIR_STATE_FILE);
  } catch {}
}

async function repairInventorySnapshot(nodes, localPubkey) {
  const entries = await Promise.all(nodes.map(async n => {
    if (!n || !n.pubkey || !nodeUrl(n)) return [n && n.pubkey, { node:n, online:false, chunks:new Set(), error:'missing-endpoint' }];
    if (n.pubkey === localPubkey) {
      return [n.pubkey, { node:n, online:true, chunks:new Set(inventory().map(x => x.hash)), error:null }];
    }
    try {
      const r = await fetch(`${nodeUrl(n)}/api/launch/inventory`, { cache:'no-store', signal:AbortSignal.timeout(REPAIR_PROBE_TIMEOUT_MS) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      return [n.pubkey, { node:n, online:true, chunks:new Set((Array.isArray(j && j.chunks) ? j.chunks : []).map(x => safe(x && x.hash,80).toLowerCase()).filter(x => /^[0-9a-f]{64}$/.test(x))), error:null }];
    } catch (e) {
      return [n.pubkey, { node:n, online:false, chunks:new Set(), error:safe(e && e.message || e,180) || 'unreachable' }];
    }
  }));
  return new Map(entries.filter(x => x[0]));
}

function repairBackoffMs(attempts) {
  return Math.min(REPAIR_BACKOFF_MAX_MS, 5000 * Math.pow(2, Math.max(0, Math.min(6, Number(attempts || 1) - 1))));
}

async function fetchVerifiedRepairChunk(hashHex, sources, localPubkey) {
  for (const state of sources) {
    const src = state && state.node;
    if (!src || src.pubkey === localPubkey || !state.online || !state.chunks.has(hashHex)) continue;
    const base = nodeUrl(src);
    if (!base) continue;
    try {
      const r = await fetch(`${base}/api/launch/chunks/${hashHex}`, { cache:'no-store', signal:AbortSignal.timeout(REPAIR_FETCH_TIMEOUT_MS) });
      if (!r.ok) continue;
      const b = Buffer.from(await r.arrayBuffer());
      if (b.length > MAX_CHUNK || hash(b) !== hashHex) continue;
      return b;
    } catch {}
  }
  return null;
}

async function repairReplicas() {
  if (repairBusy || !isFinalized()) return;
  repairBusy = true;
  const startedAt = Date.now();
  const previous = loadRepairState();
  const attempts = previous.attempts && typeof previous.attempts === 'object' ? previous.attempts : {};
  try {
    const local = localNodePubkey(), cluster = clusterStatus(), nodes = (cluster.managedNodes || []).filter(n => n && n.pubkey && nodeUrl(n));
    if (!local || !nodes.some(n => n.pubkey === local)) return;

    const observed = await repairInventorySnapshot(nodes, local);
    const liveStates = [...observed.values()].filter(x => x.online && x.node && x.node.pubkey);
    const liveNodes = liveStates.map(x => x.node);
    const localState = observed.get(local);
    const files = Object.values((manifestState() || {}).files || {});
    const fileHealth = {};
    let repairedThisRun = 0, underReplicatedChunks = 0, missingChunks = 0;
    const activeHashes = new Set();

    for (const f of files) {
      if (!f || !f.fileId || !Array.isArray(f.chunks)) continue;
      const target = Math.max(1, Math.min(nodes.length, Number(f.replicationTarget) || 1));
      const row = { fileId:f.fileId, target, totalChunks:0, healthyReplicas:target, underReplicatedChunks:0, missingChunks:0, repairingChunks:0, chunks:{} };
      for (const c of f.chunks) {
        const h = safe(c && c.hash, 80).toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(h)) continue;
        activeHashes.add(h); row.totalChunks++;

        let holders = liveStates.filter(x => x.chunks.has(h));
        let holderKeys = holders.map(x => x.node.pubkey);
        const desiredLive = liveNodes.length ? desiredNodes(f.fileId, h, Math.min(target, liveNodes.length), liveNodes) : [];
        const localWanted = desiredLive.some(n => n.pubkey === local);
        const localHas = !!(localState && localState.chunks.has(h));
        const attempt = attempts[h] && typeof attempts[h] === 'object' ? attempts[h] : { attempts:0, lastError:null, nextAttemptAt:0, lastAttemptAt:null, lastSuccessAt:null };

        if (localWanted && !localHas && holders.length) {
          row.repairingChunks++;
          if (Date.now() >= Number(attempt.nextAttemptAt || 0)) {
            attempt.lastAttemptAt = Date.now();
            const orderedSources = [
              ...desiredLive.map(n => observed.get(n.pubkey)).filter(Boolean),
              ...holders
            ].filter((x, i, a) => x && a.findIndex(y => y && y.node.pubkey === x.node.pubkey) === i);
            try {
              const data = await fetchVerifiedRepairChunk(h, orderedSources, local);
              if (!data) throw new Error('No reachable replica returned a valid SHA-256 chunk.');
              const dest = chunkPath(h); fs.mkdirSync(path.dirname(dest), { recursive:true });
              const tmp = `${dest}.repair-${process.pid}-${Date.now()}`;
              try { fs.writeFileSync(tmp, data); if (hash(fs.readFileSync(tmp)) !== h) throw new Error('Post-write SHA-256 verification failed.'); fs.renameSync(tmp, dest); }
              catch (e) { try { fs.rmSync(tmp, { force:true }); } catch {} throw e; }
              localState.chunks.add(h); repairedThisRun++;
              attempt.attempts = 0; attempt.lastError = null; attempt.nextAttemptAt = 0; attempt.lastSuccessAt = Date.now();
              holders = liveStates.filter(x => x.chunks.has(h)); holderKeys = holders.map(x => x.node.pubkey);
            } catch (e) {
              attempt.attempts = Number(attempt.attempts || 0) + 1;
              attempt.lastError = safe(e && e.message || e, 240);
              attempt.nextAttemptAt = Date.now() + repairBackoffMs(attempt.attempts);
            }
          }
        }
        attempts[h] = attempt;

        const count = holderKeys.length;
        row.healthyReplicas = Math.min(row.healthyReplicas, count);
        if (count < target) { row.underReplicatedChunks++; underReplicatedChunks++; }
        if (count < 1) { row.missingChunks++; missingChunks++; }
        row.chunks[h] = {
          replicas:holderKeys,
          desired:desiredLive.map(n => n.pubkey),
          target,
          healthy:count,
          status:count < 1 ? 'missing' : count < target ? 'repairing' : 'healthy',
          lastError:attempt.lastError || null,
          nextAttemptAt:Number(attempt.nextAttemptAt || 0) || null
        };
      }
      if (!row.totalChunks) row.healthyReplicas = 0;
      row.status = row.missingChunks ? 'critical' : row.underReplicatedChunks ? 'repairing' : 'healthy';
      fileHealth[f.fileId] = row;
    }

    for (const h of Object.keys(attempts)) if (!activeHashes.has(h)) delete attempts[h];
    const state = {
      schema:2,
      updatedAt:Date.now(),
      durationMs:Date.now() - startedAt,
      localPubkey:local,
      targetManagedNodes:nodes.length,
      onlineNodes:liveStates.map(x => x.node.pubkey),
      offlineNodes:[...observed.values()].filter(x => !x.online && x.node).map(x => ({ pubkey:x.node.pubkey, domain:x.node.domain || null, error:x.error || 'unreachable' })),
      repairedThisRun,
      underReplicatedChunks,
      missingChunks,
      files:fileHealth,
      attempts
    };
    saveRepairState(state);
  } catch (e) {
    saveRepairState({ ...previous, schema:2, updatedAt:Date.now(), durationMs:Date.now()-startedAt, lastError:safe(e && e.stack || e, 1200), attempts });
  } finally { repairBusy = false; }
}


function aiTagLocalFiles() {
  const root = stateRoot();
  if (!root) return null;
  const dir = path.resolve(root, '..', 'ai-tagging');
  return { dir, result:path.join(dir, AI_TAG_RESULT_NAME), attestation:path.join(dir, AI_TAG_ATTESTATION_NAME), work:path.join(dir, AI_TAG_NPL_WORK_NAME), worker:path.join(dir, AI_TAG_WORKER_STATE_NAME), log:path.join(dir, AI_TAG_WORKER_LOG_NAME), failures:path.join(dir, AI_TAG_FAILURES_NAME) };
}

function atomicJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive:true, mode:0o700 });
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode:0o600 });
  fs.renameSync(tmp, file);
}

function normalizeAiTag(value) {
  let s = safe(value, 96).toLowerCase();
  try { s = s.normalize('NFKD').replace(/[\u0300-\u036f]/g, ''); } catch {}
  s = s.replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-+/g, '-');
  return s.length >= 2 && s.length <= 32 ? s : null;
}

function normalizeAiTags(values, max = 12) {
  const out = [];
  for (const raw of Array.isArray(values) ? values : []) {
    const tag = normalizeAiTag(raw);
    if (tag && !out.includes(tag)) out.push(tag);
    if (out.length >= max) break;
  }
  return out;
}

function parseModelTags(content, max) {
  const raw = safe(content, 20000);
  const candidates = [];
  const wantedKeys = new Set(['tags','choices','labels','categories','keywords','topics','result','output','data']);
  const collect = (value, depth = 0, hinted = false) => {
    if (depth > 4 || value == null) return;
    if (typeof value === 'string') {
      if (hinted) candidates.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string') candidates.push(item);
        else collect(item, depth + 1, true);
      }
      return;
    }
    if (typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        const keyLower = String(key || '').toLowerCase();
        const keyLooksLikeTag = /^(tag|label|keyword|topic)\d*$/.test(keyLower);
        if (typeof child === 'string' && keyLooksLikeTag) candidates.push(child);
        else if (wantedKeys.has(keyLower) || keyLooksLikeTag) collect(child, depth + 1, true);
        else if (depth < 2 && child && typeof child === 'object') collect(child, depth + 1, false);
      }
    }
  };
  try { collect(JSON.parse(raw)); } catch {}
  if (!candidates.length) {
    const m = raw.match(/\[[\s\S]*?\]/);
    if (m) { try { collect(JSON.parse(m[0])); } catch {} }
  }
  if (!candidates.length) {
    for (const q of raw.matchAll(/["'`]([a-zA-Z0-9][a-zA-Z0-9 _./-]{1,40})["'`]/g)) candidates.push(q[1]);
  }
  if (!candidates.length) candidates.push(...raw.split(/[\n,;|]+/).map(x => x.replace(/^[-*\d.)\s]+/, '').trim()));
  return normalizeAiTags(candidates, max);
}

function aiModelResponseDiagnostics(j) {
  const content = String(j && j.message && j.message.content || '');
  const thinking = String(j && j.message && j.message.thinking || '');
  let responseShape = 'empty';
  if (content.trim()) {
    try {
      const parsed = JSON.parse(content);
      responseShape = Array.isArray(parsed) ? 'json-array' : parsed && typeof parsed === 'object' ? `json-object:${Object.keys(parsed).slice(0,8).join(',')}` : `json-${typeof parsed}`;
    } catch { responseShape = 'text'; }
  } else if (thinking.trim()) responseShape = 'thinking-only';
  const responsePreview = content.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').replace(/[^\x20-\x7E]/g, '?').slice(0, 240);
  return {
    contentBytes:Buffer.byteLength(content, 'utf8'),
    thinkingBytes:Buffer.byteLength(thinking, 'utf8'),
    doneReason:safe(j && (j.done_reason || j.doneReason), 80) || '-',
    responseShape,
    responsePreview
  };
}

const TEXT_EXTENSIONS = new Set(['.txt','.md','.markdown','.json','.jsonl','.csv','.tsv','.xml','.html','.htm','.css','.js','.mjs','.cjs','.ts','.tsx','.jsx','.py','.rb','.php','.java','.c','.h','.cpp','.hpp','.go','.rs','.sh','.bash','.zsh','.yaml','.yml','.toml','.ini','.cfg','.conf','.log','.sql','.rtf']);
const IMAGE_EXTENSIONS = new Set(['.jpg','.jpeg','.png','.gif','.webp','.bmp','.tif','.tiff','.svg','.heic','.avif']);
const VIDEO_EXTENSIONS = new Set(['.mp4','.mov','.mkv','.webm','.avi','.m4v']);
const AUDIO_EXTENSIONS = new Set(['.mp3','.wav','.flac','.m4a','.aac','.ogg','.opus']);
const ARCHIVE_EXTENSIONS = new Set(['.zip','.tar','.gz','.tgz','.bz2','.xz','.7z','.rar']);
const SHEET_EXTENSIONS = new Set(['.xls','.xlsx','.ods']);
const SLIDE_EXTENSIONS = new Set(['.ppt','.pptx','.odp']);
const DOC_EXTENSIONS = new Set(['.doc','.docx','.odt','.pdf']);

function filenameFallbackTags(file) {
  const ext = path.extname(String(file.name || '')).toLowerCase();
  const base = path.basename(String(file.name || ''), ext).toLowerCase();
  const stop = new Set(['the','and','for','with','from','this','that','file','copy','final','new','old','untitled','document','img','image','scan']);
  const words = base.split(/[^a-z0-9]+/).map(normalizeAiTag).filter(x => x && x.length > 2 && !stop.has(x));
  const out = [];
  const push = x => { const t=normalizeAiTag(x); if(t&&!out.includes(t))out.push(t); };
  if (IMAGE_EXTENSIONS.has(ext)) { push('image'); push('photo'); }
  else if (VIDEO_EXTENSIONS.has(ext)) { push('video'); push('media'); }
  else if (AUDIO_EXTENSIONS.has(ext)) { push('audio'); push('media'); }
  else if (ARCHIVE_EXTENSIONS.has(ext)) { push('archive'); push('compressed'); }
  else if (SHEET_EXTENSIONS.has(ext)) { push('spreadsheet'); push('data'); }
  else if (SLIDE_EXTENSIONS.has(ext)) { push('presentation'); push('slides'); }
  else if (DOC_EXTENSIONS.has(ext)) { push(ext === '.pdf' ? 'pdf' : 'document'); push('document'); }
  else if (TEXT_EXTENSIONS.has(ext)) {
    const isCode=['.js','.mjs','.cjs','.ts','.tsx','.jsx','.py','.rb','.php','.java','.c','.h','.cpp','.hpp','.go','.rs','.sh','.sql'].includes(ext);
    push(isCode ? 'code' : 'text'); push(isCode ? 'source-code' : 'text-file');
  } else push('binary');
  if (ext) push(ext.slice(1));
  for (const w of words) push(w);
  return out.slice(0, 12);
}

async function getChunkForAi(chunkHash) {
  const dest = chunkPath(chunkHash);
  try {
    const b = fs.readFileSync(dest);
    if (hash(b) === chunkHash) return b;
  } catch {}
  for (const n of (clusterStatus().managedNodes || [])) {
    const base = nodeUrl(n); if (!base) continue;
    try {
      const r = await fetch(`${base}/api/launch/chunks/${chunkHash}`, { cache:'no-store', signal:AbortSignal.timeout(10000) });
      if (!r.ok) continue;
      const b = Buffer.from(await r.arrayBuffer());
      if (b.length <= MAX_CHUNK && hash(b) === chunkHash) return b;
    } catch {}
  }
  return null;
}

async function publicFilePreview(file, limit = AI_TAG_PREVIEW_BYTES) {
  const ext = path.extname(String(file.name || '')).toLowerCase();
  const wantsText = TEXT_EXTENSIONS.has(ext) || ext === '.pdf';
  if (!wantsText || !Array.isArray(file.chunks) || !file.chunks.length || Number(file.size || 0) <= 0) return '';
  const parts = [];
  let total = 0;
  for (const c of file.chunks) {
    if (!c || !/^[0-9a-f]{64}$/.test(String(c.hash || ''))) continue;
    const b = await getChunkForAi(c.hash);
    if (!b) break;
    const take = b.subarray(0, Math.max(0, Math.min(b.length, limit - total)));
    parts.push(take); total += take.length;
    if (total >= limit) break;
  }
  if (!parts.length) return '';
  const b = Buffer.concat(parts);
  if (ext === '.pdf') {
    const latin = b.toString('latin1');
    const strings = latin.match(/[A-Za-z0-9][A-Za-z0-9 .,;:_()\/\-]{5,}/g) || [];
    return strings.join(' ').replace(/\s+/g, ' ').slice(0, 12000);
  }
  let t = b.toString('utf8').replace(/\0/g, ' ');
  const controls = (t.match(/[\u0001-\u0008\u000b\u000c\u000e-\u001f]/g) || []).length;
  if (controls > Math.max(8, t.length * 0.02)) return '';
  return t.replace(/\s+/g, ' ').slice(0, 16000);
}

function aiFileDescription(file, preview) {
  const ext = path.extname(String(file.name || '')).toLowerCase().replace(/^\./, '') || 'none';
  const lines = [
    `filename: ${safe(file.name, 512)}`,
    `extension: ${ext}`,
    `size_bytes: ${Math.max(0, Number(file.size) || 0)}`
  ];
  if (preview) lines.push(`content_preview: ${preview}`);
  else lines.push('content_preview: unavailable; infer conservatively from filename and file type only');
  return lines.join('\n');
}

async function askTagModel(config, phase, file, preview, candidates = []) {
  const model = safe(config && config.model, 128);
  const requestedTemperature = taggingTemperature(config && config.temperature, 0.2);
  // CPU-safe structured tagging: tiny Qwen models are materially more reliable at
  // low temperature. Preserve user configuration in status, but cap the actual
  // tagging request for qwen3:0.6b and report the effective value in diagnostics.
  const temperature = /^qwen3:0\.6b(?:$|[-:])/i.test(model) ? Math.min(requestedTemperature, 0.2) : requestedTemperature;
  const profile = taggingProfile(config && config.profile, 'balanced');
  const seed = taggingSeed(config && config.seed);
  const style = taggingProfileInstruction(profile);
  const system = phase === 'suggest'
    ? `You are a simple file tagger. Return only JSON: {"tags":[...]}. Suggest exactly 5 distinct short lowercase reusable tags. Prefer useful semantic labels over raw filename tokens. Avoid sentences, duplicate meanings, private-fact guesses, and overly specific names. ${style}`
    : `You are a simple file tag voter. Return only JSON: {"tags":[...]}. Choose exactly 5 tags from the candidate list that best describe the file. Never invent a tag outside the candidate list. ${style}`;
  const user = phase === 'suggest'
    ? `${aiFileDescription(file, preview)}\n\nReturn exactly 5 distinct useful tags.`
    : `${aiFileDescription(file, preview)}\n\ncandidate_tags: ${JSON.stringify(candidates)}\n\nChoose the best 5 candidate tags.`;
  const j = await ollamaFetch('/api/chat', {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body:JSON.stringify({ model, messages:[{role:'system',content:system},{role:'user',content:user}], stream:false, think:false, format:'json', options:{ temperature, seed, num_predict:160 } })
  }, 180000);
  const diagnostics = { ...aiModelResponseDiagnostics(j), requestedTemperature, effectiveTemperature:temperature, think:false };
  const tags = parseModelTags(j && j.message && j.message.content || '', 12);
  return { tags, diagnostics };
}

function aiWorkMatchesManifest(work, files, local) {
  if (!work || work.type !== AI_TAG_LOCAL_RESULT_TYPE || work.validatorPubkey !== local) return false;
  const f = files && files[work.fileId];
  if (!f || f.visibility !== 'public' || f.aiTaggingEnabled !== true || f.tagStatus === 'tagged') return false;
  if (Number(work.round) !== Number(f.taggingRound) || String(work.originalHash || '') !== String(f.originalHash || '')) return false;
  if (work.phase === 'suggest') return f.tagStatus === 'suggesting' && !(f.aiSuggestions && f.aiSuggestions[local]);
  if (work.phase === 'vote') return f.tagStatus === 'voting' && (!Array.isArray(f.aiEligibleVoters) || !f.aiEligibleVoters.length || f.aiEligibleVoters.includes(local)) && !(f.aiVotes && f.aiVotes[local]) && work.candidateHash === f.candidateHash;
  return false;
}

function setAiWorkerState(paths, value) {
  if (!paths || !paths.worker) return;
  try {
    const prior = readJson(paths.worker, null);
    const next = { ...value, updatedAt:Date.now() };
    atomicJson(paths.worker, next);
    const priorKey = prior ? JSON.stringify([prior.state,prior.fileId,prior.phase,prior.round,prior.error,prior.reason]) : '';
    const nextKey = JSON.stringify([next.state,next.fileId,next.phase,next.round,next.error,next.reason]);
    if (paths.log && priorKey !== nextKey) {
      fs.mkdirSync(path.dirname(paths.log), { recursive:true, mode:0o700 });
      const row = `${new Date(next.updatedAt).toISOString()} state=${safe(next.state,48)||'unknown'} file=${safe(next.fileId,128)||'-'} phase=${safe(next.phase,24)||'-'} round=${Number(next.round)||0} model=${safe(next.model,128)||'-'}${next.rawTagCount!=null?` rawTags=${Number(next.rawTagCount)||0}`:''}${next.usableTagCount!=null?` usableTags=${Number(next.usableTagCount)||0}`:''}${next.attempt!=null?` attempt=${Number(next.attempt)||0}/${AI_TAG_MAX_MODEL_ATTEMPTS}`:''}${next.retryAfter?` retryAfter=${new Date(Number(next.retryAfter)).toISOString()}`:''}${next.action?` action=${safe(next.action,80)}`:''}${next.contentBytes!=null?` contentBytes=${Number(next.contentBytes)||0}`:''}${next.thinkingBytes!=null?` thinkingBytes=${Number(next.thinkingBytes)||0}`:''}${next.doneReason?` doneReason=${safe(next.doneReason,80)}`:''}${next.responseShape?` responseShape=${safe(next.responseShape,160)}`:''}${next.effectiveTemperature!=null?` effectiveTemp=${Number(next.effectiveTemperature)}`:''}${next.responsePreview?` responsePreview=${JSON.stringify(safe(next.responsePreview,240))}`:''}${next.error?` error=${safe(next.error,500)}`:''}${next.reason?` reason=${safe(next.reason,500)}`:''}\n`;
      fs.appendFileSync(paths.log, row, { encoding:'utf8', mode:0o600 });
      try {
        const st=fs.statSync(paths.log);
        if(st.size>512*1024){const b=fs.readFileSync(paths.log);fs.writeFileSync(paths.log,b.subarray(Math.max(0,b.length-256*1024)),{mode:0o600});}
      } catch {}
    }
  } catch {}
}


function aiFailureKey(fileId, phase, round) { return `${safe(fileId,128)}|${safe(phase,24)}|${Math.max(1,Number(round)||1)}`; }
function readAiFailures(paths) { const v=paths&&paths.failures?readJson(paths.failures,{}):{}; return v&&typeof v==='object'&&!Array.isArray(v)?v:{}; }
function writeAiFailures(paths, value) { if(paths&&paths.failures) atomicJson(paths.failures, value&&typeof value==='object'?value:{}); }
function clearAiFailure(paths, fileId, phase, round) {
  const failures=readAiFailures(paths), key=aiFailureKey(fileId,phase,round);
  if(Object.prototype.hasOwnProperty.call(failures,key)){ delete failures[key]; writeAiFailures(paths,failures); }
}
function noteAiFailure(paths, fileId, phase, round, error) {
  const failures=readAiFailures(paths), key=aiFailureKey(fileId,phase,round), prior=failures[key]||{};
  const attempts=Math.max(0,Number(prior.attempts)||0)+1, now=Date.now();
  const retryAfter=attempts>=AI_TAG_MAX_MODEL_ATTEMPTS ? now+AI_TAG_FAILURE_COOLDOWN_MS : now+10000;
  failures[key]={ attempts, lastError:safe(error,500), lastAt:now, retryAfter };
  writeAiFailures(paths,failures);
  return failures[key];
}
function aiFailureBlocked(paths, fileId, phase, round) {
  const failures=readAiFailures(paths), f=failures[aiFailureKey(fileId,phase,round)];
  return f&&Number(f.retryAfter)>Date.now()?f:null;
}

async function createAiTagWork() {
  const local = localNodePubkey();
  if (!local || !(clusterStatus().managedNodes || []).some(n => n.pubkey === local)) return false;
  const status = await ollamaStatus();
  const paths = aiTagLocalFiles(); if (!paths) return false;
  if (!status.taggingEnabled || !status.taggingModel) {
    setAiWorkerState(paths, { state:'disabled', validatorPubkey:local, model:status.taggingModel || null });
    return false;
  }
  const manifest = manifestState() || {}, files = manifest.files || {};
  const pendingAttestation = readJson(paths.attestation, null);
  if (pendingAttestation && pendingAttestation.type === AI_TAG_ATTESTATION_TYPE) {
    setAiWorkerState(paths, { state:'awaiting-consensus', validatorPubkey:local, fileId:pendingAttestation.fileId, phase:pendingAttestation.phase, round:pendingAttestation.round, model:pendingAttestation.model || status.taggingModel });
    return false;
  }
  const priorWorker = readJson(paths.worker, null);
  if (priorWorker && priorWorker.state === 'submitted' && priorWorker.validatorPubkey === local && priorWorker.fileId && priorWorker.phase && Number(priorWorker.round) > 0) {
    const pf = files[priorWorker.fileId];
    const alreadyCommitted = priorWorker.phase === 'suggest'
      ? !!(pf && pf.aiSuggestions && pf.aiSuggestions[local])
      : !!(pf && pf.aiVotes && pf.aiVotes[local]);
    if (!alreadyCommitted && Date.now() - Number(priorWorker.submittedAt || 0) < 90000) {
      setAiWorkerState(paths, { ...priorWorker, state:'awaiting-consensus-state' });
      return false;
    }
  }
  const existing = readJson(paths.result, null);
  if (existing) {
    if (aiWorkMatchesManifest(existing, files, local)) {
      setAiWorkerState(paths, { state:'result-ready', validatorPubkey:local, fileId:existing.fileId, phase:existing.phase, round:existing.round, model:existing.model || status.taggingModel, resultCreatedAt:existing.createdAt || null, transport:'node-party-line' });
      return false;
    }
    try { fs.rmSync(paths.result, { force:true }); } catch {}
  }

  // AI work is assigned by the smart contract over HotPocket Node Party Line.
  // The sidecar no longer scans the manifest and invents work on its own.
  const dispatch = readJson(paths.work, null);
  const fresh = dispatch && dispatch.type === AI_TAG_NPL_WORK_TYPE && Array.isArray(dispatch.items) && Date.now() - Number(dispatch.receivedAtMs || 0) < 10 * 60 * 1000;
  if (!fresh) {
    setAiWorkerState(paths, { state:'waiting-npl', validatorPubkey:local, model:status.taggingModel, transport:'node-party-line' });
    return false;
  }

  let file = null, phase = null, skippedFailure = null, skippedMembership = null;
  for (const item of dispatch.items) {
    const f = item && files[item.fileId];
    if (!f || f.visibility !== 'public' || f.aiTaggingEnabled !== true || f.tagStatus === 'tagged') continue;
    if (Array.isArray(f.aiParticipants) && f.aiParticipants.length && !f.aiParticipants.includes(local)) { skippedMembership = { fileId:f.fileId, phase:item.phase, round:Number(f.taggingRound)||1 }; continue; }
    if (Number(item.round) !== Number(f.taggingRound) || String(item.originalHash || '') !== String(f.originalHash || '')) continue;
    const itemPhase = item.phase === 'vote' ? 'vote' : item.phase === 'suggest' ? 'suggest' : null;
    if (!itemPhase) continue;
    const blocked = aiFailureBlocked(paths, f.fileId, itemPhase, Number(f.taggingRound)||1);
    if (blocked) { skippedFailure = { fileId:f.fileId, phase:itemPhase, ...blocked }; continue; }
    if (itemPhase === 'suggest' && f.tagStatus === 'suggesting' && !(f.aiSuggestions && f.aiSuggestions[local])) { file=f; phase='suggest'; break; }
    if (itemPhase === 'vote' && f.tagStatus === 'voting' && (!Array.isArray(f.aiEligibleVoters) || !f.aiEligibleVoters.length || f.aiEligibleVoters.includes(local)) && !(f.aiVotes && f.aiVotes[local]) && item.candidateHash === f.candidateHash && Array.isArray(f.candidateTags) && f.candidateTags.length >= 5) { file=f; phase='vote'; break; }
  }
  if (!file || !phase) {
    setAiWorkerState(paths, skippedFailure ? { state:'cooldown', validatorPubkey:local, fileId:skippedFailure.fileId, phase:skippedFailure.phase, round:skippedFailure.round||1, model:status.taggingModel, attempt:skippedFailure.attempts, retryAfter:skippedFailure.retryAfter, action:'skip-poisoned-work', reason:skippedFailure.lastError, transport:'node-party-line', lastDispatchLcl:dispatch.receivedAtLcl || null } : skippedMembership ? { state:'not-participant', validatorPubkey:local, fileId:skippedMembership.fileId, phase:skippedMembership.phase, round:skippedMembership.round, model:status.taggingModel, reason:'This validator is not in the consensus AI participant set for the active tagging round.', transport:'node-party-line', lastDispatchLcl:dispatch.receivedAtLcl || null } : { state:'idle', validatorPubkey:local, model:status.taggingModel, transport:'node-party-line', lastDispatchLcl:dispatch.receivedAtLcl || null });
    return false;
  }

  const startedAt = Date.now();
  const taggerConfig = { model:status.taggingModel, temperature:status.taggingTemperature, profile:status.taggingProfile, seed:status.taggingSeed };
  setAiWorkerState(paths, { state:'processing', validatorPubkey:local, fileId:file.fileId, fileName:file.name, phase, round:Number(file.taggingRound) || 1, model:status.taggingModel, temperature:status.taggingTemperature, profile:status.taggingProfile, seed:status.taggingSeed, startedAt, transport:'node-party-line' });
  const preview = await publicFilePreview(file);
  let tags = [], modelError = null, modelDiagnostics = null;
  try {
    const answer = await askTagModel(taggerConfig, phase, file, preview, file.candidateTags || []);
    tags = answer && Array.isArray(answer.tags) ? answer.tags : [];
    modelDiagnostics = answer && answer.diagnostics ? answer.diagnostics : null;
  }
  catch (e) { modelError = safe(e && e.message || e, 300); }
  if (phase === 'suggest') {
    const rawTagCount = Array.isArray(tags) ? tags.length : 0;
    tags = normalizeAiTags(tags, 12);
    const modelUsableCount = tags.length;
    // Suggestions are useful even when a small model returns only 3-4 clean tags.
    // Prefer filling to five with conservative filename/type hints, but do not
    // deadlock the queue if only 3-4 semantic tags survive normalization.
    if (tags.length > 0 && tags.length < 5) {
      const fallback = filenameFallbackTags(file);
      for (const t of fallback) if (!tags.includes(t) && tags.length < 5) tags.push(t);
    }
    tags = normalizeAiTags(tags, 5);
    if (tags.length < 3) {
      const failure = noteAiFailure(paths, file.fileId, phase, Number(file.taggingRound)||1, modelError || `Model produced only ${tags.length} usable unique tags.`);
      setAiWorkerState(paths, { state:failure.attempts>=AI_TAG_MAX_MODEL_ATTEMPTS?'cooldown':'error', validatorPubkey:local, fileId:file.fileId, fileName:file.name, phase, round:Number(file.taggingRound) || 1, model:status.taggingModel, startedAt, rawTagCount, usableTagCount:tags.length, attempt:failure.attempts, retryAfter:failure.retryAfter, action:failure.attempts>=AI_TAG_MAX_MODEL_ATTEMPTS?'skip-poisoned-work':'retry-later', ...(modelDiagnostics||{}), error:modelError || `Model produced only ${tags.length} usable unique tags; need at least 3.`, transport:'node-party-line' });
      return false;
    }
    clearAiFailure(paths, file.fileId, phase, Number(file.taggingRound)||1);
    setAiWorkerState(paths, { state:'processing', validatorPubkey:local, fileId:file.fileId, fileName:file.name, phase, round:Number(file.taggingRound)||1, model:status.taggingModel, startedAt, rawTagCount, usableTagCount:tags.length, action:tags.length<5?'accept-partial':'accept', ...(modelDiagnostics||{}), reason:modelUsableCount<5?`model produced ${modelUsableCount} usable tag(s); conservative fallback/partial acceptance applied`:null, transport:'node-party-line' });
  } else {
    const allowed = new Set((file.candidateTags || []).map(normalizeAiTag).filter(Boolean));
    tags = normalizeAiTags(tags, 5).filter(t => allowed.has(t));
    for (const t of file.candidateTags || []) if (tags.length < 5 && allowed.has(t) && !tags.includes(t)) tags.push(t);
    tags = tags.slice(0, 5);
    if (tags.length !== 5) {
      setAiWorkerState(paths, { state:'error', validatorPubkey:local, fileId:file.fileId, fileName:file.name, phase, round:Number(file.taggingRound) || 1, model:status.taggingModel, startedAt, ...(modelDiagnostics||{}), error:modelError || 'Model did not select exactly 5 valid candidate tags.', transport:'node-party-line' });
      return false;
    }
  }
  const result = {
    type:AI_TAG_LOCAL_RESULT_TYPE,
    validatorPubkey:local,
    fileId:file.fileId,
    round:Number(file.taggingRound) || 1,
    phase,
    originalHash:file.originalHash,
    candidateHash:phase === 'vote' ? file.candidateHash : null,
    tags,
    model:status.taggingModel,
    temperature:status.taggingTemperature,
    profile:status.taggingProfile,
    seed:status.taggingSeed,
    createdAt:Date.now()
  };
  atomicJson(paths.result, result);
  setAiWorkerState(paths, { state:'result-ready', validatorPubkey:local, fileId:file.fileId, fileName:file.name, phase, round:result.round, model:status.taggingModel, temperature:status.taggingTemperature, profile:status.taggingProfile, seed:status.taggingSeed, startedAt, resultCreatedAt:result.createdAt, tagCount:tags.length, ...(modelDiagnostics||{}), transport:'node-party-line', modelWarning:modelError });
  return true;
}

function normalizeHpPrivate(value) {
  let raw = safe(value, 512).toLowerCase().replace(/\s+/g, '');
  if (raw.startsWith('ed')) raw = raw.slice(2);
  return /^[0-9a-f]{128}$/.test(raw) ? `ed${raw}` : null;
}

function hpPublicKey(value) {
  if (typeof value === 'string') return normalizePubkey(value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    let b = Buffer.from(value); if (b.length === 33 && b[0] === 0xed) b = b.subarray(1);
    return b.length === 32 ? `ed${b.toString('hex')}` : null;
  }
  return null;
}

let aiRelayIdentity = null;
async function ensureAiRelayIdentity() {
  if (aiRelayIdentity) return aiRelayIdentity;
  const HotPocket = require('hotpocket-js-client');
  let saved = null;
  try { saved = normalizeHpPrivate(fs.readFileSync(AI_TAG_RELAY_SECRET, 'utf8')); } catch {}
  let pair = null;
  if (saved) { try { pair = await HotPocket.generateKeys(saved); } catch {} }
  if (!pair) {
    pair = await HotPocket.generateKeys();
    fs.mkdirSync(path.dirname(AI_TAG_RELAY_SECRET), { recursive:true, mode:0o700 });
    const tmp = `${AI_TAG_RELAY_SECRET}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `ed${Buffer.from(pair.privateKey).toString('hex')}\n`, { mode:0o600 });
    fs.renameSync(tmp, AI_TAG_RELAY_SECRET);
  }
  const publicKey = hpPublicKey(pair.publicKey);
  if (!publicKey) throw new Error('Could not derive AI tagging relay identity.');
  aiRelayIdentity = { pair, publicKey };
  return aiRelayIdentity;
}

function localUserPort() {
  const cfg = readJson('/contract/cfg/hp.cfg', null) || readJson('/contract/hp.cfg', null) || {};
  const n = Number(cfg && cfg.user && cfg.user.port);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
}

async function relayAiTagAttestation() {
  const paths = aiTagLocalFiles(); if (!paths || !fs.existsSync(paths.attestation)) return false;
  const report = readJson(paths.attestation, null);
  if (!report || report.type !== AI_TAG_ATTESTATION_TYPE) { try { fs.rmSync(paths.attestation, { force:true }); } catch {} return false; }
  const local = localNodePubkey(), port = localUserPort();
  if (!local || report.validatorPubkey !== local || !port) return false;
  const identity = await ensureAiRelayIdentity();
  const HotPocket = require('hotpocket-js-client');
  let client = null;
  try {
    client = await HotPocket.createClient([`wss://127.0.0.1:${port}`], identity.pair, { trustedServerKeys:[local], requiredConnectionCount:1, connectionTimeoutMs:8000 });
    const connected = await client.connect();
    if (!connected) throw new Error('AI tagging relay could not connect to local HotPocket user.port.');
    const submitted = await client.submitContractInput(JSON.stringify(report), undefined, 4, true);
    if (!submitted || !submitted.submissionStatus) throw new Error('AI tagging relay returned no submission status.');
    const status = await Promise.race([
      submitted.submissionStatus,
      new Promise((_, reject) => setTimeout(() => reject(new Error('AI tagging relay submission timed out.')), 30000))
    ]);
    if (status && status.status === 'accepted') {
      // Submission acceptance only means HotPocket admitted the input. Keep the
      // exact generated result until the manifest confirms this validator's
      // suggestion/vote was committed. If consensus has not reflected it after
      // the submitted-state grace period, the same signed work can be retried
      // instead of being silently discarded and regenerated.
      try { fs.rmSync(paths.attestation, { force:true }); } catch {}
      setAiWorkerState(paths, { state:'submitted', validatorPubkey:local, fileId:report.fileId, phase:report.phase, round:report.round, model:report.model || null, transport:'node-party-line', submittedAt:Date.now(), action:'await-consensus-confirmation' });
      return true;
    }
    return false;
  } finally {
    try { await client?.close(); } catch {}
  }
}

let aiTagBusy = false;
async function aiTaggingLoop() {
  if (aiTagBusy || !isFinalized()) return;
  // Global backend kill switch for the AI *file-tagging* subsystem. Do not
  // create new model work and do not relay already-prepared attestations while
  // disabled. General Ollama/OpenAI-compatible endpoints remain available.
  if (!aiFilesBackendEnabled()) {
    const paths = aiTagLocalFiles();
    if (paths) setAiWorkerState(paths, { state:'disabled-backend', validatorPubkey:localNodePubkey(), reason:'AI file tagging disabled by backend configuration' });
    return;
  }
  aiTagBusy = true;
  try {
    const relayed = await relayAiTagAttestation().catch(() => false);
    if (!relayed) await createAiTagWork().catch(() => false);
  } finally { aiTagBusy = false; }
}

// Generate the node-local gateway key at boot. Ollama itself is optional and is
// installed later, per managed validator, from the authenticated EverAdmin AI tab.
// Supervisor runs a tiny idle launcher until the on-demand runtime appears.
setTimeout(() => { try { ensureAiApiKey(false); } catch {} repairReplicas().catch(() => {}); aiTaggingLoop().catch(() => {}); }, 2000).unref?.();
setInterval(() => repairReplicas().catch(() => {}), 30000).unref();
setInterval(() => aiTaggingLoop().catch(() => {}), 10000).unref();

async function handle(req, res, url) {
  const pathname = url.pathname;
  if (pathname.startsWith('/api/launch/')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Launch-AI-Key,X-Launch-Public-Key,X-Launch-Timestamp,X-Launch-Signature');
    if (req.method === 'OPTIONS') { res.statusCode = 204; res.end(); return true; }
  }

  if (req.method === 'GET' && pathname === '/index-preview.html') return sendJson(res, 404, { ok:false, error:'Preview is disabled. Finalize the cluster before opening the storage portal.' }) || true;
  if (req.method === 'GET' && pathname === '/launch-portal.html') {
    if (!isFinalized()) return sendJson(res, 423, { ok:false, error:'Storage portal is locked until cluster finalization completes.' }) || true;
    return sendFile(res, '/opt/eversmartnode/contract/launch-portal.html', 'text/html; charset=utf-8') || false;
  }
  if (req.method === 'GET' && pathname === '/api/launch/finalized') return sendJson(res, 200, { ok:true, finalized:isFinalized(), cluster:clusterStatus() }) || true;
  if (req.method === 'GET' && pathname === '/api/launch/nodes') return sendJson(res, 200, { ok:true, cluster:clusterStatus() }) || true;
  if (req.method === 'GET' && pathname === '/api/launch/inventory') return sendJson(res, 200, { ok:true, chunks:inventory(), storageRoot:DATA_DIR }) || true;
  if (req.method === 'GET' && pathname === '/api/launch/replication/status') {
    const state = loadRepairState();
    return sendJson(res, 200, { ok:true, ...state, running:repairBusy }) || true;
  }

  if (req.method === 'GET' && pathname.startsWith('/api/launch/chunks/')) {
    const h = cleanHash(pathname.split('/').pop()), f = chunkPath(h);
    if (!fs.existsSync(f)) return sendJson(res, 404, { ok:false, error:'Chunk not found.' }) || true;
    const b = fs.readFileSync(f);
    if (hash(b) !== h) return sendJson(res, 409, { ok:false, error:'Stored chunk failed integrity check.' }) || true;
    res.statusCode = 200; res.setHeader('Content-Type', 'application/octet-stream'); res.setHeader('Content-Length', b.length); res.setHeader('ETag', `"${h}"`); res.end(b); return true;
  }
  if (req.method === 'PUT' && pathname.startsWith('/api/launch/chunks/')) {
    const h = cleanHash(pathname.split('/').pop()), b = await body(req, MAX_CHUNK);
    verifySignature(req, b, false);
    if (hash(b) !== h) return sendJson(res, 400, { ok:false, error:'Chunk hash does not match URL.' }) || true;
    const f = chunkPath(h); fs.mkdirSync(path.dirname(f), { recursive:true });
    let validExisting = false;
    if (fs.existsSync(f)) {
      try { const existing = fs.readFileSync(f); validExisting = existing.length === b.length && hash(existing) === h; } catch {}
    }
    if (!validExisting) {
      const tmp = `${f}.tmp-${process.pid}-${Date.now()}`;
      try {
        fs.writeFileSync(tmp, b);
        if (hash(fs.readFileSync(tmp)) !== h) throw new Error('Post-write SHA-256 verification failed.');
        fs.renameSync(tmp, f);
      } catch (e) { try { fs.rmSync(tmp, { force:true }); } catch {} throw e; }
    }
    return sendJson(res, 200, { ok:true, hash:h, size:b.length, alreadyPresent:validExisting }) || true;
  }
  if (req.method === 'DELETE' && pathname.startsWith('/api/launch/chunks/')) {
    const h = cleanHash(pathname.split('/').pop()), b = Buffer.alloc(0); verifySignature(req, b, true);
    try { fs.rmSync(chunkPath(h), { force:true }); } catch {}
    return sendJson(res, 200, { ok:true, hash:h }) || true;
  }

  if (req.method === 'GET' && pathname === '/api/launch/ai/status') {
    return sendJson(res, 200, { ok:true, ...await ollamaStatus() }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/files-enabled') {
    const { raw, json } = await parseJsonBody(req); verifySignature(req, raw, true);
    if (typeof json.enabled !== 'boolean') throw new Error('enabled must be true or false.');
    const forced = envBool(process.env.EVERSMARTNODE_AI_FILES_ENABLED);
    if (forced !== null) {
      throw new Error(`AI file tagging is locked by EVERSMARTNODE_AI_FILES_ENABLED=${forced ? 'true' : 'false'}; change the backend environment variable and restart the service.`);
    }
    const prior = readJson(AI_FILE, {});
    writeJson(AI_FILE, { ...prior, aiFilesEnabled:json.enabled, updatedAt:Date.now() });
    return sendJson(res, 200, { ok:true, message:`AI file tagging ${json.enabled ? 'enabled' : 'disabled'} on this validator.`, ...await ollamaStatus() }) || true;
  }
  if (req.method === 'GET' && pathname === '/api/launch/ai/key') {
    verifySignature(req, Buffer.alloc(0), true);
    return sendJson(res, 200, { ok:true, apiKey:ensureAiApiKey(false), basePath:'/api/launch/ai/v1', openAiBasePath:'/api/launch/ai/v1' }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/key/rotate') {
    const { raw } = await parseJsonBody(req); verifySignature(req, raw, true);
    return sendJson(res, 200, { ok:true, apiKey:ensureAiApiKey(true), basePath:'/api/launch/ai/v1', openAiBasePath:'/api/launch/ai/v1' }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/install') {
    const { raw } = await parseJsonBody(req); verifySignature(req, raw, true);
    const job = startOllamaInstall();
    return sendJson(res, 202, { ok:true, ...job, status:await ollamaStatus() }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/restart') {
    const { raw } = await parseJsonBody(req); verifySignature(req, raw, true);
    await restartOllama();
    return sendJson(res, 200, { ok:true, ...await ollamaStatus() }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/pull') {
    const { raw, json } = await parseJsonBody(req); verifySignature(req, raw, true);
    const model = safe(json.model, 128);
    if (!/^[a-zA-Z0-9._:/-]{1,128}$/.test(model)) throw new Error('Invalid model name.');
    if (!(await ollamaStatus()).running) await restartOllama();
    if (!(await ollamaStatus()).installed) throw new Error('Ollama is not installed on this instance. Use Install Ollama first.');
    await command(OLLAMA_BIN, ['pull', model], 1800000);
    const prior = readJson(AI_FILE, {});
    writeJson(AI_FILE, { ...prior, enabled:true, updatedAt:Date.now(), lastPulledModel:model, taggingModel:prior.taggingModel || model });
    return sendJson(res, 200, { ok:true, model, ...await ollamaStatus() }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/tagging-config') {
    const { raw, json } = await parseJsonBody(req); verifySignature(req, raw, true);
    const status = await ollamaStatus();
    const model = safe(json.model || status.taggingModel, 128);
    if (!/^[a-zA-Z0-9._:/-]{1,128}$/.test(model)) throw new Error('Choose an installed model.');
    if (!status.models.includes(model)) throw new Error(`Model ${model} is not installed on this validator.`);
    const temperature = taggingTemperature(json.temperature, status.taggingTemperature);
    const profile = taggingProfile(json.profile, status.taggingProfile);
    const seed = taggingSeed(json.seed, status.taggingSeed);
    const prior = readJson(AI_FILE, {});
    writeJson(AI_FILE, { ...prior, enabled:true, taggingModel:model, taggingTemperature:temperature, taggingProfile:profile, taggingSeed:seed, updatedAt:Date.now() });
    return sendJson(res, 200, { ok:true, message:'Active AI tagger settings saved.', ...await ollamaStatus() }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/chat') {
    const { raw, json } = await parseJsonBody(req); verifySignature(req, raw, true);
    const model = safe(json.model, 128), prompt = safe(json.prompt, 200000);
    if (!/^[a-zA-Z0-9._:/-]{1,128}$/.test(model) || !prompt) throw new Error('Model and prompt are required.');
    const j = await ollamaFetch('/api/chat', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ model, messages:[{ role:'user', content:prompt }], stream:false }) }, 300000);
    return sendJson(res, 200, { ok:true, model, message:j.message || null, response:j.message && j.message.content || '' }) || true;
  }

  // API-key protected OpenAI-compatible gateway for applications running on or
  // talking to a managed instance. Ollama itself stays private on 127.0.0.1.
  if (req.method === 'GET' && pathname === '/api/launch/ai/v1/models') {
    verifyAiApiKey(req);
    const s = await ollamaStatus();
    return sendJson(res, 200, { object:'list', data:(s.models || []).map(id => ({ id, object:'model', owned_by:'ollama' })) }) || true;
  }
  if (req.method === 'POST' && pathname === '/api/launch/ai/v1/chat/completions') {
    const { json } = await parseJsonBody(req); verifyAiApiKey(req);
    const model = safe(json.model, 128);
    const messages = Array.isArray(json.messages) ? json.messages.map(m => ({ role:safe(m && m.role, 32) || 'user', content:safe(m && m.content, 200000) })).filter(m => m.content) : [];
    if (!/^[a-zA-Z0-9._:/-]{1,128}$/.test(model) || !messages.length) throw new Error('model and messages are required.');
    if (json.stream === true) throw new Error('Streaming is not enabled on the GPTCP1 AI gateway yet; use stream=false.');
    const j = await ollamaFetch('/api/chat', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ model, messages, stream:false, options:json.options || undefined }) }, 300000);
    const content = j.message && j.message.content || '';
    const promptTokens = Number(j.prompt_eval_count || 0), completionTokens = Number(j.eval_count || 0);
    return sendJson(res, 200, {
      id:`chatcmpl-${crypto.randomBytes(12).toString('hex')}`,
      object:'chat.completion', created:Math.floor(Date.now() / 1000), model,
      choices:[{ index:0, message:{ role:'assistant', content }, finish_reason:j.done_reason || 'stop' }],
      usage:{ prompt_tokens:promptTokens, completion_tokens:completionTokens, total_tokens:promptTokens + completionTokens }
    }) || true;
  }

  // Once the final managed UNL is autonomous, / becomes the upload/storage app.
  // No browser-only portal flag is required, so a reload/restart cannot strand the
  // cluster on the launch wizard after handover.
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html') && isFinalized()) {
    return sendFile(res, '/opt/eversmartnode/contract/launch-portal.html', 'text/html; charset=utf-8') || false;
  }
  return false;
}

module.exports = { handle, clusterStatus, isFinalized };
