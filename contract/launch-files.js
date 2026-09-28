'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.resolve(process.cwd(), 'launch-files.json');
const LOCAL_AI_ROOT = path.resolve(process.cwd(), '..', 'ai-tagging');
const LOCAL_AI_RESULT_FILE = path.join(LOCAL_AI_ROOT, 'local-result.json');
const LOCAL_AI_ATTESTATION_FILE = path.join(LOCAL_AI_ROOT, 'signed-attestation.json');
const LOCAL_AI_NPL_WORK_FILE = path.join(LOCAL_AI_ROOT, 'npl-work.json');
const AI_ATTESTATION_TYPE = 'launch_ai_attestation_v1';
const AI_LOCAL_RESULT_TYPE = 'launch_ai_local_result_v1';
const AI_NPL_WORK_TYPE = 'launch_ai_work_npl_v1';
const AI_NPL_RESULT_TYPE = 'launch_ai_result_npl_v1';
const MAX_FILES = 20000;
const MAX_CHUNKS = 8192;
const MAX_NAME = 512;
const MAX_SUGGESTED_TAGS = 5;
const MIN_SUGGESTED_TAGS = 3;
const MAX_CANDIDATE_TAGS = 64;
const WINNING_TAGS = 5;
// AI round deadlines are consensus-ledger based. The first accepted suggestion
// starts a bounded collection window; all configured AI nodes can finish sooner.
// At the usual ~2 second ledger cadence 150 ledgers is roughly five minutes.
const SUGGEST_WINDOW_LCLS = 150;
const VOTE_WINDOW_LCLS = 150;
const AI_NPL_WORK_BATCH = 12;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive:true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}
function atomicWriteJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive:true });
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode:0o600 });
  fs.renameSync(tmp, file);
}
function text(v, max=4096) { return String(v == null ? '' : v).trim().slice(0,max); }
function nowMs(ctx) {
  const raw = Number(ctx && ctx.timestamp);
  if (Number.isFinite(raw) && raw > 0) return raw < 100000000000 ? Math.floor(raw * 1000) : Math.floor(raw);
  return 0;
}
function ledgerNo(ctx) {
  return Math.max(0, Number(ctx && (ctx.lclSeqNo || ctx.ledgerSeqNo || ctx.ledger_seq_no)) || 0);
}
function normalizePub(v) {
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) {
    let b = Buffer.from(v);
    if (b.length === 33 && b[0] === 0xed) b = b.subarray(1);
    if (b.length === 32) return `ed${b.toString('hex')}`;
  }
  const s = text(v, 80).toLowerCase().replace(/^0x/,'');
  if (/^ed[0-9a-f]{64}$/.test(s)) return s;
  if (/^[0-9a-f]{64}$/.test(s)) return `ed${s}`;
  throw new Error('Invalid HotPocket public key.');
}
function userPub(user) {
  for (const candidate of [user && user.publicKey, user && user.public_key, user && user.key, user && user.id]) {
    try { return normalizePub(candidate); } catch {}
  }
  throw new Error('Connected HotPocket public key is unavailable.');
}
function normalizeTag(value) {
  let s = text(value, 96).toLowerCase();
  try { s = s.normalize('NFKD').replace(/[\u0300-\u036f]/g, ''); } catch {}
  s = s.replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-+/g, '-');
  if (s.length < 2 || s.length > 32) return null;
  if (!/[a-z0-9]/.test(s)) return null;
  return s;
}
function normalizeTags(values, max=MAX_SUGGESTED_TAGS) {
  const out = [];
  for (const raw of Array.isArray(values) ? values : []) {
    const tag = normalizeTag(raw);
    if (tag && !out.includes(tag)) out.push(tag);
    if (out.length >= max) break;
  }
  return out;
}
function normalizeAiMeta(value) {
  const v = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const model = text(v.model, 128);
  const temperature = Number(v.temperature);
  const profileRaw = text(v.profile, 32).toLowerCase();
  const seed = Number(v.seed);
  return {
    model,
    temperature:Number.isFinite(temperature) ? Math.max(0, Math.min(2, Math.round(temperature * 100) / 100)) : null,
    profile:['balanced','broad','content','discovery'].includes(profileRaw) ? profileRaw : 'balanced',
    seed:Number.isInteger(seed) && seed >= 0 && seed <= 0x7fffffff ? seed : null
  };
}
function safeHash(v) {
  const h = text(v, 80).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('Invalid SHA-256 hash.');
  return h;
}
function safeId(v) {
  const id = text(v, 128).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._:-]{7,127}$/.test(id)) throw new Error('Invalid file id.');
  return id;
}
function hashJson(v) { return crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex'); }
function candidateHash(tags) { return hashJson(normalizeTags(tags, MAX_CANDIDATE_TAGS)); }

function ensureStoredTagState(f) {
  if (!f || typeof f !== 'object') return f;
  f.tags = normalizeTags(f.tags, WINNING_TAGS);
  f.aiTaggingEnabled = f.visibility === 'public' && f.aiTaggingEnabled === true;
  if (f.tags.length) {
    f.tagStatus = 'tagged';
    f.aiSorted = true;
    f.aiSortedAt = Number(f.taggedAt || f.aiSortedAt || 0) || null;
  } else if (!f.aiTaggingEnabled || f.visibility !== 'public') {
    f.tagStatus = 'disabled';
    f.aiSorted = false;
    f.aiSortedAt = null;
  } else if (!['suggesting','voting'].includes(f.tagStatus)) {
    f.tagStatus = 'suggesting';
    f.aiSorted = false;
    f.aiSortedAt = null;
  }
  f.taggingRound = Math.max(0, Number(f.taggingRound) || (f.aiTaggingEnabled ? 1 : 0));
  f.tagPhaseStartedLcl = Math.max(0, Number(f.tagPhaseStartedLcl) || 0) || null;
  f.firstSuggestionLcl = Math.max(0, Number(f.firstSuggestionLcl) || 0) || null;
  f.lastSuggestionLcl = Math.max(0, Number(f.lastSuggestionLcl) || 0) || null;
  f.firstVoteLcl = Math.max(0, Number(f.firstVoteLcl) || 0) || null;
  f.lastVoteLcl = Math.max(0, Number(f.lastVoteLcl) || 0) || null;
  f.aiParticipants = Array.isArray(f.aiParticipants) ? [...new Set(f.aiParticipants.map(x=>{try{return normalizePub(x)}catch{return null}}).filter(Boolean))].sort() : [];
  f.aiSuggestions = f.aiSuggestions && typeof f.aiSuggestions === 'object' && !Array.isArray(f.aiSuggestions) ? f.aiSuggestions : {};
  f.aiSuggestions = Object.fromEntries(Object.entries(f.aiSuggestions).map(([pk,tags])=>{try{return [normalizePub(pk),normalizeTags(tags,MAX_SUGGESTED_TAGS)]}catch{return null}}).filter(x=>x&&x[1].length>=MIN_SUGGESTED_TAGS&&x[1].length<=MAX_SUGGESTED_TAGS));
  f.aiSuggestionMeta = f.aiSuggestionMeta && typeof f.aiSuggestionMeta === 'object' && !Array.isArray(f.aiSuggestionMeta) ? Object.fromEntries(Object.entries(f.aiSuggestionMeta).map(([pk,v])=>{try{return [normalizePub(pk),normalizeAiMeta(v)]}catch{return null}}).filter(Boolean)) : {};
  f.aiEligibleVoters = Array.isArray(f.aiEligibleVoters) ? [...new Set(f.aiEligibleVoters.map(x=>{try{return normalizePub(x)}catch{return null}}).filter(Boolean))].sort() : [];
  f.aiDisqualified = Array.isArray(f.aiDisqualified) ? [...new Set(f.aiDisqualified.map(x=>{try{return normalizePub(x)}catch{return null}}).filter(Boolean))].sort() : [];
  f.aiVotes = f.aiVotes && typeof f.aiVotes === 'object' && !Array.isArray(f.aiVotes) ? f.aiVotes : {};
  f.aiVotes = Object.fromEntries(Object.entries(f.aiVotes).map(([pk,tags])=>{try{return [normalizePub(pk),normalizeTags(tags,WINNING_TAGS)]}catch{return null}}).filter(x=>x&&x[1].length===WINNING_TAGS));
  f.aiVoteMeta = f.aiVoteMeta && typeof f.aiVoteMeta === 'object' && !Array.isArray(f.aiVoteMeta) ? Object.fromEntries(Object.entries(f.aiVoteMeta).map(([pk,v])=>{try{return [normalizePub(pk),normalizeAiMeta(v)]}catch{return null}}).filter(Boolean)) : {};
  f.suggestionDeadlineLcl = Math.max(0, Number(f.suggestionDeadlineLcl) || 0) || null;
  f.voteDeadlineLcl = Math.max(0, Number(f.voteDeadlineLcl) || 0) || null;
  f.candidateTags = normalizeTags(f.candidateTags, MAX_CANDIDATE_TAGS);
  f.candidateHash = f.candidateTags.length ? candidateHash(f.candidateTags) : null;
  return f;
}
function state() {
  const s = readJson(FILE, { schema:2, files:{}, portalFinalized:false, portalFinalizedAt:null, portalFinalizedBy:null });
  if (!s || typeof s !== 'object') return { schema:2, files:{}, portalFinalized:false, portalFinalizedAt:null, portalFinalizedBy:null };
  s.schema = 2;
  s.files = s.files && typeof s.files === 'object' && !Array.isArray(s.files) ? s.files : {};
  s.aiParticipants = Array.isArray(s.aiParticipants) ? [...new Set(s.aiParticipants.map(x=>{try{return normalizePub(x)}catch{return null}}).filter(Boolean))].sort() : [];
  for (const f of Object.values(s.files)) ensureStoredTagState(f);
  s.portalFinalized = s.portalFinalized === true;
  s.portalFinalizedAt = Number.isFinite(Number(s.portalFinalizedAt)) ? Number(s.portalFinalizedAt) : null;
  s.portalFinalizedBy = s.portalFinalizedBy ? text(s.portalFinalizedBy,80).toLowerCase() : null;
  return s;
}
function normalizeManifest(raw, owner, timestamp, lcl) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Manifest is required.');
  const fileId = safeId(raw.fileId || raw.id);
  const name = text(raw.name, MAX_NAME);
  if (!name) throw new Error('File name is required.');
  const visibility = text(raw.visibility, 16).toLowerCase();
  if (!['public','private'].includes(visibility)) throw new Error('Visibility must be public or private.');
  const size = Number(raw.size);
  const storedSize = Number(raw.storedSize == null ? raw.size : raw.storedSize);
  if (!Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(storedSize) || storedSize < 0) throw new Error('Invalid file size.');
  const replicationTarget = Number(raw.replicationTarget);
  if (!Number.isInteger(replicationTarget) || replicationTarget < 1 || replicationTarget > 64) throw new Error('Invalid replication target.');
  const chunks = Array.isArray(raw.chunks) ? raw.chunks : [];
  if (!chunks.length && storedSize > 0) throw new Error('Chunk list is required.');
  if (chunks.length > MAX_CHUNKS) throw new Error(`File exceeds ${MAX_CHUNKS} chunks.`);
  let total = 0;
  const normalizedChunks = chunks.map((c, i) => {
    const index = Number(c && c.index);
    const chunkSize = Number(c && c.size);
    if (!Number.isInteger(index) || index !== i) throw new Error('Chunks must be indexed consecutively from zero.');
    if (!Number.isInteger(chunkSize) || chunkSize < 0 || chunkSize > 16 * 1024 * 1024) throw new Error('Invalid chunk size.');
    total += chunkSize;
    return { index, size:chunkSize, hash:safeHash(c.hash) };
  });
  if (total !== storedSize) throw new Error('Chunk sizes do not match stored payload size.');
  const encryption = visibility === 'private' ? {
    scheme:text(raw.encryption && raw.encryption.scheme, 64),
    iv:text(raw.encryption && raw.encryption.iv, 256),
    sealedKey:text(raw.encryption && raw.encryption.sealedKey, 4096)
  } : null;
  if (visibility === 'private' && (!encryption.scheme || !encryption.iv || !encryption.sealedKey)) throw new Error('Private-file encryption metadata is incomplete.');
  const aiTaggingEnabled = visibility === 'public' && (raw.aiTaggingEnabled === true || raw.aiTagging === true);
  return {
    schema:2, fileId, ownerPublicKey:owner, name, visibility, size, storedSize,
    originalHash:safeHash(raw.originalHash), storedHash:safeHash(raw.storedHash),
    chunkSize:Number(raw.chunkSize) || 4 * 1024 * 1024,
    chunks:normalizedChunks,
    replicationTarget,
    encryption,
    aiTaggingEnabled,
    tagStatus:aiTaggingEnabled ? 'suggesting' : 'disabled',
    tags:[], taggingRound:aiTaggingEnabled ? 1 : 0,
    tagPhaseStartedLcl:aiTaggingEnabled ? (lcl || null) : null,
    firstSuggestionLcl:null, lastSuggestionLcl:null, firstVoteLcl:null, lastVoteLcl:null,
    aiParticipants:[], aiSuggestions:{}, aiSuggestionMeta:{}, aiEligibleVoters:[], aiDisqualified:[], suggestionDeadlineLcl:null, candidateTags:[], candidateHash:null, aiVotes:{}, aiVoteMeta:{}, voteDeadlineLcl:null, finalVoteTally:null, taggingSummary:null,
    aiSorted:false, aiSortedAt:null, taggedAt:null, taggedAtLcl:null,
    createdAt:timestamp, updatedAt:timestamp
  };
}
function publicCluster() {
  const auto = readJson(path.resolve(process.cwd(), 'autocluster.state.json'), null) || readJson(path.resolve(process.cwd(), 'autocluster.json'), null);
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const normalizePubkey = v => {
    const p = text(v, 256).toLowerCase();
    return /^ed[0-9a-f]{64}$/.test(p) ? p : null;
  };
  const bootstrap = normalizePubkey(auto && auto.bootstrapPubkey);
  const validatorMeta = new Map((Array.isArray(auto && auto.validators) ? auto.validators : [])
    .filter(v => v && normalizePubkey(v.publicKey || v.pubkey))
    .map(v => [normalizePubkey(v.publicKey || v.pubkey), v]));
  const unlSnapshot = new Set((Array.isArray(auto && auto.unlSnapshot) ? auto.unlSnapshot : []).map(normalizePubkey).filter(Boolean));
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const normalized = nodes.map(n => {
    const pubkey = normalizePubkey(n && n.pubkey);
    const meta = pubkey ? (validatorMeta.get(pubkey) || {}) : {};
    const isUnl = !!(n && n.isUnl) || (!!pubkey && unlSnapshot.has(pubkey)) || meta.isUnl === true;
    return {
      pubkey,
      domain:text((n && n.domain) || meta.domain,255) || null,
      userPort:Number((n && n.userPort) || meta.userPort) || null,
      peerPort:Number((n && (n.peerPort || n.meshPort)) || meta.peerPort) || null,
      gpTcp1Port:Number((n && (n.gpTcp1Port || n.gpTcpPort)) || meta.gpTcp1Port) || null,
      gpUdp1Port:Number((n && (n.gpUdp1Port || n.gpUdpPort)) || meta.gpUdp1Port) || null,
      isUnl,
      isBootstrap:!!bootstrap && pubkey === bootstrap,
      signerAddress:text((n && n.signerAddress) || meta.signerAddress,128) || null,
      host:text((n && n.host) || meta.hostAddress,128) || null
    };
  });
  return {
    phase:text(auto && auto.phase,64) || 'not-started',
    targetManagedNodes:Number(auto && auto.targetManagedNodes) || 0,
    signerQuorum:Number(auto && auto.signerQuorum) || 0,
    nodes:normalized,
    managedNodes:normalized.filter(n => !n.isBootstrap && n.isUnl)
  };
}
function requireHeadAdmin(owner, timestamp) {
  const auth = readJson(path.resolve(process.cwd(), 'admin-auth.json'), null);
  const device = auth && auth.authorizedDevices && auth.authorizedDevices[owner];
  const record = device && auth.users && auth.users[device.userId];
  if (!device || !record || record.active === false || record.role !== 'head-admin') throw new Error('Head-admin authorization required.');
  if (Number(device.expiresAt || 0) <= timestamp) throw new Error('Head-admin authorization expired. Sign in again before finalizing.');
  return record;
}
async function send(runtime, user, payload) {
  if (!runtime || !runtime.bson) throw new Error('BSON runtime is unavailable.');
  await user.send(runtime.bson.serialize(payload));
}
function fileView(f) {
  const x = { ...f };
  x.aiSuggestionCount = Object.keys(f.aiSuggestions || {}).length;
  x.aiVoteCount = Object.keys(f.aiVotes || {}).length;
  x.aiExpectedCount = Array.isArray(f.aiParticipants) ? f.aiParticipants.length : 0;
  x.aiEligibleVoteCount = Array.isArray(f.aiEligibleVoters) ? f.aiEligibleVoters.length : 0;
  x.aiDisqualifiedCount = Array.isArray(f.aiDisqualified) ? f.aiDisqualified.length : 0;
  x.candidateCount = Array.isArray(f.candidateTags) ? f.candidateTags.length : 0;
  x.aiTransport = f.aiTaggingEnabled && f.visibility === 'public' ? 'node-party-line' : null;
  // Keep the normalized AI audit trail visible through HotPocket so users can
  // inspect exactly which validator suggested/voted for which tags.
  return x;
}
function suggestionStats(f) {
  const counts = new Map();
  for (const tags of Object.values(f.aiSuggestions || {})) {
    for (const tag of normalizeTags(tags, MAX_SUGGESTED_TAGS)) counts.set(tag, (counts.get(tag) || 0) + 1);
  }
  return counts;
}
function buildCandidateTags(f) {
  const counts = suggestionStats(f);
  // Voting uses the full unique union of all validator suggestions. Ordering is
  // deterministic, but suggestion popularity does not remove a tag from ballot.
  return [...counts.keys()].sort((a,b) => a.localeCompare(b)).slice(0, MAX_CANDIDATE_TAGS);
}
function finalizeTags(f) {
  const suggestions = suggestionStats(f);
  const votes = new Map();
  for (const tags of Object.values(f.aiVotes || {})) {
    for (const tag of normalizeTags(tags, WINNING_TAGS)) if ((f.candidateTags || []).includes(tag)) votes.set(tag, (votes.get(tag) || 0) + 1);
  }
  return [...(f.candidateTags || [])].sort((a,b) =>
    ((votes.get(b) || 0) - (votes.get(a) || 0)) ||
    ((suggestions.get(b) || 0) - (suggestions.get(a) || 0)) ||
    a.localeCompare(b)
  ).slice(0, WINNING_TAGS);
}
function aiExpected(f) { return Array.isArray(f.aiParticipants) ? f.aiParticipants.length : 0; }
function suggestionSubmitters(f) {
  const expected = new Set(Array.isArray(f.aiParticipants) ? f.aiParticipants : []);
  return Object.keys(f.aiSuggestions || {}).filter(pk => !expected.size || expected.has(pk)).sort();
}
function eligibleVoters(f) {
  const explicit = Array.isArray(f.aiEligibleVoters) ? f.aiEligibleVoters : [];
  return explicit.length ? [...explicit] : suggestionSubmitters(f);
}
function startVoting(f, lcl, timestamp) {
  const submitters = suggestionSubmitters(f);
  if (!submitters.length) return false;
  const candidates = buildCandidateTags(f);
  if (candidates.length < WINNING_TAGS) return false;
  f.aiEligibleVoters = submitters;
  f.aiDisqualified = (Array.isArray(f.aiParticipants) ? f.aiParticipants : []).filter(pk => !submitters.includes(pk)).sort();
  f.candidateTags = candidates;
  f.candidateHash = candidateHash(candidates);
  f.tagStatus = 'voting';
  f.tagPhaseStartedLcl = lcl;
  f.firstVoteLcl = null;
  f.lastVoteLcl = null;
  f.voteDeadlineLcl = lcl + VOTE_WINDOW_LCLS;
  f.updatedAt = timestamp || f.updatedAt;
  return true;
}
function progressTagging(ctx) {
  if (!ctx || ctx.readonly) return false;
  const lcl = ledgerNo(ctx), timestamp = nowMs(ctx);
  if (!lcl) return false;
  const s = state();
  let changed = false;
  for (const f of Object.values(s.files)) {
    ensureStoredTagState(f);
    if (!f || f.visibility !== 'public' || !f.aiTaggingEnabled || f.tagStatus === 'tagged') continue;
    if (f.tagStatus === 'suggesting') {
      const expected = aiExpected(f), count = suggestionSubmitters(f).length;
      if (f.firstSuggestionLcl && !f.suggestionDeadlineLcl) {
        f.suggestionDeadlineLcl = f.firstSuggestionLcl + SUGGEST_WINDOW_LCLS;
        changed = true;
      }
      const allIn = expected > 0 && count >= expected;
      const timedOut = !!f.firstSuggestionLcl && !!f.suggestionDeadlineLcl && lcl >= f.suggestionDeadlineLcl;
      if ((allIn || timedOut) && count > 0 && startVoting(f, lcl, timestamp)) changed = true;
    }
    if (f.tagStatus === 'voting') {
      const eligible = eligibleVoters(f);
      const validVotes = Object.keys(f.aiVotes || {}).filter(pk => eligible.includes(pk));
      if (!f.voteDeadlineLcl) { f.voteDeadlineLcl = (f.tagPhaseStartedLcl || lcl) + VOTE_WINDOW_LCLS; changed = true; }
      const allVotesIn = eligible.length > 0 && validVotes.length >= eligible.length;
      const timedOut = !!f.voteDeadlineLcl && lcl >= f.voteDeadlineLcl;
      if ((allVotesIn || timedOut) && validVotes.length > 0 && Array.isArray(f.candidateTags) && f.candidateTags.length >= WINNING_TAGS) {
        const winners = finalizeTags(f);
        if (winners.length === WINNING_TAGS) {
          const suggestionNodes = suggestionSubmitters(f).length;
          const voteNodes = validVotes.length;
          f.tags = winners;
          f.tagStatus = 'tagged';
          f.aiSorted = true;
          f.aiSortedAt = timestamp || null;
          f.taggedAt = timestamp || null;
          f.taggedAtLcl = lcl;
          const voteTally = {};
          for (const tag of f.candidateTags || []) voteTally[tag] = 0;
          for (const [pk,ballot] of Object.entries(f.aiVotes || {})) {
            if (!eligible.includes(pk)) continue;
            for (const tag of normalizeTags(ballot, WINNING_TAGS)) if (Object.prototype.hasOwnProperty.call(voteTally, tag)) voteTally[tag] += 1;
          }
          f.finalVoteTally = voteTally;
          f.taggingSummary = {
            round:f.taggingRound, suggestionNodes, expectedSuggestionNodes:aiExpected(f),
            disqualifiedSuggestionNodes:(f.aiDisqualified || []).length,
            eligibleVoteNodes:eligible.length, voteNodes, candidateCount:f.candidateTags.length,
            winners:[...winners], suggestionDeadlineLcl:f.suggestionDeadlineLcl, voteDeadlineLcl:f.voteDeadlineLcl
          };
          f.updatedAt = timestamp || f.updatedAt;
          changed = true;
        }
      }
    }
  }
  if (changed) writeJson(FILE, s);
  return changed;
}
function setAiTagging(f, enabled, timestamp, lcl) {
  ensureStoredTagState(f);
  if (enabled && f.visibility !== 'public') throw new Error('AI tagging is available only for public files.');
  if (f.tagStatus === 'tagged') return;
  f.aiTaggingEnabled = !!enabled;
  f.aiSorted = false;
  f.aiSortedAt = null;
  f.tags = [];
  f.taggingSummary = null;
  f.aiSuggestions = {};
  f.aiSuggestionMeta = {};
  f.aiEligibleVoters = [];
  f.aiDisqualified = [];
  f.suggestionDeadlineLcl = null;
  f.aiVotes = {};
  f.aiVoteMeta = {};
  f.voteDeadlineLcl = null;
  f.candidateTags = [];
  f.candidateHash = null;
  f.firstSuggestionLcl = null;
  f.lastSuggestionLcl = null;
  f.firstVoteLcl = null;
  f.lastVoteLcl = null;
  if (enabled) {
    f.tagStatus = 'suggesting';
    f.taggingRound = Math.max(0, Number(f.taggingRound) || 0) + 1;
    f.tagPhaseStartedLcl = lcl || null;
  } else {
    f.tagStatus = 'disabled';
    f.tagPhaseStartedLcl = null;
  }
  f.updatedAt = timestamp;
}

function hotPocketKeyHex(value, expectedBytes) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    let buf = Buffer.from(value);
    if (buf.length === expectedBytes + 1 && buf[0] === 0xed) buf = buf.subarray(1);
    const hex = buf.toString('hex').toLowerCase();
    return hex.length === expectedBytes * 2 ? hex : null;
  }
  let raw = text(value, expectedBytes * 2 + 8).toLowerCase().replace(/^0x/, '');
  if (raw.startsWith('ed') && raw.length === expectedBytes * 2 + 2) raw = raw.slice(2);
  return new RegExp(`^[0-9a-f]{${expectedBytes * 2}}$`).test(raw) ? raw : null;
}
function nodePrivateKey(privateKey, expectedPublicKey) {
  const raw = hotPocketKeyHex(privateKey, 64);
  const expected = hotPocketKeyHex(expectedPublicKey, 32);
  if (!raw || !expected || raw.slice(64) !== expected) throw new Error('Local validator signing key is unavailable.');
  const seed = Buffer.from(raw.slice(0, 64), 'hex');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key:der, format:'der', type:'pkcs8' });
}
function nodePublicKey(publicKey) {
  const raw = hotPocketKeyHex(publicKey, 32);
  if (!raw) throw new Error('Invalid validator public key.');
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw, 'hex')]);
  return crypto.createPublicKey({ key:der, format:'der', type:'spki' });
}
function attestationCanonical(a) {
  return JSON.stringify([
    AI_ATTESTATION_TYPE,
    text(a && a.validatorPubkey,80).toLowerCase(),
    safeId(a && a.fileId),
    Math.max(1, Number(a && a.round) || 1),
    text(a && a.phase,16).toLowerCase(),
    safeHash(a && a.originalHash),
    text(a && a.candidateHash,80).toLowerCase() || null,
    normalizeTags(a && a.tags, a && a.phase === 'vote' ? WINNING_TAGS : MAX_SUGGESTED_TAGS),
    text(a && a.model,128),
    normalizeAiMeta(a).temperature,
    normalizeAiMeta(a).profile,
    normalizeAiMeta(a).seed
  ]);
}
function verifyAiAttestation(a) {
  try {
    if (!a || a.type !== AI_ATTESTATION_TYPE) return false;
    const pub = normalizePub(a.validatorPubkey);
    const sig = text(a.signature, 512);
    if (!sig) return false;
    return crypto.verify(null, Buffer.from(attestationCanonical(a)), nodePublicKey(pub), Buffer.from(sig, 'base64'));
  } catch { return false; }
}
function aiAttestationRejected(reason, a, f, validatorPubkey) {
  const phase = text(a && a.phase,16).toLowerCase() || 'unknown';
  const fileId = (()=>{ try { return safeId(a && a.fileId); } catch { return 'invalid'; } })();
  const expectedRound = f ? Number(f.taggingRound) || 0 : 0;
  const gotRound = Number(a && a.round) || 0;
  console.log(`LaunchFiles AI attestation rejected: reason=${reason} validator=${validatorPubkey || text(a && a.validatorPubkey,80) || 'unknown'} file=${fileId} phase=${phase} round=${gotRound} expectedRound=${expectedRound} status=${f && f.tagStatus || 'missing'}`);
  return true;
}
function acceptAiAttestation(a, ctx) {
  if (ctx.readonly) throw new Error('AI tagging votes require consensus input.');
  if (!verifyAiAttestation(a)) throw new Error('Invalid validator AI attestation signature.');
  const validatorPubkey = normalizePub(a.validatorPubkey);
  const managed = new Set(publicCluster().managedNodes.map(n => n.pubkey).filter(Boolean));
  if (!managed.has(validatorPubkey)) throw new Error('AI attestation is not from a current managed validator.');
  const s = state(), id = safeId(a.fileId), f = s.files[id];
  if (!f) return aiAttestationRejected('file-missing', a, null, validatorPubkey);
  if (f.visibility !== 'public') return aiAttestationRejected('file-not-public', a, f, validatorPubkey);
  if (!f.aiTaggingEnabled) return aiAttestationRejected('tagging-disabled', a, f, validatorPubkey);
  if (f.tagStatus === 'tagged') return aiAttestationRejected('already-tagged', a, f, validatorPubkey);
  if (Number(a.round) !== Number(f.taggingRound)) return aiAttestationRejected('wrong-round', a, f, validatorPubkey);
  if (safeHash(a.originalHash) !== f.originalHash) return aiAttestationRejected('original-hash-mismatch', a, f, validatorPubkey);
  if (Array.isArray(f.aiParticipants) && f.aiParticipants.length && !f.aiParticipants.includes(validatorPubkey)) return aiAttestationRejected('not-participant', a, f, validatorPubkey);
  const lcl = ledgerNo(ctx), timestamp = nowMs(ctx);
  const phase = text(a.phase,16).toLowerCase();
  if (phase === 'suggest') {
    if (f.tagStatus !== 'suggesting') return aiAttestationRejected('wrong-phase-status', a, f, validatorPubkey);
    if (f.aiSuggestions[validatorPubkey]) return aiAttestationRejected('duplicate-suggestion', a, f, validatorPubkey);
    if (!Array.isArray(a.tags)) return aiAttestationRejected('tags-not-array', a, f, validatorPubkey);
    if (a.tags.length < MIN_SUGGESTED_TAGS || a.tags.length > MAX_SUGGESTED_TAGS) return aiAttestationRejected('invalid-raw-tag-count', a, f, validatorPubkey);
    const tags = normalizeTags(a.tags, MAX_SUGGESTED_TAGS);
    if (tags.length < MIN_SUGGESTED_TAGS || tags.length > MAX_SUGGESTED_TAGS) return aiAttestationRejected('invalid-normalized-tag-count', a, f, validatorPubkey);
    f.aiSuggestions[validatorPubkey] = tags;
    f.aiSuggestionMeta[validatorPubkey] = normalizeAiMeta(a);
    if (!f.firstSuggestionLcl) {
      f.firstSuggestionLcl = lcl || null;
      f.suggestionDeadlineLcl = lcl ? lcl + SUGGEST_WINDOW_LCLS : null;
    }
    f.lastSuggestionLcl = lcl || f.lastSuggestionLcl || null;
    f.updatedAt = timestamp || f.updatedAt;
    writeJson(FILE, s);
    console.log(`LaunchFiles AI suggestion accepted: validator=${validatorPubkey} file=${f.fileId} round=${f.taggingRound} tags=${tags.length}`);
    return true;
  }
  if (phase === 'vote') {
    if (f.tagStatus !== 'voting') return aiAttestationRejected('wrong-phase-status', a, f, validatorPubkey);
    if (f.aiVotes[validatorPubkey]) return aiAttestationRejected('duplicate-vote', a, f, validatorPubkey);
    if (!eligibleVoters(f).includes(validatorPubkey)) return aiAttestationRejected('not-eligible-voter', a, f, validatorPubkey);
    if (!f.candidateHash || text(a.candidateHash,80).toLowerCase() !== f.candidateHash) return aiAttestationRejected('candidate-hash-mismatch', a, f, validatorPubkey);
    if (!Array.isArray(a.tags) || a.tags.length !== WINNING_TAGS) return aiAttestationRejected('invalid-vote-tag-count', a, f, validatorPubkey);
    const tags = normalizeTags(a.tags, WINNING_TAGS).filter(t => f.candidateTags.includes(t));
    if (tags.length !== WINNING_TAGS) return aiAttestationRejected('vote-tag-not-in-candidates', a, f, validatorPubkey);
    f.aiVotes[validatorPubkey] = tags;
    f.aiVoteMeta[validatorPubkey] = normalizeAiMeta(a);
    if (!f.firstVoteLcl) f.firstVoteLcl = lcl || null;
    f.lastVoteLcl = lcl || f.lastVoteLcl || null;
    f.updatedAt = timestamp || f.updatedAt;
    writeJson(FILE, s);
    console.log(`LaunchFiles AI vote accepted: validator=${validatorPubkey} file=${f.fileId} round=${f.taggingRound}`);
    return true;
  }
  return aiAttestationRejected('unknown-phase', a, f, validatorPubkey);
}
function localValidatorPub(ctx) {
  try { return normalizePub(ctx && (ctx.publicKey || ctx.public_key)); } catch { return null; }
}
function currentManagedPubkeys() {
  return new Set(publicCluster().managedNodes.map(n => n.pubkey).filter(Boolean));
}
function aiNplWorkItems() {
  const s = state();
  return Object.values(s.files).filter(f => f && f.visibility === 'public' && f.aiTaggingEnabled && ['suggesting','voting'].includes(f.tagStatus))
    .sort((a,b) => Number(a.createdAt || 0) - Number(b.createdAt || 0) || String(a.fileId).localeCompare(String(b.fileId)))
    .slice(0, AI_NPL_WORK_BATCH)
    .map(f => ({
      fileId:f.fileId,
      round:Number(f.taggingRound) || 1,
      phase:f.tagStatus === 'voting' ? 'vote' : 'suggest',
      originalHash:f.originalHash,
      candidateHash:f.tagStatus === 'voting' ? f.candidateHash : null,
      candidateTags:f.tagStatus === 'voting' ? normalizeTags(f.candidateTags, MAX_CANDIDATE_TAGS) : []
    }));
}
async function broadcastAiWork(ctx) {
  if (!ctx || ctx.readonly || !ctx.unl || typeof ctx.unl.send !== 'function') return false;
  const local = localValidatorPub(ctx), managed = currentManagedPubkeys(), lcl = ledgerNo(ctx);
  if (!local || !managed.has(local) || !lcl || lcl % 3 !== 0) return false;
  const items = aiNplWorkItems();
  if (!items.length) return false;
  await ctx.unl.send(JSON.stringify({ type:AI_NPL_WORK_TYPE, senderPubkey:local, lcl, items }));
  return true;
}
function buildLocalAiAttestation(ctx) {
  if (!ctx || ctx.readonly || !fs.existsSync(LOCAL_AI_RESULT_FILE)) return null;
  const result = readJson(LOCAL_AI_RESULT_FILE, null);
  if (!result || result.type !== AI_LOCAL_RESULT_TYPE) return null;
  const pub = localValidatorPub(ctx);
  if (!pub || normalizePub(result.validatorPubkey) !== pub || !currentManagedPubkeys().has(pub)) return null;
  const s = state(), f = s.files[safeId(result.fileId)];
  if (!f || f.visibility !== 'public' || !f.aiTaggingEnabled || f.tagStatus === 'tagged') return null;
  const phase = text(result.phase,16).toLowerCase();
  if (Number(result.round) !== Number(f.taggingRound) || safeHash(result.originalHash) !== f.originalHash) return null;
  if (phase === 'suggest' && f.tagStatus !== 'suggesting') return null;
  if (phase === 'vote' && (f.tagStatus !== 'voting' || !f.candidateHash || text(result.candidateHash,80).toLowerCase() !== f.candidateHash)) return null;
  const rawTags = Array.isArray(result.tags) ? result.tags : [];
  const requiredMin = phase === 'suggest' ? MIN_SUGGESTED_TAGS : WINNING_TAGS;
  const requiredMax = phase === 'suggest' ? MAX_SUGGESTED_TAGS : WINNING_TAGS;
  if (rawTags.length < requiredMin || rawTags.length > requiredMax) return null;
  const tags = normalizeTags(rawTags, requiredMax);
  if (tags.length < requiredMin || tags.length > requiredMax) return null;
  const report = {
    type:AI_ATTESTATION_TYPE,
    validatorPubkey:pub,
    fileId:f.fileId,
    round:f.taggingRound,
    phase,
    originalHash:f.originalHash,
    candidateHash:phase === 'vote' ? f.candidateHash : null,
    tags,
    model:text(result.model,128),
    temperature:normalizeAiMeta(result).temperature,
    profile:normalizeAiMeta(result).profile,
    seed:normalizeAiMeta(result).seed
  };
  const key = nodePrivateKey(ctx.privateKey || ctx.private_key, pub);
  report.signature = crypto.sign(null, Buffer.from(attestationCanonical(report)), key).toString('base64');
  return report;
}
async function publishLocalAiResult(ctx) {
  if (!ctx || ctx.readonly) return false;
  const report = buildLocalAiAttestation(ctx);
  if (!report) return false;
  const existing = readJson(LOCAL_AI_ATTESTATION_FILE, null);
  const fresh = !existing || existing.signature !== report.signature;
  // Persist the validator-signed attestation locally first. The sidecar relays
  // this exact signed result into HotPocket consensus; NPL loopback is not a
  // prerequisite, so a dropped/self-suppressed Party Line packet cannot strand
  // the worker in result-ready/awaiting-consensus forever.
  if (fresh) atomicWriteJson(LOCAL_AI_ATTESTATION_FILE, report);
  // Still announce the result over Node Party Line for validator visibility.
  // This is best-effort coordination only; permanent state changes happen only
  // after the signed attestation is accepted as a normal consensus input.
  if (fresh && ctx.unl && typeof ctx.unl.send === 'function') {
    try { await ctx.unl.send(JSON.stringify({ type:AI_NPL_RESULT_TYPE, senderPubkey:report.validatorPubkey, attestation:report })); }
    catch (e) { console.log(`LaunchFiles AI NPL result announcement skipped: ${e.message}`); }
  }
  return fresh;
}
function nplSender(node) {
  try { return normalizePub(node && (node.publicKey || node.public_key || node.pubkey || node.key || node.id || node)); } catch { return null; }
}
function nplText(msg) {
  if (Buffer.isBuffer(msg)) return msg.toString('utf8');
  if (msg instanceof Uint8Array) return Buffer.from(msg).toString('utf8');
  return String(msg || '');
}
function validNplWorkItem(raw, files) {
  try {
    const fileId = safeId(raw && raw.fileId), f = files[fileId];
    if (!f || f.visibility !== 'public' || !f.aiTaggingEnabled || f.tagStatus === 'tagged') return null;
    const round = Math.max(1, Number(raw.round) || 1), phase = text(raw.phase,16).toLowerCase();
    if (round !== Number(f.taggingRound) || safeHash(raw.originalHash) !== f.originalHash) return null;
    if (phase === 'suggest' && f.tagStatus !== 'suggesting') return null;
    if (phase === 'vote') {
      if (f.tagStatus !== 'voting' || !f.candidateHash || text(raw.candidateHash,80).toLowerCase() !== f.candidateHash) return null;
      const incoming = normalizeTags(raw.candidateTags, MAX_CANDIDATE_TAGS);
      if (candidateHash(incoming) !== f.candidateHash) return null;
    }
    return {
      fileId, round, phase, originalHash:f.originalHash,
      candidateHash:phase === 'vote' ? f.candidateHash : null,
      candidateTags:phase === 'vote' ? normalizeTags(f.candidateTags, MAX_CANDIDATE_TAGS) : []
    };
  } catch { return null; }
}
function handleNpl(node, msg, ctx) {
  if (!ctx || ctx.readonly) return false;
  let parsed = null;
  try { parsed = JSON.parse(nplText(msg)); } catch { return false; }
  if (!parsed || ![AI_NPL_WORK_TYPE, AI_NPL_RESULT_TYPE].includes(parsed.type)) return false;
  const sender = nplSender(node), managed = currentManagedPubkeys();
  if (!sender || !managed.has(sender)) return true;
  if (parsed.type === AI_NPL_WORK_TYPE) {
    if (text(parsed.senderPubkey,80).toLowerCase() !== sender) return true;
    const files = state().files, items = (Array.isArray(parsed.items) ? parsed.items : []).map(x => validNplWorkItem(x, files)).filter(Boolean).slice(0, AI_NPL_WORK_BATCH);
    if (!items.length) return true;
    atomicWriteJson(LOCAL_AI_NPL_WORK_FILE, {
      type:AI_NPL_WORK_TYPE,
      senderPubkey:sender,
      receivedAtLcl:ledgerNo(ctx) || null,
      receivedAtMs:Date.now(),
      items
    });
    return true;
  }
  const report = parsed.attestation;
  if (!report || text(parsed.senderPubkey,80).toLowerCase() !== sender || text(report.validatorPubkey,80).toLowerCase() !== sender || !verifyAiAttestation(report)) return true;
  // Every result is visible to the validator party line. Only the originating
  // validator persists its own looped-back NPL result for the sidecar consensus
  // relay, preventing N identical relays of the same signed AI vote.
  if (sender !== localValidatorPub(ctx)) return true;
  const s = state(), f = s.files[safeId(report.fileId)];
  if (!f || f.visibility !== 'public' || !f.aiTaggingEnabled || f.tagStatus === 'tagged') return true;
  if (Number(report.round) !== Number(f.taggingRound) || safeHash(report.originalHash) !== f.originalHash) return true;
  if (report.phase === 'suggest' && (f.tagStatus !== 'suggesting' || f.aiSuggestions[sender])) return true;
  if (report.phase === 'vote' && (f.tagStatus !== 'voting' || f.aiVotes[sender] || report.candidateHash !== f.candidateHash)) return true;
  const existing = readJson(LOCAL_AI_ATTESTATION_FILE, null);
  if (!existing || existing.signature !== report.signature) atomicWriteJson(LOCAL_AI_ATTESTATION_FILE, report);
  return true;
}
async function tick(ctx) {
  if (!ctx || ctx.readonly) return;
  progressTagging(ctx);
  try { await publishLocalAiResult(ctx); } catch (e) { console.log(`LaunchFiles AI result publication skipped: ${e.message}`); }
  try { await broadcastAiWork(ctx); } catch (e) { console.log(`LaunchFiles AI NPL work broadcast skipped: ${e.message}`); }
}
async function handleRaw(user, raw, ctx, runtime) {
  let parsed = null;
  try {
    const b = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || []);
    const str = b.toString('utf8').trim();
    if (!str.startsWith('{') || !str.includes(AI_ATTESTATION_TYPE)) return false;
    parsed = JSON.parse(str);
  } catch { return false; }
  if (!parsed || parsed.type !== AI_ATTESTATION_TYPE) return false;
  acceptAiAttestation(parsed, ctx);
  return true;
}

async function handle(user, message, ctx, runtime) {
  const type = text(message && message.type, 128);
  if (!type.startsWith('launch-')) return false;
  const owner = userPub(user);
  const timestamp = nowMs(ctx);
  const lcl = ledgerNo(ctx);
  const actionId = message && message.actionId || null;

  if (type === 'launch-status') {
    const s = state();
    const mine = Object.values(s.files).filter(f => f && f.ownerPublicKey === owner);
    await send(runtime,user,{type:'launch-status',actionId,ownerPublicKey:owner,fileCount:mine.length,portalFinalized:s.portalFinalized,portalFinalizedAt:s.portalFinalizedAt,portalFinalizedBy:s.portalFinalizedBy,aiParticipants:[...(s.aiParticipants||[])],cluster:publicCluster()});
    return true;
  }
  function applyAiParticipants(s, participants) {
    s.aiParticipants=[...participants];
    for (const f of Object.values(s.files||{})) if (f && f.visibility==='public' && f.aiTaggingEnabled && f.tagStatus!=='tagged') {
      f.aiParticipants=[...participants];
      f.aiSuggestions=Object.fromEntries(Object.entries(f.aiSuggestions||{}).filter(([pk])=>participants.includes(pk)));
      f.aiSuggestionMeta=Object.fromEntries(Object.entries(f.aiSuggestionMeta||{}).filter(([pk])=>participants.includes(pk)));
      f.aiVotes=Object.fromEntries(Object.entries(f.aiVotes||{}).filter(([pk])=>participants.includes(pk)));
      f.aiVoteMeta=Object.fromEntries(Object.entries(f.aiVoteMeta||{}).filter(([pk])=>participants.includes(pk)));
      if (Array.isArray(f.aiEligibleVoters)) f.aiEligibleVoters=f.aiEligibleVoters.filter(pk=>participants.includes(pk));
      if (Array.isArray(f.aiDisqualified)) f.aiDisqualified=f.aiDisqualified.filter(pk=>participants.includes(pk));
    }
  }
  if (type === 'launch-ai-participants-set' || type === 'launch-ai-participant-add' || type === 'launch-ai-participant-remove') {
    if (ctx.readonly) throw new Error('AI participant changes require consensus input.');
    const s = state(); requireHeadAdmin(owner, timestamp);
    const managed = new Set(publicCluster().managedNodes.map(n=>n.pubkey).filter(Boolean));
    let participants=[...(s.aiParticipants||[])].map(x=>{try{return normalizePub(x)}catch{return null}}).filter(x=>x&&managed.has(x));
    if (type === 'launch-ai-participants-set') {
      const requested = Array.isArray(message.participants) ? message.participants : [];
      participants=requested.map(x=>{try{return normalizePub(x)}catch{return null}}).filter(x=>x&&managed.has(x));
    } else {
      const participant=normalizePub(message.participant);
      if (!managed.has(participant)) throw new Error('AI participant must be a current managed validator.');
      if (type === 'launch-ai-participant-add') participants.push(participant);
      else participants=participants.filter(pk=>pk!==participant);
    }
    participants=[...new Set(participants)].sort();
    applyAiParticipants(s, participants);
    writeJson(FILE,s);
    await send(runtime,user,{type,actionId,participant:type==='launch-ai-participants-set'?null:normalizePub(message.participant),participants,count:participants.length}); return true;
  }
  if (type === 'launch-portal-finalize') {
    if (ctx.readonly) throw new Error('Portal finalization requires consensus input.');
    const s = state();
    requireHeadAdmin(owner, timestamp);
    const cluster = publicCluster();
    if (cluster.phase !== 'autonomous') throw new Error('The managed cluster is not autonomous yet.');
    if (cluster.managedNodes.length < Math.max(1, cluster.targetManagedNodes || 1)) throw new Error('The managed validator target is not complete.');
    if (!s.portalFinalized) {
      s.portalFinalized = true;
      s.portalFinalizedAt = timestamp;
      s.portalFinalizedBy = owner;
      writeJson(FILE, s);
    }
    await send(runtime,user,{type:'launch-portal-finalized',actionId,portalFinalized:true,portalFinalizedAt:s.portalFinalizedAt,portalFinalizedBy:s.portalFinalizedBy});
    return true;
  }
  if (type === 'launch-admin-storage-map') {
    requireHeadAdmin(owner, timestamp);
    const s = state();
    const rows = Object.values(s.files).filter(Boolean).sort((a,b)=>Number(b.createdAt||0)-Number(a.createdAt||0));
    await send(runtime,user,{type:'launch-admin-storage-map',actionId,files:rows.map(fileView),cluster:publicCluster(),generatedAt:timestamp});
    return true;
  }
  if (type === 'launch-file-list') {
    const s = state();
    const rows = Object.values(s.files).filter(f => f && (f.ownerPublicKey === owner || f.visibility === 'public'))
      .sort((a,b)=>Number(b.createdAt||0)-Number(a.createdAt||0)).map(fileView);
    await send(runtime,user,{type:'launch-file-list',actionId,files:rows}); return true;
  }
  if (type === 'launch-file-get') {
    const s = state(); const id=safeId(message.fileId); const f=s.files[id];
    if (!f || (f.ownerPublicKey !== owner && f.visibility !== 'public')) throw new Error('File not found.');
    await send(runtime,user,{type:'launch-file',actionId,file:fileView(f)}); return true;
  }
  if (type === 'launch-file-put') {
    if (ctx.readonly) throw new Error('File manifests require consensus input.');
    const s = state();
    const incoming = normalizeManifest(message.manifest || message.file, owner, timestamp, lcl);
    const managedCount = publicCluster().managedNodes.length;
    if (managedCount < 1) throw new Error('No managed storage instances are currently available.');
    if (incoming.replicationTarget > managedCount) throw new Error(`Replication target exceeds the ${managedCount} managed storage instance(s) currently available.`);
    const old = s.files[incoming.fileId];
    if (old && old.ownerPublicKey !== owner) throw new Error('That file id belongs to another user.');
    // A manifest submission can be accepted by consensus while the browser loses
    // the response. Treat an exact retry as idempotent so a retry never resets AI
    // progress or other state that may already have advanced after the first save.
    const exactRetry = !!old && old.name === incoming.name && old.visibility === incoming.visibility &&
      Number(old.size) === Number(incoming.size) && Number(old.storedSize) === Number(incoming.storedSize) &&
      old.originalHash === incoming.originalHash && old.storedHash === incoming.storedHash &&
      Number(old.replicationTarget) === Number(incoming.replicationTarget) &&
      JSON.stringify(old.chunks || []) === JSON.stringify(incoming.chunks || []) &&
      JSON.stringify(old.encryption || null) === JSON.stringify(incoming.encryption || null) &&
      old.aiTaggingEnabled === incoming.aiTaggingEnabled;
    if (exactRetry) { await send(runtime,user,{type:'launch-file-saved',actionId,file:fileView(old),idempotentRetry:true}); return true; }
    incoming.createdAt = old ? old.createdAt : incoming.createdAt;
    if (incoming.aiTaggingEnabled) incoming.aiParticipants = [...(s.aiParticipants || [])];
    if (!old && Object.keys(s.files).length >= MAX_FILES) throw new Error('Cluster manifest limit reached.');
    s.files[incoming.fileId] = incoming; writeJson(FILE,s);
    await send(runtime,user,{type:'launch-file-saved',actionId,file:fileView(incoming)}); return true;
  }
  if (type === 'launch-file-delete') {
    if (ctx.readonly) throw new Error('File deletion requires consensus input.');
    const s=state();const id=safeId(message.fileId),f=s.files[id];
    if (!f || f.ownerPublicKey !== owner) throw new Error('File not found or not owned by this key.');
    delete s.files[id];writeJson(FILE,s);await send(runtime,user,{type:'launch-file-deleted',actionId,fileId:id});return true;
  }
  if (type === 'launch-file-ai-tagging' || type === 'launch-file-ai-state') {
    if (ctx.readonly) throw new Error('AI tagging changes require consensus input.');
    const s=state();const id=safeId(message.fileId),f=s.files[id];
    if (!f || f.ownerPublicKey !== owner) throw new Error('File not found or not owned by this key.');
    const enabled = type === 'launch-file-ai-state' ? !!message.aiSorted : !!message.enabled;
    setAiTagging(f, enabled, timestamp, lcl); if (enabled) f.aiParticipants=[...(s.aiParticipants||[])]; writeJson(FILE,s);
    await send(runtime,user,{type:'launch-file-ai-tagging',actionId,fileId:id,enabled:f.aiTaggingEnabled,tagStatus:f.tagStatus,tags:f.tags});return true;
  }
  return false;
}

module.exports = { handle, handleRaw, handleNpl, tick };
