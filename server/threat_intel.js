// Threat Intel — extract IoCs from an OctoView chat session and score them
// against external providers (VirusTotal, AbuseIPDB). Strictly read-only: never
// triggers a Velociraptor collection. Recommendations surfaced as passive text
// when IoC coverage is thin.

import fs    from "fs";
import path  from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import * as VT    from "./providers/virustotal.js";
import * as AIPDB from "./providers/abuseipdb.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CACHE_TTL_MS    = 24 * 60 * 60 * 1000;
const VT_WINDOW_MS    = 60_000;                // VT free tier: 4 calls / rolling minute
const VT_TOKENS       = Number(process.env.VT_RATE_TOKENS || 4);
export const MAX_IOCS_PER_SCAN = Number(process.env.TI_MAX_IOCS || 50);

// Short-circuit allowlists — loaded from plain-text files in workspace/ so
// the user can curate without code edits. Files are empty by default; the
// operator adds entries as they discover sources of benign noise in their
// fleet (CDN hostnames, well-known empty-file hashes, etc.).
//
// Format: one entry per line, `#` comments allowed, blank lines ignored.
// Reloaded automatically when the file's mtime changes.
const ALLOWLIST_DOMAINS_FILE = path.join(__dirname, "workspace", "allowlist_domains.txt");
const ALLOWLIST_HASHES_FILE  = path.join(__dirname, "workspace", "allowlist_hashes.txt");

function readAllowlistFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => l.toLowerCase());
  } catch { return []; }
}

function mtimeMs(filePath) {
  try { return fs.statSync(filePath).mtimeMs; } catch { return 0; }
}

let domainAllowlist = readAllowlistFile(ALLOWLIST_DOMAINS_FILE);
let hashAllowlist   = new Set(readAllowlistFile(ALLOWLIST_HASHES_FILE));
let domainListMtime = mtimeMs(ALLOWLIST_DOMAINS_FILE);
let hashListMtime   = mtimeMs(ALLOWLIST_HASHES_FILE);

function maybeReloadAllowlists() {
  const dm = mtimeMs(ALLOWLIST_DOMAINS_FILE);
  if (dm !== domainListMtime) {
    domainAllowlist = readAllowlistFile(ALLOWLIST_DOMAINS_FILE);
    domainListMtime = dm;
  }
  const hm = mtimeMs(ALLOWLIST_HASHES_FILE);
  if (hm !== hashListMtime) {
    hashAllowlist = new Set(readAllowlistFile(ALLOWLIST_HASHES_FILE));
    hashListMtime = hm;
  }
}

function isAllowlistedDomain(domain) {
  maybeReloadAllowlists();
  const d = String(domain || "").toLowerCase();
  if (!d) return false;
  return domainAllowlist.some((suf) => d === suf || d.endsWith("." + suf));
}

function isAllowlistedHash(h) {
  maybeReloadAllowlists();
  return hashAllowlist.has(String(h || "").toLowerCase());
}

// ─── IoC extraction ───────────────────────────────────────────────────────────

const HASH_COLS   = /^(sha1|sha256|md5|hash|imphash|filehash|processhash)$/i;
const IP_COLS     = /(src|dst|source|destination|remote|local|client|server).*?(ip|addr|address)|^ipaddress$|^ip$/i;
const URL_COLS    = /^(url|uri)$/i;
const DOMAIN_COLS = /^(domain|host|hostname|fqdn)$/i;

const RE_SHA256 = /\b[A-Fa-f0-9]{64}\b/g;
const RE_SHA1   = /\b[A-Fa-f0-9]{40}\b/g;
const RE_MD5    = /\b[A-Fa-f0-9]{32}\b/g;
const RE_IPV4   = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const RE_URL    = /https?:\/\/[^\s"'<>()\]]+/gi;
const RE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

// Allowlist of real TLDs we accept for bare-domain extraction. Everything else
// is assumed to be a filename/artifact string and rejected. Kept tight on
// purpose — a DFIR chat's row cells are littered with `foo.dat`, `bar.json`,
// `1.lck`, registry path fragments, etc. that the naive domain regex loves.
const REAL_TLDS = new Set([
  // generic
  "com","net","org","io","co","me","dev","app","ai","info","biz","xyz",
  "online","site","tech","cloud","pro","tv","cc","shop","store","blog",
  // infrastructure-ish
  "gov","edu","mil","int",
  // popular country codes
  "uk","us","de","fr","it","es","nl","be","ch","at","se","no","fi","dk",
  "pl","cz","ru","ua","by","cn","jp","kr","in","sg","hk","tw","tr","br",
  "mx","ar","ca","au","nz","za","ie","pt","gr","ro","hu","bg","eu","asia",
  // commonly abused / free
  "su","cf","ga","ml","tk","pw","top","club","icu","ws","link","site","life",
]);

function isPrivateIp(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10)                              return true;
  if (a === 127)                             return true;
  if (a === 169 && b === 254)                return true;
  if (a === 172 && b >= 16 && b <= 31)       return true;
  if (a === 192 && b === 168)                return true;
  if (a === 0)                               return true;
  if (a >= 224)                              return true; // multicast / reserved
  return false;
}

function hostFromUrl(u) {
  try {
    const host = new URL(u).hostname.toLowerCase();
    if (!host.includes(".")) return "";
    return host;
  } catch { return ""; }
}

function normaliseValue(type, raw) {
  const v = String(raw || "").trim();
  if (!v) return "";
  if (type === "hash")   return v.toLowerCase();
  if (type === "domain") return v.toLowerCase().replace(/\.$/, "");
  if (type === "ip")     return v;
  if (type === "url") {
    try {
      const u = new URL(v);
      u.hash = "";                            // drop fragment
      return u.toString();
    } catch { return v; }
  }
  return v;
}

function hashType(value) {
  const L = value.length;
  if (L === 64 && /^[A-Fa-f0-9]+$/.test(value)) return "sha256";
  if (L === 40 && /^[A-Fa-f0-9]+$/.test(value)) return "sha1";
  if (L === 32 && /^[A-Fa-f0-9]+$/.test(value)) return "md5";
  return null;
}

function looksLikeHash(v) { return !!hashType(v); }

function looksLikeDomain(v) {
  const s = String(v).toLowerCase();
  if (!s.includes(".")) return false;
  const labels = s.split(".");
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  if (!REAL_TLDS.has(tld)) return false;
  for (const label of labels) {
    if (!label) return false;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return false;
  }
  // Reject single-char labels and purely-numeric second-level labels
  // (kills "1.net", "1.org", "a.io" — all filename-like patterns).
  const sld = labels[labels.length - 2];
  if (sld.length < 2) return false;
  if (!/[a-z]/.test(sld)) return false;
  return true;
}

function pushIoc(bucket, type, value, msgId, column) {
  const norm = normaliseValue(type, value);
  if (!norm) return;
  if (type === "ip"     && isPrivateIp(norm))    return;
  if (type === "domain" && !looksLikeDomain(norm)) return;
  if (type === "hash"   && !looksLikeHash(norm))   return;
  const key = `${type}:${norm.toLowerCase()}`;
  let item = bucket.get(key);
  if (!item) {
    item = { type, value: norm, foundIn: [] };
    bucket.set(key, item);
  }
  const already = item.foundIn.some((f) => f.messageId === msgId && f.column === column);
  if (!already) item.foundIn.push({ messageId: msgId, column: column || null });
}

// mode="full"   — used on free-text (assistant content): run every regex including bare domains
// mode="cells"  — used on arbitrary row cells: skip bare domains (too many false positives like filenames)
function scanString(bucket, s, msgId, column, mode = "full") {
  if (!s || typeof s !== "string") return;
  // Hashes — unambiguous, safe everywhere.
  for (const m of s.match(RE_SHA256) || []) pushIoc(bucket, "hash", m, msgId, column);
  for (const m of s.match(RE_SHA1)   || []) pushIoc(bucket, "hash", m, msgId, column);
  for (const m of s.match(RE_MD5)    || []) pushIoc(bucket, "hash", m, msgId, column);
  // URLs — http:// prefix makes them unambiguous. Host is promoted to a domain.
  for (const m of s.match(RE_URL) || []) {
    pushIoc(bucket, "url", m, msgId, column);
    const host = hostFromUrl(m);
    if (host && !/^[\d.]+$/.test(host)) pushIoc(bucket, "domain", host, msgId, column);
  }
  // Bare IPs — IPv4 regex + RFC1918 drop keeps the signal clean.
  for (const m of s.match(RE_IPV4) || []) pushIoc(bucket, "ip", m, msgId, column);
  // Bare domains only from free-text. Row cells get too noisy here
  // (shellbags has "ntuser.dat", "1.lck", folder names with dots, etc.).
  if (mode === "full") {
    for (const m of s.match(RE_DOMAIN) || []) pushIoc(bucket, "domain", m, msgId, column);
  }
}

export function extractIocs(messages) {
  const bucket = new Map();
  for (const msg of messages || []) {
    const mid = msg.id || "unknown";
    if (msg.content) scanString(bucket, String(msg.content), mid, null);
    if (Array.isArray(msg.rows)) {
      for (const row of msg.rows) {
        if (!row || typeof row !== "object") continue;
        for (const [col, val] of Object.entries(row)) {
          if (val == null) continue;
          const sval = typeof val === "string" ? val : JSON.stringify(val);
          // Column-name heuristic first: if the column clearly names an IoC type,
          // pin the value as that type (skip regex fallback for this cell).
          if (HASH_COLS.test(col))        pushIoc(bucket, "hash",   sval, mid, col);
          else if (URL_COLS.test(col)) {
            pushIoc(bucket, "url", sval, mid, col);
            const host = hostFromUrl(sval);
            if (host && !/^[\d.]+$/.test(host)) pushIoc(bucket, "domain", host, mid, col);
          }
          else if (DOMAIN_COLS.test(col)) pushIoc(bucket, "domain", sval, mid, col);
          else if (IP_COLS.test(col))     pushIoc(bucket, "ip",     sval, mid, col);
          else                            scanString(bucket, sval, mid, col, "cells");
        }
      }
    }
  }
  return [...bucket.values()];
}

// ─── Cache ────────────────────────────────────────────────────────────────────

export function createCache(cachePath) {
  let data = {};
  try {
    if (fs.existsSync(cachePath)) data = JSON.parse(fs.readFileSync(cachePath, "utf8")) || {};
  } catch { data = {}; }

  const dirty = { flag: false };
  let   flushTimer = null;

  function scheduleFlush() {
    if (flushTimer) return;
    flushTimer = setTimeout(() => { flush(); flushTimer = null; }, 2_000);
  }
  function flush() {
    if (!dirty.flag) return;
    try {
      fs.mkdirSync(path.dirname(cachePath), { recursive: true });
      fs.writeFileSync(cachePath, JSON.stringify(data));
      dirty.flag = false;
    } catch (err) {
      console.error("[threat_intel] cache flush failed:", err.message);
    }
  }

  return {
    get(provider, type, value) {
      const key = `${provider}:${type}:${value.toLowerCase()}`;
      const hit = data[key];
      if (!hit) return null;
      if (Date.now() - hit.fetchedAt > CACHE_TTL_MS) return null;
      return hit.result;
    },
    put(provider, type, value, result) {
      const key = `${provider}:${type}:${value.toLowerCase()}`;
      data[key] = { result, fetchedAt: Date.now() };
      dirty.flag = true;
      scheduleFlush();
    },
    flush,
  };
}

// ─── Rate limiter ────────────────────────────────────────────────────────────
// Token bucket: `tokens` allowed every `windowMs`. Consumes a token per call,
// blocks when empty until the oldest in-flight call's slot frees up.
// This lets a small scan fire 4 parallel calls immediately instead of waiting
// 15s between each one — same throughput as the VT free tier allows, much
// lower "time to first result".

function tokenBucket(tokens, windowMs) {
  const history = [];  // timestamps of recent successful acquires
  const waiters = [];

  function scheduleRelease() {
    if (!history.length) return;
    const soonest = history[0] + windowMs - Date.now();
    setTimeout(tryDrain, Math.max(0, soonest) + 10);
  }
  function tryDrain() {
    const now = Date.now();
    while (history.length && history[0] <= now - windowMs) history.shift();
    while (waiters.length && history.length < tokens) {
      history.push(Date.now());
      const w = waiters.shift();
      w();
    }
    if (waiters.length) scheduleRelease();
  }

  return function acquire(fn) {
    return new Promise((resolve, reject) => {
      const run = async () => {
        try { resolve(await fn()); }
        catch (err) { reject(err); }
      };
      waiters.push(run);
      tryDrain();
    });
  };
}

// ─── Scan orchestration ──────────────────────────────────────────────────────

function providersForType(type, keys) {
  const out = [];
  if (keys.vt)    out.push("vt");
  if (type === "ip" && keys.aipdb) out.push("aipdb");
  return out;
}

function mergeVerdict(sources) {
  const rank = { malicious: 3, suspicious: 2, clean: 1, unknown: 0 };
  let best = { verdict: "unknown", score: 0 };
  for (const s of sources) {
    if ((rank[s.verdict] || 0) > (rank[best.verdict] || 0)) best = s;
    else if (s.verdict === best.verdict && s.score > best.score) best = s;
  }
  return { verdict: best.verdict, score: best.score };
}

function allowlistResult(provider, reason) {
  return {
    provider,
    verdict: "clean",
    score:   0,
    detail:  { allowlisted: true, reason },
  };
}

// Balance the cap across IoC types so a 200-hash Amcache dump doesn't starve
// the 3 IPs from a connections collection. Round-robin pick until cap is hit.
function capIocs(iocs, max) {
  if (iocs.length <= max) return { picked: iocs, truncated: false };
  const byType = { hash: [], ip: [], url: [], domain: [] };
  for (const i of iocs) (byType[i.type] || (byType[i.type] = [])).push(i);
  const picked = [];
  let progressed = true;
  while (picked.length < max && progressed) {
    progressed = false;
    for (const type of ["hash", "ip", "domain", "url"]) {
      if (picked.length >= max) break;
      const bucket = byType[type] || [];
      if (bucket.length) { picked.push(bucket.shift()); progressed = true; }
    }
  }
  return { picked, truncated: true };
}

export async function scanSession(rawIocs, keys, cache, onProgress) {
  const { picked: iocs, truncated } = capIocs(rawIocs, MAX_IOCS_PER_SCAN);
  if (truncated) {
    onProgress({
      type:    "warning",
      provider: "scanner",
      message: `Scan capped at ${MAX_IOCS_PER_SCAN} IoCs (found ${rawIocs.length}). Raise TI_MAX_IOCS in server/.env to scan more.`,
    });
  }

  const vtAcquire = tokenBucket(VT_TOKENS, VT_WINDOW_MS);
  if (!keys.vt)    onProgress({ type: "warning", provider: "vt",    message: "VirusTotal disabled — set VIRUSTOTAL_API_KEY in server/.env" });
  if (!keys.aipdb) onProgress({ type: "warning", provider: "aipdb", message: "AbuseIPDB disabled — set ABUSEIPDB_API_KEY in server/.env" });

  const results = [];
  const tasks = [];

  for (const ioc of iocs) {
    onProgress({ type: "ioc_found", ioc: ioc.value, iocType: ioc.type, foundIn: ioc.foundIn });

    // Skip provider calls entirely for allowlisted IoCs — they're always clean.
    const allowlisted =
      (ioc.type === "hash"   && isAllowlistedHash(ioc.value)) ||
      (ioc.type === "domain" && isAllowlistedDomain(ioc.value)) ||
      (ioc.type === "url"    && isAllowlistedDomain(hostFromUrl(ioc.value)));
    if (allowlisted) {
      const result = {
        ioc: ioc.value, iocType: ioc.type,
        verdict: "clean", score: 0,
        sources: [allowlistResult("local", "known-good")],
        foundIn: ioc.foundIn,
      };
      results.push(result);
      onProgress({ type: "result", result });
      continue;
    }

    const providers = providersForType(ioc.type, keys);
    if (providers.length === 0) {
      const noop = {
        ioc: ioc.value, iocType: ioc.type, verdict: "unknown", score: 0,
        sources: [], foundIn: ioc.foundIn,
      };
      results.push(noop);
      onProgress({ type: "result", result: noop });
      continue;
    }

    tasks.push((async () => {
      const sources = [];
      for (const p of providers) {
        const cached = cache.get(p, ioc.type, ioc.value);
        if (cached) { sources.push(cached); continue; }
        try {
          let fresh;
          if (p === "vt") {
            fresh = await vtAcquire(() => VT.lookupByType(keys.vt, ioc.type, ioc.value));
          } else if (p === "aipdb") {
            fresh = await AIPDB.lookupByType(keys.aipdb, ioc.type, ioc.value);
          }
          if (fresh) {
            cache.put(p, ioc.type, ioc.value, fresh);
            sources.push(fresh);
          }
        } catch (err) {
          onProgress({ type: "warning", provider: p, message: `${ioc.value}: ${err.message}` });
        }
      }
      const merged = mergeVerdict(sources.length ? sources : [{ verdict: "unknown", score: 0 }]);
      const result = {
        ioc: ioc.value, iocType: ioc.type,
        verdict: merged.verdict, score: merged.score,
        sources, foundIn: ioc.foundIn,
      };
      results.push(result);
      onProgress({ type: "result", result });
    })());
  }

  await Promise.all(tasks);
  cache.flush();
  return results;
}

// ─── Recommendations ──────────────────────────────────────────────────────────

const ARTIFACT_SUGGESTIONS = {
  hash: [
    { artifactName: "Windows.System.Amcache",        reason: "Enumerates executed binaries with SHA1 hashes." },
    { artifactName: "Windows.System.Pslist",         reason: "Running processes with Exe paths — hash and cross-check." },
    { artifactName: "Windows.Forensics.Prefetch",    reason: "Recently executed binaries with path + run count." },
  ],
  ip: [
    { artifactName: "Windows.System.ActiveNetworkConnections", reason: "Live TCP/UDP connections — outbound IPs ready to score." },
    { artifactName: "Windows.EventLogs.Sysmon",                reason: "Sysmon network events (if Sysmon deployed)." },
  ],
  domain: [
    { artifactName: "Windows.Applications.Chrome.History",   reason: "Browser URL history — domains ready for reputation check." },
    { artifactName: "Windows.Applications.Firefox.History",  reason: "Firefox URL history." },
    { artifactName: "Windows.DNS.Cache",                     reason: "Resolver cache — all recently looked-up domains." },
  ],
  url: [
    { artifactName: "Windows.Applications.Chrome.History",   reason: "Browser URL history — full URLs." },
    { artifactName: "Windows.Applications.Edge.History",     reason: "Edge URL history." },
  ],
};

export function recommendCollections(iocs) {
  const byType = { hash: 0, ip: 0, domain: 0, url: 0 };
  for (const i of iocs) byType[i.type] = (byType[i.type] || 0) + 1;

  const out = [];
  for (const type of ["hash", "ip", "domain", "url"]) {
    if (byType[type] === 0) out.push(...ARTIFACT_SUGGESTIONS[type].slice(0, 2));
  }
  // Dedup by artifact name (same artifact may cover two gaps).
  const seen = new Set();
  return out.filter((s) => (seen.has(s.artifactName) ? false : (seen.add(s.artifactName), true)));
}

// ─── Helper: new scan id ─────────────────────────────────────────────────────

export function newScanId() {
  return "scan-" + crypto.randomBytes(6).toString("hex");
}
