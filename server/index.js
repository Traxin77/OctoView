import { exec, spawn }  from "child_process";
import { promisify }    from "util";
import express           from "express";
import cors              from "cors";
import path              from "path";
import fs                from "fs";
import os                from "os";
import yaml              from "js-yaml";
import { fileURLToPath } from "url";
import {
  extractIocs, scanSession, recommendCollections,
  createCache, newScanId, MAX_IOCS_PER_SCAN,
} from "./threat_intel.js";

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load server/.env into process.env if present (Node 22+; doesn't override
// vars already set in the shell).
try {
  const envFile = path.join(__dirname, ".env");
  if (fs.existsSync(envFile) && typeof process.loadEnvFile === "function") {
    process.loadEnvFile(envFile);
  }
} catch { /* ignore */ }

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const VR_API_CONFIG   = process.env.VR_API_CONFIG || path.join(__dirname, "api.config.yaml");
const PYTHON          = process.env.PYTHON        || "/home/kali/velociprompt/utils/venv/bin/python3";
const VQL_SCRIPT      = path.join(__dirname, "vql_query.py");
const AGENT_SCRIPT    = path.join(__dirname, "agent.py");
const ENRICH_SCRIPT   = path.join(__dirname, "enrich_artifacts.py");
const CATALOG_FILE    = path.join(__dirname, "workspace", "artifact_catalog.json");
const OUTPUTS_ROOT    = path.join(__dirname, "..", "outputs");
const SESSIONS_DIR    = path.join(__dirname, "sessions");
const PORT            = parseInt(process.env.PORT || "3001", 10);
const REFRESH_MS      = 15_000;
const ARTIFACTS_MS    = 60 * 60 * 1000;   // 1 hour
const POLL_INTERVAL   = 3_000;
const POLL_TIMEOUT    = 300_000;

// ─── Agent build config ───────────────────────────────────────────────────────
const VR_BIN          = process.env.VR_BIN          || "/usr/local/bin/velociraptor";
const VR_CLIENT_CFG   = process.env.VR_CLIENT_CFG   || "/home/kali/velociprompt/utils/config/client.config.yaml";
const AGENT_OUT_DIR   = process.env.AGENT_OUT_DIR   || "/home/kali/velociprompt/utils/binaries";
const AGENT_SRC_DIR   = process.env.AGENT_SRC_DIR   || "/home/kali/velociprompt/utils/sources";
const VR_VERSION      = process.env.VR_VERSION      || "v0.75.6";
const VR_RELEASE_URL  = process.env.VR_RELEASE_URL  || "https://github.com/Velocidex/velociraptor/releases/download";

// Per-OS source binary filenames (inside AGENT_SRC_DIR and as GitHub release assets).
const AGENT_SOURCE_FILES = {
  windows: `velociraptor-${VR_VERSION}-windows-amd64.exe`,
  linux:   `velociraptor-${VR_VERSION}-linux-amd64`,
  darwin:  `velociraptor-${VR_VERSION}-darwin-amd64`,
};

function agentSourcePath(osType) {
  const override = process.env[`VR_SRC_${osType.toUpperCase()}`];
  if (override) return override;
  const file = AGENT_SOURCE_FILES[osType];
  if (!file) return "";
  return path.join(AGENT_SRC_DIR, file);
}

// Download a source binary from the Velociraptor GitHub release if it's
// missing locally. Streams to a .part file and renames on completion so a
// crashed download can't leave a half-written binary that later gets used.
async function ensureAgentSource(osType) {
  const dest = agentSourcePath(osType);
  if (!dest) throw new Error(`no source filename defined for ${osType}`);
  if (fs.existsSync(dest) && fs.statSync(dest).size > 0) return dest;

  const file = AGENT_SOURCE_FILES[osType];
  if (!file) throw new Error(`cannot auto-download ${osType}`);

  if (!fs.existsSync(AGENT_SRC_DIR)) fs.mkdirSync(AGENT_SRC_DIR, { recursive: true, mode: 0o700 });

  const url = `${VR_RELEASE_URL}/${VR_VERSION}/${file}`;
  const tmp = `${dest}.part`;
  console.log(`[agent src] downloading ${url}`);

  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok || !resp.body)
    throw new Error(`download failed: ${resp.status} ${resp.statusText}`);

  // Stream the response body to disk without buffering the whole file.
  const { Readable } = await import("stream");
  const { pipeline } = await import("stream/promises");
  await pipeline(Readable.fromWeb(resp.body), fs.createWriteStream(tmp, { mode: 0o600 }));

  fs.renameSync(tmp, dest);
  if (osType !== "windows") fs.chmodSync(dest, 0o700);
  console.log(`[agent src] saved ${dest} (${fs.statSync(dest).size} bytes)`);
  return dest;
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Python VQL helper ────────────────────────────────────────────────────────
async function py(mode, ...args) {
  const escaped = args.map((a) => JSON.stringify(String(a))).join(" ");
  const cmd = `"${PYTHON}" "${VQL_SCRIPT}" ${mode} "${VR_API_CONFIG}" ${escaped}`;
  const { stdout } = await execAsync(cmd, { timeout: 60_000, maxBuffer: 100 * 1024 * 1024 });
  const result = JSON.parse(stdout.trim());
  if (result?.error) throw new Error(result.error);
  return result;
}

// ─── Client cache ─────────────────────────────────────────────────────────────
function toRelativeTime(us) {
  if (!us) return "never";
  const diff = Date.now() - Number(us) / 1000;
  if (diff < 60_000)     return "just now";
  if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function mapClient(row) {
  const osRaw  = (row.os_system || "").toLowerCase();
  let osType   = "linux";
  if (osRaw.includes("windows"))                               osType = "windows";
  else if (osRaw.includes("darwin") || osRaw.includes("mac")) osType = "macos";
  const lastSeenMs = Number(row.last_seen_at) / 1000;
  const diff       = Date.now() - lastSeenMs;
  const status     = diff < 2 * 60_000 ? "active" : "offline";
  const clientId   = row.client_id || "";
  return {
    id: clientId, clientId,
    hostname: row.hostname || clientId,
    os: osType, status,
    lastSeen: toRelativeTime(row.last_seen_at),
    ip: row.last_ip || "",
  };
}

let cachedClients = [];
let lastFetchedAt = null;
let fetchError    = null;

async function refreshClients() {
  try {
    const vql  = `SELECT client_id, os_info.hostname AS hostname, os_info.system AS os_system, last_ip, last_seen_at FROM clients() LIMIT 1000`;
    const rows = await py("query", vql);
    cachedClients = rows.map(mapClient);
    lastFetchedAt = new Date().toISOString();
    fetchError    = null;
    console.log(`[${lastFetchedAt}] ${cachedClients.length} clients`);
  } catch (err) {
    fetchError = err.message;
    console.error("Refresh failed:", err.message);
  }
}

refreshClients();
setInterval(refreshClients, REFRESH_MS);

// ─── Artifact catalog cache ───────────────────────────────────────────────────
// Fetches the full Velociraptor artifact catalog once per hour and keeps a
// local enriched copy on disk so agent.py can do keyword/intent search without
// a gRPC round-trip. Enrichment (LLM-generated user-intent keywords) runs in a
// background process; only new/changed entries are re-enriched.

let cachedArtifacts       = [];
let artifactsLastFetchedAt = null;
let artifactsFetchError    = null;
let enrichProc             = null;

function loadCatalogFromDisk() {
  try {
    if (!fs.existsSync(CATALOG_FILE)) return;
    const data = JSON.parse(fs.readFileSync(CATALOG_FILE, "utf8"));
    if (Array.isArray(data)) {
      cachedArtifacts       = data;
      artifactsLastFetchedAt = new Date(fs.statSync(CATALOG_FILE).mtime).toISOString();
      console.log(`[artifacts] loaded ${data.length} from disk cache`);
    }
  } catch (err) {
    console.warn("[artifacts] could not load disk cache:", err.message);
  }
}

function spawnEnrichment(rawCatalog) {
  if (enrichProc) {
    console.log("[enrich] skip: previous enrichment still running");
    return;
  }
  try {
    enrichProc = spawn(PYTHON, [ENRICH_SCRIPT, CATALOG_FILE], {
      cwd: __dirname,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    console.error("[enrich] spawn failed:", err.message);
    enrichProc = null;
    return;
  }

  enrichProc.stdout.on("data", (chunk) => process.stdout.write(`[enrich] ${chunk}`));
  enrichProc.stderr.on("data", (chunk) => process.stderr.write(`[enrich] ${chunk}`));
  enrichProc.on("error", (err) => {
    console.error("[enrich] error:", err.message);
    enrichProc = null;
  });
  enrichProc.on("close", (code) => {
    console.log(`[enrich] exited with code ${code}`);
    enrichProc = null;
    // Reload the freshly enriched catalog into memory.
    loadCatalogFromDisk();
  });

  enrichProc.stdin.on("error", (err) => {
    console.error("[enrich] stdin error:", err.message);
  });
  enrichProc.stdin.end(JSON.stringify(rawCatalog));
}

async function refreshArtifacts() {
  try {
    const rows = await py(
      "query",
      "SELECT name, description FROM artifact_definitions() ORDER BY name",
    );
    if (!Array.isArray(rows)) throw new Error("bad artifact catalog shape");
    artifactsLastFetchedAt = new Date().toISOString();
    artifactsFetchError    = null;
    console.log(`[${artifactsLastFetchedAt}] ${rows.length} artifacts in catalog`);

    // Populate cache immediately with raw rows so search works on first boot
    // even before enrichment finishes. Keywords from any previous on-disk
    // catalog are merged so we don't lose them between boots.
    const diskByName = new Map(cachedArtifacts.map((a) => [a.name, a.keywords || []]));
    cachedArtifacts = rows.map((r) => ({
      name:        r.name,
      description: r.description || "",
      keywords:    diskByName.get(r.name) || [],
    }));

    // Hand off to the enrichment worker. It merges with the existing on-disk
    // catalog, reuses keywords for unchanged entries (hash match), and only
    // hits NIM for new/changed artifacts.
    spawnEnrichment(rows);
  } catch (err) {
    artifactsFetchError = err.message;
    console.error("[artifacts] refresh failed:", err.message);
  }
}

loadCatalogFromDisk();
refreshArtifacts();
setInterval(refreshArtifacts, ARTIFACTS_MS);

function searchArtifactsLocal(query, limit = 15) {
  const q = String(query || "").toLowerCase().trim();
  if (!q) return [];
  const tokens = q.split(/[^a-z0-9]+/).filter((t) => t.length >= 2);

  const scored = [];
  for (const art of cachedArtifacts) {
    const name    = (art.name || "").toLowerCase();
    const desc    = (art.description || "").toLowerCase();
    const keywords = Array.isArray(art.keywords) ? art.keywords : [];
    const kwJoined = keywords.map((k) => String(k).toLowerCase()).join(" ");

    let score = 0;
    if (q && name.includes(q)) score += 3;
    for (const kw of keywords) {
      const k = String(kw).toLowerCase();
      if (q && (k.includes(q) || q.includes(k))) score += 3;
    }
    for (const tok of tokens) {
      if (name.includes(tok))     score += 2;
      if (kwJoined.includes(tok)) score += 2;
      if (desc.includes(tok))     score += 1;
    }
    if (score > 0) scored.push({ art, score });
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((s) => ({
    name:        s.art.name,
    description: s.art.description,
    keywords:    s.art.keywords || [],
    score:       s.score,
  }));
}

// ─── Express ──────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));

app.get("/api/health", (_req, res) => {
  res.json({ ok: !fetchError, lastFetchedAt, clientCount: cachedClients.length, error: fetchError });
});

app.get("/api/clients", (_req, res) => {
  if (fetchError && cachedClients.length === 0)
    return res.status(502).json({ error: "Could not reach Velociraptor", details: fetchError });
  res.json({ clients: cachedClients, lastFetchedAt, error: fetchError || null });
});

app.get("/api/artifacts/search", (req, res) => {
  const q     = String(req.query.q || "");
  const limit = Math.max(1, Math.min(50, parseInt(req.query.limit || "15", 10) || 15));
  if (!cachedArtifacts.length && artifactsFetchError) {
    return res.status(502).json({
      error: "Artifact catalog unavailable",
      details: artifactsFetchError,
    });
  }
  res.json({
    query:   q,
    total:   cachedArtifacts.length,
    results: searchArtifactsLocal(q, limit),
    lastFetchedAt: artifactsLastFetchedAt,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/chat
// Runs agent.py exactly like the CLI:
//   echo '<json>' | PYTHONUNBUFFERED=1 python3 agent.py
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/chat", (req, res) => {
  const { prompt, clientIds, sessionId } = req.body || {};
  if (!prompt)
    return res.status(400).json({ error: "Missing prompt" });

  const sid   = sessionId || "default";
  const input = JSON.stringify({ prompt, clientIds: clientIds || [], sessionId: sid });

  // Escape input for shell — use single quotes, escape any single quotes inside
  const shellInput = input.replace(/'/g, "'\\''");
  const cmd = `echo '${shellInput}' | PYTHONUNBUFFERED=1 "${PYTHON}" "${AGENT_SCRIPT}"`;

  console.log("[chat] running agent for:", prompt);

  res.writeHead(200, {
    "Content-Type":  "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection":    "keep-alive",
  });
  res.flushHeaders();

  const send = (obj) => {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
    if (res.flush) res.flush();
  };

  const agentProc = exec(cmd, {
    timeout:   600_000,
    maxBuffer: 100 * 1024 * 1024,  // 100MB
    cwd:       __dirname,
  });

  let buffer = "";

  agentProc.stdout.on("data", (chunk) => {
    console.log("[agent stdout]", chunk.toString().slice(0, 200));
    buffer += chunk.toString();
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const event = JSON.parse(trimmed);
        send(event);
        if (event.type === "flow") {
          send({ type: "status", message: `Collection started: ${event.artifactName} on ${event.clientId}` });
        }
      } catch {
        // non-JSON debug line — ignore
      }
    }
  });

  agentProc.stderr.on("data", (chunk) => {
    console.error("[agent stderr]", chunk.toString());
  });
  agentProc.on("error", (err) => {
    console.error("[agent error]", err);
  });
  agentProc.on("close", (code) => {
    console.log("[agent] exited with code", code);
    if (buffer.trim()) {
      try { send(JSON.parse(buffer.trim())); } catch { /* ignore */ }
    }
    res.end();
  });

  res.on("close", () => {
    if (!res.writableEnded) {
      try { agentProc.kill(); } catch { /* ignore */ }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/stream?clientId=X&flowId=Y&artifactName=Z
// Polls a Velociraptor flow and streams results as SSE.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/stream", (req, res) => {
  const { clientId, flowId, artifactName } = req.query;
  if (!clientId || !flowId)
    return res.status(400).json({ error: "Missing clientId or flowId" });

  res.writeHead(200, {
    "Content-Type":  "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection":    "keep-alive",
  });
  res.flushHeaders();

  const send = (obj) => {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
    if (res.flush) res.flush();
  };

  send({ type: "status", message: `Waiting for ${artifactName || flowId}...` });

  let elapsed     = 0;
  let seenRowKeys = new Set();

  const interval = setInterval(async () => {
    elapsed += POLL_INTERVAL;
    if (elapsed > POLL_TIMEOUT) {
      send({ type: "error", message: "Flow timed out" });
      clearInterval(interval);
      res.end();
      return;
    }
    try {
      const status = await py("status", clientId, flowId);
      const state  = (status.state || "").toUpperCase();

      if (state === "ERROR") {
        send({ type: "error", message: status.error || "Flow failed" });
        clearInterval(interval);
        res.end();
        return;
      }

      const rows    = await py("results", clientId, flowId);
      const newRows = rows.filter((r) => {
        const key = JSON.stringify(r);
        if (seenRowKeys.has(key)) return false;
        seenRowKeys.add(key);
        return true;
      });

      if (newRows.length > 0)
        send({ type: "rows", rows: newRows, artifactName });

      if (state === "FINISHED") {
        send({ type: "done", artifactName, totalRows: seenRowKeys.size });
        clearInterval(interval);
        res.end();
      }
    } catch (err) {
      send({ type: "error", message: err.message });
      clearInterval(interval);
      res.end();
    }
  }, POLL_INTERVAL);

  req.on("close", () => clearInterval(interval));
});

// ─────────────────────────────────────────────────────────────────────────────
// Output file browser — lists and reads files in outputs/<sessionId>/
// ─────────────────────────────────────────────────────────────────────────────
function safeSessionDir(sessionId) {
  const sid = String(sessionId || "").replace(/[^a-zA-Z0-9._-]/g, "_") || "default";
  return path.join(OUTPUTS_ROOT, sid);
}

app.get("/api/files", (req, res) => {
  const dir = safeSessionDir(req.query.sessionId);
  try {
    if (!fs.existsSync(dir)) return res.json({ files: [] });
    const files = fs.readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => {
        const s = fs.statSync(path.join(dir, e.name));
        return { name: e.name, size: s.size, mtime: s.mtime.toISOString() };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
    res.json({ files });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/files/content", (req, res) => {
  const name = String(req.query.name || "");
  if (!name || name.includes("/") || name.includes("\\") || name === "..")
    return res.status(400).json({ error: "invalid name" });

  const file  = path.join(safeSessionDir(req.query.sessionId), name);
  const LIMIT = 5 * 1024 * 1024;
  try {
    const stat = fs.statSync(file);
    const buf  = fs.readFileSync(file);
    const truncated = buf.length > LIMIT;
    const content   = (truncated ? buf.subarray(0, LIMIT) : buf).toString("utf8");
    res.json({ name, size: stat.size, truncated, content });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Chat session management
// ─────────────────────────────────────────────────────────────────────────────
function safeSessionId(id) {
  const clean = String(id || "").replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!clean || /^\.+$/.test(clean)) return "";
  return clean;
}

function readSessionName(jsonlPath, fallback) {
  try {
    const contents = fs.readFileSync(jsonlPath, "utf8");
    for (const line of contents.split("\n")) {
      if (!line.trim()) continue;
      const turn = JSON.parse(line);
      if (turn.role === "user") {
        const content = String(turn.content || "");
        if (content.startsWith("[tool_result")) continue;
        return content.slice(0, 80);
      }
    }
  } catch { /* ignore */ }
  return fallback;
}

app.get("/api/sessions", (_req, res) => {
  try {
    if (!fs.existsSync(SESSIONS_DIR)) return res.json({ sessions: [] });
    const sessions = fs.readdirSync(SESSIONS_DIR)
      .filter((f) => f.endsWith(".jsonl"))
      .map((f) => {
        const id       = f.replace(/\.jsonl$/, "");
        const fullPath = path.join(SESSIONS_DIR, f);
        const stat     = fs.statSync(fullPath);
        return {
          id,
          name:  readSessionName(fullPath, id),
          mtime: stat.mtime.toISOString(),
        };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
    res.json({ sessions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/sessions/:id", (req, res) => {
  const id = safeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid id" });
  try {
    const jsonlPath   = path.join(SESSIONS_DIR, `${id}.jsonl`);
    const outputsPath = path.join(OUTPUTS_ROOT, id);
    if (fs.existsSync(jsonlPath))   fs.unlinkSync(jsonlPath);
    if (fs.existsSync(outputsPath)) fs.rmSync(outputsPath, { recursive: true, force: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/sessions/:id/messages", (req, res) => {
  const id = safeSessionId(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid id" });
  try {
    const jsonlPath = path.join(SESSIONS_DIR, `${id}.jsonl`);
    if (!fs.existsSync(jsonlPath)) return res.json({ messages: [] });
    const contents = fs.readFileSync(jsonlPath, "utf8");
    const messages = [];
    for (const line of contents.split("\n")) {
      if (!line.trim()) continue;
      let turn;
      try { turn = JSON.parse(line); } catch { continue; }
      const ts = turn.ts || new Date().toISOString();

      if (turn.role === "user") {
        const content = String(turn.content || "");
        if (content.startsWith("[tool_result")) continue;
        messages.push({ id: `hist-${messages.length}`, role: "user", content, timestamp: ts });
        continue;
      }

      if (turn.role === "assistant") {
        const raw = String(turn.content || "").trim();
        if (!raw) continue;

        // Try to parse as JSON — covers both legacy envelope and new tool-calls blob.
        let parsed = null;
        if (raw.startsWith("{")) {
          try { parsed = JSON.parse(raw); } catch { /* fall through */ }
        }

        if (parsed && typeof parsed === "object") {
          // Legacy: {"action":"final","answer":"..."}
          if (parsed.action === "final" && parsed.answer) {
            messages.push({
              id: `hist-${messages.length}`, role: "assistant",
              content: String(parsed.answer), timestamp: ts, status: "complete",
            });
            continue;
          }
          // New (native function-calling): {"content":"...","tool_calls":[...]}
          // Only render if there's user-visible text (intermediate tool-only
          // turns have empty content and no replay value).
          if (typeof parsed.content === "string" && parsed.content.trim()) {
            messages.push({
              id: `hist-${messages.length}`, role: "assistant",
              content: parsed.content, timestamp: ts, status: "complete",
            });
            continue;
          }
          // Legacy intermediate tool/display turn — skip.
          if (parsed.action || parsed.tool_calls) continue;
        }

        // Plain-text final answer (new format path without a JSON wrapper).
        messages.push({
          id: `hist-${messages.length}`, role: "assistant",
          content: raw, timestamp: ts, status: "complete",
        });
      }
      // turn.role === "tool" — skip; tool results stream live during a run,
      // they're not part of the replayable conversation.
    }
    res.json({ messages });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Threat Intel — read-only enrichment of IoCs already present in a chat.
// Never triggers a Velociraptor collection.
// ─────────────────────────────────────────────────────────────────────────────
const TI_CACHE_FILE = path.join(__dirname, "workspace", "threat_intel_cache.json");
const tiCache       = createCache(TI_CACHE_FILE);
const tiScans       = new Map();   // scanId → scan state
const TI_MAX_SCANS  = 16;

function tiPruneScans() {
  if (tiScans.size <= TI_MAX_SCANS) return;
  const oldest = [...tiScans.entries()]
    .sort((a, b) => (a[1].createdAt || 0) - (b[1].createdAt || 0))
    .slice(0, tiScans.size - TI_MAX_SCANS);
  for (const [id] of oldest) tiScans.delete(id);
}

function tiBroadcast(scan, event) {
  scan.events.push(event);
  for (const send of scan.subscribers) {
    try { send(event); } catch { /* dead subscriber */ }
  }
}

// Load full artifact rows from outputs/<sessionId>/results_*.json as synthetic
// messages so IoC extraction doesn't depend on what the browser currently has
// in state. Survives reloads and tab-switches because the files are the
// ground truth — agent.py writes every collected flow here (see agent.py:471).
//
// Strictly scoped to the requested session's folder:
//   - sessionId is already sanitised by safeSessionId (a-zA-Z0-9._- only)
//   - path.resolve + containment check blocks any directory traversal
//   - non-recursive readdir, so nested subfolders are ignored
//   - only files named results_*.json are considered (agent.py:471 convention)
//   - isFile() guard rejects a directory that happens to match the name glob
const TI_OUTPUT_FILE_CAP = 50 * 1024 * 1024;   // per-file byte cap

function readOutputFileMessages(sessionId) {
  const synth = [];
  const rootResolved = path.resolve(OUTPUTS_ROOT);
  const dir          = path.resolve(path.join(OUTPUTS_ROOT, sessionId));
  if (dir !== rootResolved && !dir.startsWith(rootResolved + path.sep)) return synth;

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return synth; }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const name = entry.name;
    if (!name.startsWith("results_") || !name.endsWith(".json")) continue;
    const full = path.join(dir, name);
    try {
      if (fs.statSync(full).size > TI_OUTPUT_FILE_CAP) {
        console.warn(`[threat-intel] skipping ${name}: exceeds ${TI_OUTPUT_FILE_CAP} bytes`);
        continue;
      }
      const parsed = JSON.parse(fs.readFileSync(full, "utf8"));
      if (Array.isArray(parsed) && parsed.length) {
        synth.push({ id: `outputs/${name}`, rows: parsed });
      }
    } catch (err) {
      console.warn(`[threat-intel] skipping ${name}: ${err.message}`);
    }
  }
  return synth;
}

app.post("/api/threat-intel/:sessionId/scan", (req, res) => {
  const sessionId = safeSessionId(req.params.sessionId);
  if (!sessionId) return res.status(400).json({ error: "invalid session id" });
  const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];

  const outputMessages = readOutputFileMessages(sessionId);
  const iocs = extractIocs([...messages, ...outputMessages]);
  const scanId = newScanId();

  const scan = {
    scanId, sessionId,
    status: "running",
    createdAt: Date.now(),
    events: [],
    results: [],
    warnings: [],
    recommendations: [],
    iocCount: iocs.length,
    subscribers: new Set(),
  };
  tiScans.set(scanId, scan);
  tiPruneScans();

  res.json({ scanId, iocCount: iocs.length });

  // Kick off async scan. onProgress records events for future subscribers
  // and broadcasts live to connected ones.
  const keys = {
    vt:    process.env.VIRUSTOTAL_API_KEY || "",
    aipdb: process.env.ABUSEIPDB_API_KEY  || "",
  };

  const onProgress = (event) => {
    if (event.type === "warning")  scan.warnings.push(event);
    if (event.type === "result")   scan.results.push(event.result);
    tiBroadcast(scan, event);
  };

  // Synthesise a "started" event so late subscribers know the total IoC count.
  // iocCount reflects what will actually be scored (capped); rawCount is the
  // pre-cap total so the UI can show "50 of 312".
  const effectiveCount = Math.min(iocs.length, MAX_IOCS_PER_SCAN);
  tiBroadcast(scan, {
    type:      "started",
    iocCount:  effectiveCount,
    rawCount:  iocs.length,
    capped:    iocs.length > MAX_IOCS_PER_SCAN,
    sessionId,
  });

  // Recommendations computed upfront from what was extracted — they don't
  // depend on scan results.
  scan.recommendations = recommendCollections(iocs);
  for (const rec of scan.recommendations) {
    tiBroadcast(scan, { type: "recommendation", ...rec });
  }

  scanSession(iocs, keys, tiCache, onProgress)
    .then(() => {
      scan.status      = "complete";
      scan.completedAt = Date.now();
      const summary = summariseResults(scan.results);
      tiBroadcast(scan, { type: "done", summary, recommendations: scan.recommendations });
    })
    .catch((err) => {
      scan.status = "error";
      tiBroadcast(scan, { type: "error", message: err.message });
    });
});

function summariseResults(results) {
  const s = { total: results.length, malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  for (const r of results) {
    if (r.verdict in s) s[r.verdict]++;
  }
  return s;
}

app.get("/api/threat-intel/:scanId/stream", (req, res) => {
  const scan = tiScans.get(String(req.params.scanId || ""));
  if (!scan) return res.status(404).json({ error: "scan not found" });

  res.writeHead(200, {
    "Content-Type":  "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection":    "keep-alive",
  });
  res.flushHeaders();

  const send = (obj) => {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
    if (res.flush) res.flush();
  };

  // Replay any events already buffered.
  for (const ev of scan.events) send(ev);

  if (scan.status !== "running") {
    res.end();
    return;
  }
  scan.subscribers.add(send);
  req.on("close", () => scan.subscribers.delete(send));
});

app.get("/api/threat-intel/:scanId", (req, res) => {
  const scan = tiScans.get(String(req.params.scanId || ""));
  if (!scan) return res.status(404).json({ error: "scan not found" });
  res.json({
    scanId:          scan.scanId,
    sessionId:       scan.sessionId,
    status:          scan.status,
    iocCount:        scan.iocCount,
    results:         scan.results,
    warnings:        scan.warnings,
    recommendations: scan.recommendations,
    summary:         summariseResults(scan.results),
    createdAt:       new Date(scan.createdAt).toISOString(),
    completedAt:     scan.completedAt ? new Date(scan.completedAt).toISOString() : null,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Agent binary builder — repack a velociraptor binary with the client config
// so it auto-registers with this server when executed on the target host.
// ─────────────────────────────────────────────────────────────────────────────
function safeAgentName(name) {
  const clean = String(name || "").replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!clean || clean.startsWith(".")) return "";
  return clean;
}

function agentExtFor(osType) {
  if (osType === "windows") return ".exe";
  if (osType === "docker")  return ".tar.gz";
  return "";
}

app.get("/api/agents", (_req, res) => {
  try {
    if (!fs.existsSync(AGENT_OUT_DIR)) fs.mkdirSync(AGENT_OUT_DIR, { recursive: true });
    const files = fs.readdirSync(AGENT_OUT_DIR, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => {
        const st = fs.statSync(path.join(AGENT_OUT_DIR, e.name));
        let os = "linux";
        if (e.name.endsWith(".exe"))        os = "windows";
        else if (e.name.endsWith(".tar.gz")) os = "docker";
        return { name: e.name, size: st.size, mtime: st.mtime.toISOString(), os };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
    res.json({ agents: files });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/agents/build", async (req, res) => {
  const osType = String(req.body?.os || "").toLowerCase();
  if (!["windows", "linux", "darwin", "docker"].includes(osType))
    return res.status(400).json({ error: "invalid os (windows|linux|darwin|docker)" });

  if (!fs.existsSync(VR_CLIENT_CFG))
    return res.status(500).json({ error: `client config missing: ${VR_CLIENT_CFG}` });

  const srcKey = osType === "docker" ? "linux" : osType;

  let src;
  try {
    src = await ensureAgentSource(srcKey);
  } catch (err) {
    return res.status(500).json({ error: `source binary unavailable: ${err.message}` });
  }

  try {
    if (!fs.existsSync(AGENT_OUT_DIR)) fs.mkdirSync(AGENT_OUT_DIR, { recursive: true });
    const stamp    = Date.now();
    const baseName = `velociraptor-agent-${osType}-${stamp}`;
    const repackOut = osType === "docker"
      ? path.join(AGENT_OUT_DIR, `${baseName}.bin`)
      : path.join(AGENT_OUT_DIR, `${baseName}${agentExtFor(osType)}`);

    // Bake `autoexec` so running the binary with zero args launches the
    // client — matches the Windows MSI "just run it" UX on Linux/macOS too.
    // This Velociraptor build has no `config repack --merge`, so we merge
    // at the YAML layer: load the client config, splice in autoexec, write
    // to a temp file, then repack from that.
    const baseCfg = yaml.load(fs.readFileSync(VR_CLIENT_CFG, "utf8")) || {};
    baseCfg.autoexec = { argv: ["client", "-v"] };
    const mergedCfg = path.join(os.tmpdir(), `vp-client-${stamp}.yaml`);
    fs.writeFileSync(mergedCfg, yaml.dump(baseCfg), { mode: 0o600 });

    const cmd = `"${VR_BIN}" config repack --exe "${src}" "${mergedCfg}" "${repackOut}"`;
    console.log("[agent build]", cmd);
    try {
      await execAsync(cmd, { timeout: 120_000, maxBuffer: 50 * 1024 * 1024 });
    } finally {
      try { fs.unlinkSync(mergedCfg); } catch { /* ignore */ }
    }

    if (!fs.existsSync(repackOut))
      throw new Error("repack finished but output missing");

    if (osType === "docker") {
      // Bundle the repacked Linux binary with a Dockerfile into a tar.gz
      const bundleDir = path.join(AGENT_OUT_DIR, `.build-${stamp}`);
      fs.mkdirSync(bundleDir, { recursive: true });
      fs.copyFileSync(repackOut, path.join(bundleDir, "velociraptor"));
      fs.chmodSync(path.join(bundleDir, "velociraptor"), 0o755);
      fs.writeFileSync(
        path.join(bundleDir, "Dockerfile"),
        [
          "FROM debian:stable-slim",
          "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*",
          "COPY velociraptor /usr/local/bin/velociraptor",
          "RUN chmod +x /usr/local/bin/velociraptor",
          'ENTRYPOINT ["/usr/local/bin/velociraptor"]',
          "",
        ].join("\n"),
      );
      fs.writeFileSync(
        path.join(bundleDir, "README.txt"),
        [
          "VelociPrompt — Docker agent bundle",
          "",
          "Build:  docker build -t velociraptor-agent .",
          "Run:    docker run -d --name vr-agent --restart unless-stopped velociraptor-agent",
          "",
          "The embedded client config points back to the VelociPrompt server.",
          "",
        ].join("\n"),
      );
      const tarOut = path.join(AGENT_OUT_DIR, `${baseName}.tar.gz`);
      await execAsync(`tar -czf "${tarOut}" -C "${bundleDir}" .`, { timeout: 60_000 });
      fs.rmSync(bundleDir, { recursive: true, force: true });
      fs.unlinkSync(repackOut);
      const st = fs.statSync(tarOut);
      return res.json({ name: path.basename(tarOut), size: st.size, os: osType });
    }

    // For linux/darwin ensure the file is executable
    if (osType !== "windows") fs.chmodSync(repackOut, 0o755);
    const st = fs.statSync(repackOut);
    res.json({ name: path.basename(repackOut), size: st.size, os: osType });
  } catch (err) {
    console.error("[agent build] failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/agents/download/:name", (req, res) => {
  const name = safeAgentName(req.params.name);
  if (!name) return res.status(400).json({ error: "invalid name" });
  const file = path.join(AGENT_OUT_DIR, name);
  if (!fs.existsSync(file)) return res.status(404).json({ error: "not found" });
  res.download(file, name);
});

app.delete("/api/agents/:name", (req, res) => {
  const name = safeAgentName(req.params.name);
  if (!name) return res.status(400).json({ error: "invalid name" });
  const file = path.join(AGENT_OUT_DIR, name);
  if (!fs.existsSync(file)) return res.status(404).json({ error: "not found" });
  try { fs.unlinkSync(file); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`VelociPrompt backend on http://localhost:${PORT}`);
  console.log(`Agent: ${AGENT_SCRIPT}`);
  console.log(`Python: ${PYTHON}`);
});