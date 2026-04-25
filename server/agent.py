#!/usr/bin/env python3
"""
agent.py — VelociPrompt Unified Agent (native function calling).

LOCAL MODE  (no clients): bash, file ops, python, http, remember
VR MODE     (clients selected): search_artifacts, run_vql, list_clients,
                                 collect_artifact, get_flow_results, remember

This agent uses OpenAI-compatible `tools=[]` + `tool_choice="auto"` against
NVIDIA NIM. It reuses one gRPC channel to Velociraptor for the whole run
(via VrClient) and serves artifact search from a local JSON cache that the
Node server pre-populates and enriches with user-intent keywords.
"""

import json
import os
import sys
import re
import time
import platform
import subprocess
import threading
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

# Import vql_query as a sibling module so we can reuse one gRPC channel.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import vql_query  # noqa: E402

# ─── Paths ────────────────────────────────────────────────────────────────────
WORKSPACE    = SCRIPT_DIR / "workspace"
SESSIONS_DIR = SCRIPT_DIR / "sessions"
OUTPUTS_ROOT = SCRIPT_DIR.parent / "outputs"
CATALOG_FILE = WORKSPACE / "artifact_catalog.json"

load_dotenv(SCRIPT_DIR.parent / ".env", override=True)
load_dotenv(SCRIPT_DIR / ".env",        override=True)

# ─── Config ───────────────────────────────────────────────────────────────────
NIM_API_KEY  = os.getenv("NIM_API_KEY", os.getenv("NVIDIA_API_KEY", ""))
NIM_MODEL    = os.getenv("NIM_MODEL",   "meta/llama-3.3-70b-instruct")
NIM_BASE_URL = os.getenv("NIM_BASE_URL","https://integrate.api.nvidia.com/v1")
VR_CONFIG    = os.getenv("VR_API_CONFIG", str(SCRIPT_DIR / "api.config.yaml"))

IS_WINDOWS      = platform.system() == "Windows"
OS_NAME         = platform.system()
WORKDIR         = Path.cwd()   # overridden per-session in main()
MAX_TOOL_CALLS  = 20
MAX_TOOL_OUTPUT = 40_000
MAX_FILE_CHARS  = 15_000
MAX_TOTAL_CHARS = 100_000
CONTEXT_LIMIT   = 150_000
CATALOG_MAX_AGE = 24 * 3600        # fall back to gRPC if cache older than 24h

WORKSPACE.mkdir(exist_ok=True)
SESSIONS_DIR.mkdir(exist_ok=True)
OUTPUTS_ROOT.mkdir(exist_ok=True)

client = OpenAI(base_url=NIM_BASE_URL, api_key=NIM_API_KEY)

# ─── Emit ─────────────────────────────────────────────────────────────────────

def emit(obj: dict):
    print(json.dumps(obj), flush=True)

def emit_done(answer: str):
    emit({"type": "done", "answer": answer})

def emit_error(msg: str):
    emit({"type": "error", "message": msg})

# ─── Helpers ──────────────────────────────────────────────────────────────────

def truncate(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n...[truncated {len(text)} chars]"

def safe_path(raw: str) -> Path:
    p = Path(raw)
    return p.resolve() if p.is_absolute() else (WORKDIR / raw).resolve()

def _run_subprocess(cmd, timeout=30, shell=False, cwd=None) -> str:
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd or str(WORKDIR))
        out = r.stdout or ""
        if r.stderr:
            out += ("\n--- stderr ---\n" + r.stderr) if out else r.stderr
        if r.returncode != 0:
            out += f"\n[exit code: {r.returncode}]"
        return truncate(out) if out else "[no output]"
    except subprocess.TimeoutExpired:
        return f"Error: timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

# ─── LOCAL TOOLS ──────────────────────────────────────────────────────────────

_UNIX_ROOT_SEARCH = re.compile(r"find\s+/\s", re.IGNORECASE)
_WIN_ROOT_SEARCH  = re.compile(
    r"(?:Get-ChildItem\s+(?:-Path\s+)?[A-Za-z]:[/\\]\s|dir\s+/s\s+/b\s+[A-Za-z]:[/\\])",
    re.IGNORECASE,
)

def local_bash(command: str, timeout: int = 30) -> str:
    if (IS_WINDOWS and _WIN_ROOT_SEARCH.search(command)) or \
       (not IS_WINDOWS and _UNIX_ROOT_SEARCH.search(command)):
        return "Error: Blocked — recursive root search. Use find_files with a subdirectory."
    if IS_WINDOWS:
        return _run_subprocess(["cmd", "/c", command], timeout=timeout)
    return _run_subprocess(command, timeout=timeout, shell=True)

def local_read_file(file_path: str) -> str:
    try:
        t = safe_path(file_path)
        if not t.exists():  return f"Error: not found: {file_path}"
        if not t.is_file(): return f"Error: not a file: {file_path}"
        return truncate(t.read_text(encoding="utf-8", errors="replace"))
    except Exception as e: return f"Error: {e}"

def local_write_file(file_path: str, content: str) -> str:
    try:
        t = safe_path(file_path)
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text(content, encoding="utf-8")
        return f"OK — wrote {len(content)} chars to {t}"
    except Exception as e: return f"Error: {e}"

def local_edit_file(file_path: str, old_string: str, new_string: str) -> str:
    try:
        t = safe_path(file_path)
        if not t.exists(): return f"Error: not found: {file_path}"
        c = t.read_text(encoding="utf-8", errors="replace")
        n = c.count(old_string)
        if n == 0: return "Error: old_string not found."
        if n > 1:  return f"Error: old_string found {n} times — must be unique."
        t.write_text(c.replace(old_string, new_string, 1), encoding="utf-8")
        return f"OK — edited {t}"
    except Exception as e: return f"Error: {e}"

def local_delete_file(file_path: str) -> str:
    try:
        t = safe_path(file_path)
        if not t.exists(): return f"Error: not found: {file_path}"
        if t.is_dir(): t.rmdir(); return f"OK — removed dir {t}"
        t.unlink(); return f"OK — deleted {t}"
    except Exception as e: return f"Error: {e}"

def local_move_file(src: str, dst: str) -> str:
    try:
        s, d = safe_path(src), safe_path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(s), str(d))
        return f"OK — moved {s} -> {d}"
    except Exception as e: return f"Error: {e}"

def local_copy_file(src: str, dst: str) -> str:
    try:
        s, d = safe_path(src), safe_path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(s), str(d))
        return f"OK — copied {s} -> {d}"
    except Exception as e: return f"Error: {e}"

def local_make_dir(directory: str) -> str:
    try:
        safe_path(directory).mkdir(parents=True, exist_ok=True)
        return f"OK — {safe_path(directory)}"
    except Exception as e: return f"Error: {e}"

def local_list_dir(directory: str = ".", show_hidden: bool = False) -> str:
    try:
        t = safe_path(directory)
        if not t.exists(): return f"Error: not found: {directory}"
        if not t.is_dir(): return f"Error: not a directory: {directory}"
        entries = sorted(t.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        lines   = [f"Directory: {t}", ""]
        for e in entries:
            if not show_hidden and e.name.startswith("."): continue
            kind = "DIR " if e.is_dir() else "FILE"
            try:   sz = f"{e.stat().st_size:>12}" if e.is_file() else f"{'':>12}"
            except: sz = f"{'?':>12}"
            lines.append(f"  {kind}  {sz}  {e.name}")
        return "\n".join(lines)
    except Exception as e: return f"Error: {e}"

def local_find_files(pattern: str, directory: str = ".",
                     recursive: bool = True, max_results: int = 200,
                     timeout: int = 15) -> str:
    try:
        base = safe_path(directory)
    except Exception as e:
        return f"Error resolving path: {e}"
    if not base.exists():
        return f"Error: directory not found: {directory}"
    glob    = f"**/{pattern}" if recursive and "**" not in pattern else pattern
    matches = []
    def _glob():
        try:
            for m in base.glob(glob):
                matches.append(m)
                if len(matches) >= max_results: break
        except Exception: pass
    t = threading.Thread(target=_glob, daemon=True)
    t.start(); t.join(timeout=timeout)
    if not matches:
        return f"No matches for '{glob}' in {base}"
    lines = [f"Found {len(matches)} match(es) for '{glob}' in {base}:", ""]
    for m in matches:
        try:    lines.append(f"  {m.relative_to(base)}")
        except: lines.append(f"  {m}")
    return "\n".join(lines)

def local_grep(pattern: str, file_path: str,
               ignore_case: bool = False, context_lines: int = 0) -> str:
    try:
        t = safe_path(file_path)
        if not t.exists(): return f"Error: not found: {file_path}"
        content = t.read_text(encoding="utf-8", errors="replace")
        flags   = re.IGNORECASE if ignore_case else 0
        lines   = content.splitlines()
        hits    = []
        for i, line in enumerate(lines):
            if re.search(pattern, line, flags):
                s = max(0, i - context_lines)
                e = min(len(lines), i + context_lines + 1)
                for j in range(s, e):
                    hits.append(f"{j+1:5} {'>' if j==i else ' '} {lines[j]}")
                if context_lines: hits.append("---")
        return truncate("\n".join(hits)) if hits else f"No matches for '{pattern}' in {file_path}"
    except re.error as e: return f"Error: bad regex — {e}"
    except Exception as e: return f"Error: {e}"

def local_env_info() -> str:
    lines = [
        f"OS      : {platform.system()} {platform.release()}",
        f"Machine : {platform.machine()}",
        f"Python  : {sys.version.split()[0]}",
        f"Workdir : {WORKDIR}",
        f"Home    : {Path.home()}",
        f"DiskFree: {shutil.disk_usage(WORKDIR).free//(1024**2)} MB",
    ]
    try:
        import psutil; vm = psutil.virtual_memory()
        lines += [f"RAM     : {vm.available//(1024**2)}/{vm.total//(1024**2)} MB free",
                  f"CPUs    : {psutil.cpu_count(logical=True)}"]
    except ImportError:
        lines.append("RAM/CPU : pip install psutil for details")
    return "\n".join(lines)

def local_http_get(url: str, timeout: int = 15) -> str:
    try:
        import requests
        r = requests.get(url, headers={"User-Agent": "VelociPrompt/1.0"}, timeout=timeout)
        return truncate(f"Status: {r.status_code}\n\n{r.text}")
    except Exception as e: return f"Error: {e}"

def local_python_exec(code: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True,
                           timeout=timeout, cwd=str(WORKDIR))
        out = r.stdout or ""
        if r.stderr: out += ("\n--- stderr ---\n" + r.stderr) if out else r.stderr
        if r.returncode != 0: out += f"\n[exit code: {r.returncode}]"
        return truncate(out) if out else "[no output]"
    except subprocess.TimeoutExpired: return f"Error: timeout after {timeout}s"
    except Exception as e: return f"Error: {e}"

# ─── VELOCIRAPTOR CLIENT (shared gRPC channel) ────────────────────────────────

class VrClient:
    """Lazy-initialised gRPC stub shared across all VR tool calls in one run."""
    def __init__(self, config_path: str):
        self.config_path = config_path
        self._stub = None
        self._channel = None

    @property
    def stub(self):
        if self._stub is None:
            self._stub, self._channel = vql_query.get_stub_and_channel(self.config_path)
        return self._stub

    def close(self):
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
        self._channel = None
        self._stub = None

_vr = VrClient(VR_CONFIG)

# ─── Local artifact cache ─────────────────────────────────────────────────────

_catalog_cache: list | None = None

def _load_artifact_cache() -> list | None:
    """Return the enriched artifact catalog if fresh; otherwise None so the
    caller can fall back to a server-side query."""
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache
    if not CATALOG_FILE.is_file():
        return None
    try:
        age = time.time() - CATALOG_FILE.stat().st_mtime
        if age > CATALOG_MAX_AGE:
            return None
        data = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return None
        _catalog_cache = data
        return data
    except Exception:
        return None

def _tokenise(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t]

def _score_artifact(query: str, tokens: list[str], art: dict) -> int:
    """Rank an artifact against a user query.

    - name substring / per-token hit → 3 / 2 pts
    - keyword phrase hit / per-token hit → 3 / 2 pts (enriched column)
    - description token hit → 1 pt
    """
    name = (art.get("name") or "").lower()
    desc = (art.get("description") or "").lower()
    keywords = art.get("keywords") or []
    kw_joined = " ".join(k.lower() for k in keywords)

    score = 0
    q = query.lower().strip()
    if q and q in name:
        score += 3
    # Keyword phrase match — full query substring against any keyword phrase
    for kw in keywords:
        kw_low = kw.lower()
        if q and (q in kw_low or kw_low in q):
            score += 3

    for tok in tokens:
        if not tok or len(tok) < 2:
            continue
        if tok in name:
            score += 2
        if tok in kw_joined:
            score += 2
        if tok in desc:
            score += 1
    return score

def _format_artifact_matches(query: str, rows: list[dict], limit: int = 10) -> str:
    lines = [f"Artifacts matching '{query}':", ""]
    for r in rows[:limit]:
        name = r.get("name", "?")
        desc = str(r.get("description", ""))[:160].replace("\n", " ")
        lines.append(f"  {name}")
        if desc:
            lines.append(f"    {desc}")
    return "\n".join(lines)

# ─── VELOCIRAPTOR TOOLS ───────────────────────────────────────────────────────

def vr_search_artifacts(keyword: str) -> str:
    """Search Velociraptor's artifact catalog. Prefers the local enriched cache
    (which maps vague user phrasing to artifact names); falls back to the
    server-side regex query when the cache is missing or stale."""
    if not keyword or not keyword.strip():
        return "Error: keyword is required"

    catalog = _load_artifact_cache()
    if catalog:
        tokens = _tokenise(keyword)
        scored = [(a, _score_artifact(keyword, tokens, a)) for a in catalog]
        scored = [(a, s) for a, s in scored if s > 0]
        scored.sort(key=lambda x: -x[1])
        if not scored:
            return f"No artifacts found matching '{keyword}'"
        return _format_artifact_matches(keyword, [a for a, _ in scored], limit=10)

    # Fallback — server-side regex (shared gRPC channel)
    try:
        rows = vql_query.search_artifacts(VR_CONFIG, keyword, stub=_vr.stub)
    except Exception as e:
        return f"Error: {e}"
    if not rows:
        return f"No artifacts found matching '{keyword}'"
    return _format_artifact_matches(keyword, rows, limit=10)

def vr_run_vql(vql: str) -> str:
    try:
        rows = vql_query.run_vql(VR_CONFIG, vql, stub=_vr.stub)
    except Exception as e:
        return f"Error: {e}"
    if not rows:
        return "Query returned no rows."
    if isinstance(rows, list) and rows:
        cols  = list(rows[0].keys())[:6]
        lines = [" | ".join(cols), "-" * 60]
        for row in rows[:20]:
            lines.append(" | ".join(str(row.get(c, ""))[:40] for c in cols))
        if len(rows) > 20:
            lines.append(f"... and {len(rows)-20} more rows")
        return "\n".join(lines)
    return str(rows)

def vr_list_clients() -> str:
    try:
        rows = vql_query.run_vql(
            VR_CONFIG,
            "SELECT client_id, os_info.hostname AS hostname, last_ip FROM clients() LIMIT 100",
            stub=_vr.stub,
        )
    except Exception as e:
        return f"Error: {e}"
    if not rows:
        return "No clients found."
    return "\n".join(
        f"- {r.get('hostname','?')} ({r.get('client_id','?')}) — {r.get('last_ip','?')}"
        for r in rows
    )

def vr_collect_artifact(client_id: str, artifact_name: str, params: str = "{}") -> str:
    try:
        p = json.loads(params) if isinstance(params, str) else (params or {})
    except Exception:
        p = {}
    try:
        flow_id = vql_query.collect_artifact(
            VR_CONFIG, client_id, artifact_name, p, stub=_vr.stub
        )
    except Exception as e:
        return f"Error: {e}"
    emit({"type": "flow", "clientId": client_id, "flowId": flow_id, "artifactName": artifact_name})
    return f"Scheduled {artifact_name} on {client_id} → flow_id: {flow_id}"

def vr_get_flow_results(client_id: str, flow_id: str, save_to: str = "") -> str:
    for _ in range(24):
        try:
            status = vql_query.get_flow_status(VR_CONFIG, client_id, flow_id, stub=_vr.stub)
            state  = str(status.get("state", "")).upper()
            if state == "FINISHED":
                break
            if state == "ERROR":
                return f"Flow failed: {status.get('error','')}"
        except Exception as e:
            return f"Error checking status: {e}"
        time.sleep(5)

    try:
        rows = vql_query.get_flow_results(VR_CONFIG, client_id, flow_id, stub=_vr.stub)
    except Exception as e:
        return f"Error getting results: {e}"

    if not rows:
        return "No results collected."

    total = len(rows)
    cols  = list(rows[0].keys())

    if not save_to:
        save_to = f"results_{flow_id}.json"

    out_path = WORKDIR / save_to
    out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    return (
        f"Collected {total} rows from {flow_id}.\n"
        f"Columns: {', '.join(cols[:8])}\n"
        f"Results saved to: {out_path}\n"
        f"First row preview: {json.dumps(rows[0])[:200]}"
    )

# ─── SHARED TOOL ──────────────────────────────────────────────────────────────

MEMORY_FILE = WORKSPACE / "MEMORY.md"

def tool_remember(note: str) -> str:
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    txt = f"\n- [{ts}] {note}"
    with open(MEMORY_FILE, "a", encoding="utf-8") as f:
        f.write(txt)
    return "Saved to memory."

# ─── Tool registries ──────────────────────────────────────────────────────────

LOCAL_TOOLS: dict[str, Any] = {
    "bash":         local_bash,
    "read_file":    local_read_file,
    "write_file":   local_write_file,
    "edit_file":    local_edit_file,
    "delete_file":  local_delete_file,
    "move_file":    local_move_file,
    "copy_file":    local_copy_file,
    "make_dir":     local_make_dir,
    "list_dir":     local_list_dir,
    "find_files":   local_find_files,
    "grep":         local_grep,
    "env_info":     local_env_info,
    "http_get":     local_http_get,
    "python_exec":  local_python_exec,
    "remember":     tool_remember,
}

VR_TOOLS: dict[str, Any] = {
    "search_artifacts": vr_search_artifacts,
    "run_vql":          vr_run_vql,
    "list_clients":     vr_list_clients,
    "collect_artifact": vr_collect_artifact,
    "get_flow_results": vr_get_flow_results,
    "remember":         tool_remember,
}

# ─── Tool schemas (OpenAI function-calling format) ────────────────────────────

def _fn(name: str, description: str, properties: dict, required: list[str]):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }

LOCAL_TOOLS_SCHEMA = [
    _fn("bash",
        "Run a shell command. Do not run `find /` — use find_files with a subdirectory.",
        {"command": {"type": "string"},
         "timeout": {"type": "integer", "description": "seconds, default 30"}},
        ["command"]),
    _fn("read_file", "Read a file's contents.",
        {"file_path": {"type": "string"}}, ["file_path"]),
    _fn("write_file", "Write content to a file, creating parents.",
        {"file_path": {"type": "string"}, "content": {"type": "string"}},
        ["file_path", "content"]),
    _fn("edit_file",
        "Replace a unique old_string with new_string in a file. Read the file first.",
        {"file_path": {"type": "string"},
         "old_string": {"type": "string"},
         "new_string": {"type": "string"}},
        ["file_path", "old_string", "new_string"]),
    _fn("delete_file", "Delete a file or empty directory.",
        {"file_path": {"type": "string"}}, ["file_path"]),
    _fn("move_file", "Move or rename a file.",
        {"src": {"type": "string"}, "dst": {"type": "string"}},
        ["src", "dst"]),
    _fn("copy_file", "Copy a file.",
        {"src": {"type": "string"}, "dst": {"type": "string"}},
        ["src", "dst"]),
    _fn("make_dir", "Create a directory (including parents).",
        {"directory": {"type": "string"}}, ["directory"]),
    _fn("list_dir", "List directory contents.",
        {"directory": {"type": "string", "description": "default '.'"},
         "show_hidden": {"type": "boolean"}},
        []),
    _fn("find_files", "Find files by glob pattern under a directory.",
        {"pattern": {"type": "string"},
         "directory": {"type": "string", "description": "default '.'"},
         "recursive": {"type": "boolean"},
         "max_results": {"type": "integer"},
         "timeout": {"type": "integer"}},
        ["pattern"]),
    _fn("grep", "Regex-search within a single file.",
        {"pattern": {"type": "string"},
         "file_path": {"type": "string"},
         "ignore_case": {"type": "boolean"},
         "context_lines": {"type": "integer"}},
        ["pattern", "file_path"]),
    _fn("env_info", "Report OS, Python, CPU/RAM, working directory.", {}, []),
    _fn("http_get", "HTTP GET a URL and return status + body (truncated).",
        {"url": {"type": "string"}, "timeout": {"type": "integer"}},
        ["url"]),
    _fn("python_exec", "Run a short Python snippet and return stdout/stderr.",
        {"code": {"type": "string"}, "timeout": {"type": "integer"}},
        ["code"]),
    _fn("remember", "Append a finding to cross-session memory.",
        {"note": {"type": "string"}}, ["note"]),
]

VR_TOOLS_SCHEMA = [
    _fn("search_artifacts",
        "Search Velociraptor's artifact catalog by intent phrase or keyword. "
        "Accepts natural-language queries like 'what programs ran', 'chrome "
        "history', 'persistence', 'who logged in'. ALWAYS call this before "
        "collect_artifact — never invent artifact names.",
        {"keyword": {"type": "string", "description": "User-intent phrase or keyword"}},
        ["keyword"]),
    _fn("run_vql", "Run a VQL query directly against the Velociraptor server.",
        {"vql": {"type": "string"}}, ["vql"]),
    _fn("list_clients", "List connected Velociraptor endpoints.", {}, []),
    _fn("collect_artifact",
        "Schedule an artifact collection on an endpoint. Use the exact "
        "artifact_name returned by search_artifacts.",
        {"client_id": {"type": "string"},
         "artifact_name": {"type": "string",
                           "description": "e.g. Windows.System.Amcache"},
         "params": {"type": "string",
                    "description": "JSON object of artifact params, e.g. '{}'"}},
        ["client_id", "artifact_name"]),
    _fn("get_flow_results",
        "Wait for a flow (up to 2 min) and save rows to a JSON file. "
        "Only call this when you need to analyse rows yourself — collection "
        "results already stream to the UI.",
        {"client_id": {"type": "string"},
         "flow_id":   {"type": "string"},
         "save_to":   {"type": "string", "description": "Optional filename"}},
        ["client_id", "flow_id"]),
    _fn("remember", "Append a finding to cross-session memory.",
        {"note": {"type": "string"}}, ["note"]),
]

# ─── System prompts ───────────────────────────────────────────────────────────

LOCAL_SYSTEM_PROMPT = f"""You are VelociPrompt in LOCAL mode on {OS_NAME}.
You have shell, file, HTTP, and Python tools on the host machine.

Guidelines:
- Always read_file before edit_file.
- Do NOT run `find /` (too slow) — use find_files with a subdirectory.
- After a tool returns useful output, reply with a short natural-language answer
  summarising what you found. Do not keep calling tools once the question is answered.
"""

def build_vr_system_prompt(bootstrap: dict, memory_context: str, client_ids: list) -> str:
    soul     = bootstrap.get("SOUL.md", "")
    identity = bootstrap.get("IDENTITY.md", "")
    skill    = bootstrap.get("SKILL.md", "")
    parts    = []
    if soul:     parts.append(soul)
    if identity: parts.append(identity)

    parts.append(f"""You are VelociPrompt in VELOCIRAPTOR mode.
Target endpoints: {', '.join(client_ids)}

Workflow:
1. search_artifacts(keyword) — find the correct artifact name. Pass the user's
   intent in plain words (e.g. "what programs ran", "persistence", "chrome
   history"); the search understands vague phrasing.
2. collect_artifact(client_id, artifact_name) — schedule the collection.
   Collection rows stream to the UI automatically.
3. get_flow_results(client_id, flow_id) — only if you need to analyse rows
   yourself.
4. Reply with a short natural-language summary when you have enough to answer.

Rules:
- Always call search_artifacts before collect_artifact — never guess names.
- You may emit multiple tool calls in one turn when they are independent (for
  example, collecting on several clients in parallel).
""")

    if skill:          parts.append(f"## Skills\n{skill}")
    if memory_context: parts.append(f"## Relevant Memory\n{memory_context}")
    return "\n\n".join(parts)

# ─── Bootstrap + memory ───────────────────────────────────────────────────────

BOOTSTRAP_FILES = ["SOUL.md", "IDENTITY.md", "SKILL.md", "MEMORY.md"]

def load_bootstrap() -> dict:
    result = {}
    total  = 0
    for name in BOOTSTRAP_FILES:
        path = WORKSPACE / name
        if not path.is_file(): continue
        content = path.read_text(encoding="utf-8", errors="replace")
        if len(content) > MAX_FILE_CHARS:
            content = content[:MAX_FILE_CHARS] + "\n[truncated]"
        if total + len(content) > MAX_TOTAL_CHARS: break
        result[name] = content
        total += len(content)
    return result

def memory_recall(query: str) -> str:
    if not MEMORY_FILE.is_file(): return ""
    content = MEMORY_FILE.read_text(encoding="utf-8", errors="replace")
    q_words = set(query.lower().split())
    hits    = [line for line in content.splitlines()
               if any(w in line.lower() for w in q_words)]
    return "\n".join(hits[:10]) if hits else ""

# ─── Session ──────────────────────────────────────────────────────────────────

def session_file(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.jsonl"

def load_session(session_id: str) -> list:
    """Load recent conversation as OpenAI-shape messages (user + assistant text
    only). Legacy JSON-envelope assistant turns get their `answer` extracted;
    other legacy tool/display wrappers and `[tool_result …]` lines are dropped.

    Tool-role messages within a run are held in memory during that run but not
    replayed from disk — tool_call_id chaining across process boundaries isn't
    worth the complexity here."""
    sf = session_file(session_id)
    if not sf.is_file(): return []
    messages: list = []
    for line in sf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        role    = obj.get("role")
        content = obj.get("content", "")
        if role == "user":
            if isinstance(content, str) and content.startswith("[tool_result"):
                continue  # legacy bridge turn — drop
            messages.append({"role": "user", "content": content})
        elif role == "assistant":
            stripped = (content or "").strip()
            # Legacy JSON envelope: {"action":"final","answer":"..."}
            if stripped.startswith("{"):
                try:
                    parsed = json.loads(stripped)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    if parsed.get("action") == "final" and parsed.get("answer"):
                        messages.append({"role": "assistant",
                                         "content": str(parsed["answer"])})
                        continue
                    # Legacy tool/display turns are not replayable — drop
                    if "action" in parsed or "tool_calls" in parsed:
                        continue
            if stripped:
                messages.append({"role": "assistant", "content": content})
        # role == "tool" — drop (see docstring)
    return messages[-40:] if len(messages) > 40 else messages

def save_turn(session_id: str, role: str, content: str):
    sf = session_file(session_id)
    ts = datetime.now(timezone.utc).isoformat()
    with open(sf, "a", encoding="utf-8") as f:
        f.write(json.dumps({"role": role, "content": content, "ts": ts}) + "\n")

# ─── Agent loop ───────────────────────────────────────────────────────────────

def run_agent(prompt: str, client_ids: list, session_id: str):
    is_local  = len(client_ids) == 0
    handlers  = LOCAL_TOOLS if is_local else VR_TOOLS
    schema    = LOCAL_TOOLS_SCHEMA if is_local else VR_TOOLS_SCHEMA
    bootstrap = load_bootstrap()
    mem_ctx   = memory_recall(prompt)
    messages  = load_session(session_id)

    system_prompt = (
        LOCAL_SYSTEM_PROMPT + (f"\n\n## Relevant Memory\n{mem_ctx}" if mem_ctx else "")
        if is_local else
        build_vr_system_prompt(bootstrap, mem_ctx, client_ids)
    )

    messages.append({"role": "user", "content": prompt})
    save_turn(session_id, "user", prompt)

    tool_calls_made  = 0
    last_tool_result = ""
    last_tool_name   = ""

    try:
        while True:
            if tool_calls_made >= MAX_TOOL_CALLS:
                emit_done(
                    f"Reached tool call limit. Last result from {last_tool_name}:\n"
                    f"{last_tool_result[:1000]}"
                )
                break

            all_messages = [{"role": "system", "content": system_prompt}] + messages
            if sum(len(json.dumps(m, default=str)) for m in all_messages) > CONTEXT_LIMIT:
                # Keep only the last 20 turns; cheap trim
                messages     = messages[-20:]
                all_messages = [{"role": "system", "content": system_prompt}] + messages

            try:
                response = client.chat.completions.create(
                    model=NIM_MODEL,
                    messages=all_messages,
                    tools=schema,
                    tool_choice="auto",
                    max_tokens=1024,
                    temperature=0.1,
                )
                message = response.choices[0].message
            except Exception as e:
                emit_error(f"NIM API error: {e}")
                break

            tool_calls = getattr(message, "tool_calls", None) or []
            content    = message.content or ""

            # No tool calls → content is the final answer.
            if not tool_calls:
                answer = content.strip() or (
                    last_tool_result[:3000] if last_tool_result else "(no answer)"
                )
                save_turn(session_id, "assistant", answer)
                emit_done(answer)
                if len(answer) > 80:
                    tool_remember(f"Q: {prompt[:60]} → A: {answer[:100]}")
                break

            # Tool calls present — record assistant message (with tool_calls) and
            # execute each tool.
            tool_calls_payload = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name,
                              "arguments": tc.function.arguments}}
                for tc in tool_calls
            ]
            messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls_payload,
            })
            save_turn(session_id, "assistant",
                      json.dumps({"content": content, "tool_calls": tool_calls_payload}))

            for tc in tool_calls:
                if tool_calls_made >= MAX_TOOL_CALLS:
                    result = "Error: reached tool call limit"
                else:
                    name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except Exception:
                        args = {}
                    emit({"type": "tool_call", "name": name, "args": args})
                    handler = handlers.get(name)
                    if handler is None:
                        result = f"Unknown tool: {name}"
                    else:
                        try:
                            result = handler(**args)
                        except TypeError as e:
                            result = f"Error: bad args for {name}: {e}"
                        except Exception as e:
                            result = f"Error: {e}"
                    last_tool_result = str(result)
                    last_tool_name   = name
                    emit({"type": "tool_result", "name": name,
                          "result": str(result)[:500]})
                    tool_calls_made += 1

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result)[:MAX_TOOL_OUTPUT],
                })
                save_turn(session_id, "tool", json.dumps({
                    "tool_call_id": tc.id,
                    "name": tc.function.name,
                    "result": str(result)[:MAX_TOOL_OUTPUT],
                }))
    finally:
        _vr.close()

# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    raw = sys.stdin.read().strip()
    try:
        inp = json.loads(raw)
    except Exception:
        emit_error("Invalid JSON input")
        sys.exit(1)

    prompt     = inp.get("prompt", "")
    client_ids = inp.get("clientIds", [])
    session_id = inp.get("sessionId", "default")

    if not prompt:
        emit_error("No prompt provided")
        sys.exit(1)
    if not NIM_API_KEY:
        emit_error("NIM_API_KEY not set — add it to .env")
        sys.exit(1)

    # Redirect all file writes for this session into outputs/<sessionId>/.
    global WORKDIR
    safe_sid = re.sub(r"[^a-zA-Z0-9._-]", "_", session_id) or "default"
    WORKDIR  = OUTPUTS_ROOT / safe_sid
    WORKDIR.mkdir(parents=True, exist_ok=True)

    run_agent(prompt, client_ids, session_id)

if __name__ == "__main__":
    main()
