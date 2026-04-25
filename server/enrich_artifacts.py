#!/usr/bin/env python3
"""
enrich_artifacts.py — Build the local artifact catalog with user-intent keywords.

Usage:
  enrich_artifacts.py <output_path>

Stdin: a JSON array of {"name": str, "description": str} — the raw catalog
from `SELECT name, description FROM artifact_definitions()`.

Output: writes a JSON array of {"name", "description", "content_hash",
"keywords"} to <output_path>. Reuses keywords for unchanged entries (matched
by content_hash) so a refresh only re-enriches what actually changed.

Keywords are produced by batched NIM calls (10 per request). They are
user-phrase synonyms ("what programs ran", "who logged in") — not domain
jargon — so the agent can match vague investigator queries.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR.parent / ".env", override=True)
load_dotenv(SCRIPT_DIR / ".env",        override=True)

NIM_API_KEY  = os.getenv("NIM_API_KEY", os.getenv("NVIDIA_API_KEY", ""))
NIM_MODEL    = os.getenv("NIM_MODEL",   "meta/llama-3.3-70b-instruct")
NIM_BASE_URL = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")

BATCH_SIZE = 10
MAX_BATCHES_PER_RUN = 200   # soft cap so a huge first build doesn't burn all credit in one go
SYSTEM_PROMPT = (
    "You help build a search index for Velociraptor DFIR artifacts. "
    "For each artifact, produce 5-10 short keyword phrases an investigator "
    "might say when they want that data. Use plain English, not domain "
    "jargon. Example: for Windows.System.Amcache -> "
    '["what programs ran", "recently run", "execution history", '
    '"binary execution evidence", "app launches", "program history"]. '
    "Respond with ONLY a JSON array of {\"name\": str, \"keywords\": [str]}."
)


def content_hash(name: str, description: str) -> str:
    h = hashlib.sha256()
    h.update((name or "").encode("utf-8"))
    h.update(b"\x00")
    h.update((description or "").encode("utf-8"))
    return h.hexdigest()[:16]


def load_existing(path: Path) -> dict:
    """Return name -> {content_hash, keywords} from a previous catalog."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    if isinstance(data, list):
        for e in data:
            if isinstance(e, dict) and e.get("name"):
                out[e["name"]] = {
                    "content_hash": e.get("content_hash", ""),
                    "keywords":     e.get("keywords", []) or [],
                }
    return out


def parse_json_array(text: str) -> list:
    """Strip code fences and parse a JSON array; return [] if it fails."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        # drop possible leading 'json'
        if t.lower().startswith("json"):
            t = t[4:].strip()
    # Find the first '[' to the last ']'
    lo, hi = t.find("["), t.rfind("]")
    if lo >= 0 and hi > lo:
        t = t[lo:hi + 1]
    try:
        parsed = json.loads(t)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def enrich_batch(client: OpenAI, batch: list[dict]) -> dict[str, list[str]]:
    """Return name -> keywords[] for the given batch. Empty dict on failure."""
    lines = []
    for i, a in enumerate(batch, 1):
        desc = (a.get("description") or "").replace("\n", " ").strip()
        lines.append(f"{i}. {a['name']} — {desc[:400]}")
    user = "Artifacts:\n" + "\n".join(lines)

    try:
        resp = client.chat.completions.create(
            model=NIM_MODEL,
            max_tokens=1024,
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user},
            ],
        )
        raw = resp.choices[0].message.content or ""
    except Exception as e:
        print(f"[enrich] batch failed: {e}", file=sys.stderr)
        return {}

    rows = parse_json_array(raw)
    out: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        kws  = row.get("keywords") or []
        if isinstance(name, str) and isinstance(kws, list):
            clean = [str(k).strip() for k in kws if str(k).strip()]
            if clean:
                out[name] = clean[:10]
    return out


def main():
    if len(sys.argv) < 2:
        print("Usage: enrich_artifacts.py <output_path>", file=sys.stderr)
        sys.exit(1)

    output_path = Path(sys.argv[1]).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        raw_catalog = json.load(sys.stdin)
    except Exception as e:
        print(f"[enrich] invalid stdin JSON: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(raw_catalog, list):
        print("[enrich] expected JSON array on stdin", file=sys.stderr)
        sys.exit(1)

    existing = load_existing(output_path)

    # Build the merged catalog entries and collect ones needing enrichment.
    merged: list[dict] = []
    todo:   list[dict] = []
    for entry in raw_catalog:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not name:
            continue
        desc = entry.get("description") or ""
        h    = content_hash(name, desc)

        prev = existing.get(name)
        if prev and prev.get("content_hash") == h and prev.get("keywords"):
            keywords = prev["keywords"]
        else:
            keywords = []
            todo.append({"name": name, "description": desc})

        merged.append({
            "name":         name,
            "description":  desc,
            "content_hash": h,
            "keywords":     keywords,
        })

    if not NIM_API_KEY:
        print("[enrich] NIM_API_KEY missing — writing catalog without enrichment",
              file=sys.stderr)
        output_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        return

    if not todo:
        print(f"[enrich] no new/changed entries ({len(merged)} total)", file=sys.stderr)
        output_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        return

    client = OpenAI(base_url=NIM_BASE_URL, api_key=NIM_API_KEY)

    # Build a name -> entry map for merged so we can patch keywords in.
    merged_by_name = {e["name"]: e for e in merged}

    batches = [todo[i:i + BATCH_SIZE] for i in range(0, len(todo), BATCH_SIZE)]
    if len(batches) > MAX_BATCHES_PER_RUN:
        print(f"[enrich] capping at {MAX_BATCHES_PER_RUN} batches "
              f"(had {len(batches)}); remaining artifacts run next refresh",
              file=sys.stderr)
        batches = batches[:MAX_BATCHES_PER_RUN]

    total_enriched = 0
    for i, batch in enumerate(batches, 1):
        mapping = enrich_batch(client, batch)
        for name, kws in mapping.items():
            if name in merged_by_name:
                merged_by_name[name]["keywords"] = kws
                total_enriched += 1

        # Checkpoint after every batch so a crash doesn't lose progress.
        output_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        print(f"[enrich] batch {i}/{len(batches)} done "
              f"({total_enriched} enriched so far)", file=sys.stderr)

    print(f"[enrich] complete: {total_enriched}/{len(todo)} enriched, "
          f"{len(merged)} total in catalog", file=sys.stderr)


if __name__ == "__main__":
    main()
