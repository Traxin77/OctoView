// VirusTotal v3 API adapter.
// Free tier: 4 requests/minute, 500/day. Rate limiting is the caller's job.
// Returns a normalised shape: { provider, verdict, score, engines, detail }
//   score:   malicious_count / total_analysed  (0–1)
//   verdict: "malicious" | "suspicious" | "clean" | "unknown"

const BASE = "https://www.virustotal.com/api/v3";

function verdictFromStats(stats) {
  if (!stats) return { verdict: "unknown", score: 0, total: 0, malicious: 0, suspicious: 0 };
  const malicious  = Number(stats.malicious  || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless   = Number(stats.harmless   || 0);
  const undetected = Number(stats.undetected || 0);
  const total      = malicious + suspicious + harmless + undetected;
  if (total === 0) return { verdict: "unknown", score: 0, total: 0, malicious: 0, suspicious: 0 };
  let verdict = "clean";
  if (malicious >= 3)                        verdict = "malicious";
  else if (malicious >= 1 || suspicious > 0) verdict = "suspicious";
  return { verdict, score: malicious / total, total, malicious, suspicious };
}

async function vtGet(apiKey, endpoint) {
  const r = await fetch(`${BASE}${endpoint}`, { headers: { "x-apikey": apiKey } });
  if (r.status === 404) return null;                           // not yet analysed
  if (r.status === 400) return null;                           // malformed IoC for this type — not scorable
  if (r.status === 429) throw new Error("vt_rate_limited");
  if (!r.ok)            throw new Error(`vt http ${r.status}`);
  return r.json();
}

function engineList(attrs) {
  const results = attrs?.last_analysis_results || {};
  return Object.entries(results)
    .filter(([, v]) => v?.category === "malicious" || v?.category === "suspicious")
    .map(([name, v]) => ({ engine: name, category: v.category, result: v.result || "" }));
}

function buildResult(attrs) {
  const v = verdictFromStats(attrs?.last_analysis_stats);
  return {
    provider: "vt",
    verdict:  v.verdict,
    score:    v.score,
    detail: {
      total:       v.total,
      malicious:   v.malicious,
      suspicious:  v.suspicious,
      engines:     engineList(attrs),
      reputation:  attrs?.reputation ?? null,
      lastAnalysis: attrs?.last_analysis_date || null,
    },
  };
}

export async function lookupHash(apiKey, hash) {
  const data = await vtGet(apiKey, `/files/${encodeURIComponent(hash)}`);
  if (!data) return { provider: "vt", verdict: "unknown", score: 0, detail: { reason: "not_found" } };
  return buildResult(data.data?.attributes);
}

export async function lookupIp(apiKey, ip) {
  const data = await vtGet(apiKey, `/ip_addresses/${encodeURIComponent(ip)}`);
  if (!data) return { provider: "vt", verdict: "unknown", score: 0, detail: { reason: "not_found" } };
  return buildResult(data.data?.attributes);
}

export async function lookupDomain(apiKey, domain) {
  const data = await vtGet(apiKey, `/domains/${encodeURIComponent(domain)}`);
  if (!data) return { provider: "vt", verdict: "unknown", score: 0, detail: { reason: "not_found" } };
  return buildResult(data.data?.attributes);
}

export async function lookupUrl(apiKey, url) {
  // VT identifies URLs by base64-url of the URL itself.
  const id = Buffer.from(url).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const data = await vtGet(apiKey, `/urls/${id}`);
  if (!data) return { provider: "vt", verdict: "unknown", score: 0, detail: { reason: "not_submitted" } };
  return buildResult(data.data?.attributes);
}

export function lookupByType(apiKey, iocType, value) {
  switch (iocType) {
    case "hash":   return lookupHash(apiKey, value);
    case "ip":     return lookupIp(apiKey, value);
    case "domain": return lookupDomain(apiKey, value);
    case "url":    return lookupUrl(apiKey, value);
    default:       return Promise.resolve(null);
  }
}
