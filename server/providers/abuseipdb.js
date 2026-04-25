// AbuseIPDB v2 API adapter (IP reputation only).
// Free tier: 1000 checks/day. No sub-second rate limit in practice.

const BASE = "https://api.abuseipdb.com/api/v2";

export async function lookupIp(apiKey, ip) {
  const url = `${BASE}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=`;
  const r   = await fetch(url, {
    headers: { "Key": apiKey, "Accept": "application/json" },
  });
  if (r.status === 429) throw new Error("aipdb_rate_limited");
  if (!r.ok)            throw new Error(`aipdb http ${r.status}`);
  const json = await r.json();
  const d    = json?.data || {};
  const conf = Number(d.abuseConfidenceScore || 0);
  let verdict = "clean";
  if (conf >= 75)      verdict = "malicious";
  else if (conf >= 25) verdict = "suspicious";
  if (d.totalReports === 0 && conf === 0) verdict = "unknown";
  return {
    provider: "aipdb",
    verdict,
    score: conf / 100,
    detail: {
      confidence:   conf,
      totalReports: d.totalReports ?? 0,
      countryCode:  d.countryCode || "",
      isp:          d.isp || "",
      usageType:    d.usageType || "",
      domain:       d.domain || "",
      lastReported: d.lastReportedAt || null,
    },
  };
}

export function lookupByType(apiKey, iocType, value) {
  if (iocType === "ip") return lookupIp(apiKey, value);
  return Promise.resolve(null);
}
