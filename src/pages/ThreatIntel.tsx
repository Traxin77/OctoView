import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import {
  ShieldAlert, AlertCircle, CheckCircle2, HelpCircle, ChevronRight, ChevronDown,
  ArrowLeft, Lightbulb, Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  IocType, ThreatVerdict, ThreatIntelResult, ThreatIntelRecommendation,
} from "@/types/client";

interface Summary {
  total: number; malicious: number; suspicious: number; clean: number; unknown: number;
}

const VERDICT_STYLES: Record<ThreatVerdict, { text: string; bg: string; label: string }> = {
  malicious:  { text: "text-destructive",        bg: "bg-destructive/10",        label: "Malicious"  },
  suspicious: { text: "text-warning",            bg: "bg-warning/10",            label: "Suspicious" },
  clean:      { text: "text-success",            bg: "bg-success/10",            label: "Clean"      },
  unknown:    { text: "text-muted-foreground",   bg: "bg-muted/30",              label: "Unknown"    },
};

const VERDICT_RANK: Record<ThreatVerdict, number> = {
  malicious: 3, suspicious: 2, unknown: 1, clean: 0,
};

function VerdictBadge({ verdict }: { verdict: ThreatVerdict }) {
  const s = VERDICT_STYLES[verdict];
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded", s.bg, s.text)}>
      {verdict === "malicious" && <AlertCircle className="h-3 w-3" />}
      {verdict === "suspicious" && <AlertCircle className="h-3 w-3" />}
      {verdict === "clean" && <CheckCircle2 className="h-3 w-3" />}
      {verdict === "unknown" && <HelpCircle className="h-3 w-3" />}
      {s.label}
    </span>
  );
}

function SummaryCard({
  label, value, accent,
}: { label: string; value: number | string; accent: "total" | ThreatVerdict }) {
  const accentClass =
    accent === "total"      ? "text-foreground"
    : accent === "malicious"  ? "text-destructive"
    : accent === "suspicious" ? "text-warning"
    : accent === "clean"      ? "text-success"
    :                           "text-muted-foreground";
  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className={cn("text-2xl font-semibold tabular-nums", accentClass)}>{value}</div>
    </div>
  );
}

type SortKey = "verdict" | "type" | "value" | "score";

export default function ThreatIntel() {
  const { sessionId = "" } = useParams();
  const [search] = useSearchParams();
  const scanId   = search.get("scanId") || "";

  const [status,          setStatus]          = useState<"idle" | "running" | "complete" | "error">("idle");
  const [summary,         setSummary]         = useState<Summary>({ total: 0, malicious: 0, suspicious: 0, clean: 0, unknown: 0 });
  const [results,         setResults]         = useState<ThreatIntelResult[]>([]);
  const [recommendations, setRecommendations] = useState<ThreatIntelRecommendation[]>([]);
  const [warnings,        setWarnings]        = useState<string[]>([]);
  const [expectedCount,   setExpectedCount]   = useState<number>(0);
  const [rawCount,        setRawCount]        = useState<number>(0);
  const [capped,          setCapped]          = useState<boolean>(false);
  const [errorMsg,        setErrorMsg]        = useState("");
  const [expanded,        setExpanded]        = useState<Set<string>>(new Set());
  const [filter,          setFilter]          = useState<"all" | ThreatVerdict | IocType>("all");
  const [sortKey,         setSortKey]         = useState<SortKey>("verdict");
  const [sortDir,         setSortDir]         = useState<"asc" | "desc">("desc");
  const [startedAt,       setStartedAt]       = useState<number>(0);

  // Track results by IoC key so we merge events cleanly.
  const resultsRef = useRef<Map<string, ThreatIntelResult>>(new Map());
  const statusRef  = useRef<typeof status>("idle");
  statusRef.current = status;

  useEffect(() => {
    if (!scanId) { setStatus("error"); setErrorMsg("Missing scanId"); return; }
    setStatus("running");
    setStartedAt(Date.now());
    const es = new EventSource(`/api/threat-intel/${encodeURIComponent(scanId)}/stream`);

    es.onmessage = (ev) => {
      let event: Record<string, unknown>;
      try { event = JSON.parse(ev.data); } catch { return; }

      switch (event.type) {
        case "started":
          setExpectedCount(Number(event.iocCount ?? 0));
          setRawCount(Number(event.rawCount ?? event.iocCount ?? 0));
          setCapped(Boolean(event.capped));
          break;
        case "ioc_found":
          // Pre-populate a pending row so the table grows as IoCs come in,
          // even before scoring is back.
          {
            const key = `${event.iocType}:${String(event.ioc).toLowerCase()}`;
            if (!resultsRef.current.has(key)) {
              resultsRef.current.set(key, {
                ioc: String(event.ioc), iocType: event.iocType as IocType,
                verdict: "unknown", score: 0, sources: [],
                foundIn: (event.foundIn as { messageId: string; column?: string | null }[]) || [],
              });
              setResults([...resultsRef.current.values()]);
            }
          }
          break;
        case "result":
          {
            const r = event.result as ThreatIntelResult;
            resultsRef.current.set(`${r.iocType}:${r.ioc.toLowerCase()}`, r);
            setResults([...resultsRef.current.values()]);
          }
          break;
        case "recommendation":
          setRecommendations(prev => {
            const next = [...prev];
            const name = String(event.artifactName);
            if (!next.some(r => r.artifactName === name)) {
              next.push({ artifactName: name, reason: String(event.reason) });
            }
            return next;
          });
          break;
        case "warning":
          setWarnings(prev => [...prev, String(event.message)]);
          break;
        case "done":
          setSummary(event.summary as Summary);
          setStatus("complete");
          es.close();
          break;
        case "error":
          setErrorMsg(String(event.message));
          setStatus("error");
          es.close();
          break;
      }
    };

    es.onerror = () => {
      // Streams may close normally when the scan was already done on replay.
      if (statusRef.current === "running") {
        setStatus("error");
        setErrorMsg("Stream closed unexpectedly");
      }
      es.close();
    };

    return () => es.close();
  }, [scanId]);

  // Live summary while running.
  const liveSummary: Summary = useMemo(() => {
    const s = { total: results.length, malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
    for (const r of results) s[r.verdict]++;
    return status === "complete" ? summary : s;
  }, [results, status, summary]);

  const filtered = useMemo(() => {
    let list = results;
    if (filter !== "all") {
      if (filter === "malicious" || filter === "suspicious" || filter === "clean" || filter === "unknown")
        list = list.filter(r => r.verdict === filter);
      else
        list = list.filter(r => r.iocType === filter);
    }
    const dir = sortDir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      switch (sortKey) {
        case "verdict": return (VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict]) * dir;
        case "type":    return a.iocType.localeCompare(b.iocType) * dir;
        case "value":   return a.ioc.localeCompare(b.ioc) * dir;
        case "score":   return (a.score - b.score) * dir;
        default:        return 0;
      }
    });
  }, [results, filter, sortKey, sortDir]);

  const toggleRow = (k: string) =>
    setExpanded(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n; });

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  // Rough ETA: VT free tier = 4 calls per 60s. Cached/allowlisted results come
  // back instantly, so we base ETA on measured per-result time vs wall clock.
  const eta = useMemo(() => {
    if (status !== "running" || expectedCount <= 0 || results.length === 0) return "";
    const remaining = expectedCount - results.length;
    if (remaining <= 0) return "";
    const elapsed = (Date.now() - startedAt) / 1000;
    const perItem = elapsed / Math.max(1, results.length);
    const seconds = Math.ceil(remaining * perItem);
    if (seconds < 60) return `~${seconds}s left`;
    return `~${Math.ceil(seconds / 60)} min left`;
  }, [status, expectedCount, results.length, startedAt]);

  const percent = expectedCount > 0 ? Math.min(100, (results.length / expectedCount) * 100) : 0;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="h-14 border-b flex items-center px-4 gap-4 bg-background">
        <Link
          to="/"
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          title="Back to chat"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back
        </Link>
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-primary" />
          <h1 className="text-sm font-semibold">Threat Intel</h1>
          <span className="text-xs text-muted-foreground font-mono">{sessionId}</span>
        </div>
        <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
          {status === "running" && (
            <>
              <Loader2 className="h-3 w-3 animate-spin text-primary" />
              <span className="tabular-nums">
                {results.length} / {expectedCount || "?"} scanned
              </span>
              {eta && <span className="tabular-nums">{eta}</span>}
            </>
          )}
          {status === "complete" && <span>Scan complete</span>}
          {status === "error"    && <span className="text-destructive">{errorMsg || "Scan failed"}</span>}
        </div>
      </header>

      {status === "running" && expectedCount > 0 && (
        <div className="h-1 bg-muted/30 relative" aria-label="Scan progress">
          <div
            className="h-full bg-primary transition-all duration-300"
            style={{ width: `${percent}%` }}
          />
        </div>
      )}

      {capped && (
        <div className="px-4 py-2 text-xs text-warning bg-warning/5 border-b border-warning/20">
          Scanning {expectedCount} of {rawCount} IoCs (capped). Raise <span className="font-mono">TI_MAX_IOCS</span> in <span className="font-mono">server/.env</span> to scan more.
        </div>
      )}

      <main className="p-6 flex gap-6 max-w-[1400px] mx-auto">
        <div className="flex-1 min-w-0">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
            <SummaryCard label="Total IoCs"  value={liveSummary.total}      accent="total" />
            <SummaryCard label="Malicious"   value={liveSummary.malicious}  accent="malicious" />
            <SummaryCard label="Suspicious"  value={liveSummary.suspicious} accent="suspicious" />
            <SummaryCard label="Clean"       value={liveSummary.clean}      accent="clean" />
            <SummaryCard label="Unknown"     value={liveSummary.unknown}    accent="unknown" />
          </div>

          {warnings.length > 0 && (
            <div className="mb-4 rounded border border-warning/30 bg-warning/5 p-3 text-xs text-warning-foreground">
              {warnings.map((w, i) => (
                <div key={i} className="text-warning">{w}</div>
              ))}
            </div>
          )}

          <div className="flex items-center gap-2 mb-3 text-xs">
            <span className="text-muted-foreground">Filter:</span>
            {(["all", "malicious", "suspicious", "clean", "unknown", "hash", "ip", "domain", "url"] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={cn(
                  "px-2 py-0.5 rounded",
                  filter === f ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-secondary",
                )}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="rounded-lg border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/50 text-left text-xs text-muted-foreground">
                  <th className="w-6"></th>
                  <SortHeader k="verdict" current={sortKey} dir={sortDir} onClick={toggleSort}>Verdict</SortHeader>
                  <SortHeader k="type"    current={sortKey} dir={sortDir} onClick={toggleSort}>Type</SortHeader>
                  <SortHeader k="value"   current={sortKey} dir={sortDir} onClick={toggleSort}>Value</SortHeader>
                  <SortHeader k="score"   current={sortKey} dir={sortDir} onClick={toggleSort}>Score</SortHeader>
                  <th className="px-3 py-2">Sources</th>
                  <th className="px-3 py-2">Found in</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-12 text-center text-xs text-muted-foreground">
                      {status === "running"
                        ? "Extracting and scoring IoCs…"
                        : "No IoCs found in this chat. See recommendations →"}
                    </td>
                  </tr>
                )}
                {filtered.map(r => {
                  const key = `${r.iocType}:${r.ioc.toLowerCase()}`;
                  const isOpen = expanded.has(key);
                  return (
                    <Fragment key={key}>
                      <tr
                        onClick={() => toggleRow(key)}
                        className="border-t border-border/30 cursor-pointer hover:bg-muted/30"
                      >
                        <td className="px-1 py-2">
                          {isOpen ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                        </td>
                        <td className="px-3 py-2"><VerdictBadge verdict={r.verdict} /></td>
                        <td className="px-3 py-2 text-xs font-mono uppercase text-muted-foreground">{r.iocType}</td>
                        <td className="px-3 py-2 font-mono text-xs truncate max-w-[320px]" title={r.ioc}>{r.ioc}</td>
                        <td className="px-3 py-2 text-xs tabular-nums">{r.sources.length ? r.score.toFixed(2) : "—"}</td>
                        <td className="px-3 py-2 text-xs">
                          {r.sources.length
                            ? r.sources.map(s => s.provider).join(", ")
                            : <span className="text-muted-foreground">—</span>}
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">
                          {r.foundIn.length} msg{r.foundIn.length !== 1 ? "s" : ""}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="border-t border-border/30 bg-muted/10">
                          <td colSpan={7} className="px-6 py-3 text-xs space-y-2">
                            {r.sources.length === 0 && (
                              <div className="text-muted-foreground italic">
                                Not scored — either no provider supports this IoC type, or provider is disabled / rate-limited.
                              </div>
                            )}
                            {r.sources.map((s, i) => (
                              <SourceDetail key={i} source={s} />
                            ))}
                            <div className="mt-2 pt-2 border-t border-border/30 text-muted-foreground">
                              <div className="font-medium text-foreground mb-1">Found in:</div>
                              <ul className="space-y-0.5">
                                {r.foundIn.map((f, i) => (
                                  <li key={i} className="font-mono">
                                    <span className="text-muted-foreground">{f.messageId}</span>
                                    {f.column && <span className="text-muted-foreground"> · col <span className="text-foreground">{f.column}</span></span>}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {recommendations.length > 0 && (
          <aside className="w-80 shrink-0">
            <div className="rounded-lg border bg-card p-4 sticky top-20">
              <div className="flex items-center gap-2 mb-2">
                <Lightbulb className="h-4 w-4 text-warning" />
                <h2 className="text-sm font-semibold">Recommended collections</h2>
              </div>
              <p className="text-xs text-muted-foreground mb-3">
                Your chat has thin coverage for some IoC types. Running these artifacts from the main chat would expand what threat intel can score.
              </p>
              <ul className="space-y-3">
                {recommendations.map(rec => (
                  <li key={rec.artifactName} className="text-xs">
                    <div className="font-mono text-primary break-all">{rec.artifactName}</div>
                    <div className="text-muted-foreground mt-0.5">{rec.reason}</div>
                  </li>
                ))}
              </ul>
            </div>
          </aside>
        )}
      </main>
    </div>
  );
}

function SortHeader({
  k, current, dir, onClick, children,
}: {
  k: SortKey; current: SortKey; dir: "asc" | "desc";
  onClick: (k: SortKey) => void; children: React.ReactNode;
}) {
  const active = current === k;
  return (
    <th className="px-3 py-2">
      <button
        onClick={() => onClick(k)}
        className={cn(
          "inline-flex items-center gap-1 hover:text-foreground",
          active ? "text-foreground" : "",
        )}
      >
        {children}
        {active && <span className="text-[10px]">{dir === "asc" ? "▲" : "▼"}</span>}
      </button>
    </th>
  );
}

function SourceDetail({ source }: { source: { provider: string; verdict: ThreatVerdict; score: number; detail: Record<string, unknown> } }) {
  const d = source.detail || {};
  if (source.provider === "vt") {
    const engines = Array.isArray(d.engines) ? d.engines as { engine: string; result: string }[] : [];
    return (
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="font-medium text-foreground">VirusTotal</span>
          <VerdictBadge verdict={source.verdict} />
          <span className="text-muted-foreground">
            {String(d.malicious ?? 0)}/{String(d.total ?? 0)} malicious
            {d.suspicious ? `, ${String(d.suspicious)} suspicious` : ""}
          </span>
        </div>
        {engines.length > 0 && (
          <div className="pl-3 space-y-0.5">
            {engines.slice(0, 12).map((e, i) => (
              <div key={i} className="font-mono text-muted-foreground">
                <span className="text-foreground">{e.engine}</span> — {e.result}
              </div>
            ))}
            {engines.length > 12 && <div className="text-muted-foreground">…and {engines.length - 12} more</div>}
          </div>
        )}
      </div>
    );
  }
  if (source.provider === "aipdb") {
    return (
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="font-medium text-foreground">AbuseIPDB</span>
          <VerdictBadge verdict={source.verdict} />
          <span className="text-muted-foreground">
            {String(d.confidence ?? 0)}% confidence · {String(d.totalReports ?? 0)} reports
          </span>
        </div>
        {(d.isp || d.countryCode) && (
          <div className="pl-3 text-muted-foreground font-mono">
            {String(d.countryCode || "")} {String(d.isp || "")} {d.usageType ? `(${String(d.usageType)})` : ""}
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="font-mono text-muted-foreground">
      {source.provider}: {JSON.stringify(d)}
    </div>
  );
}
