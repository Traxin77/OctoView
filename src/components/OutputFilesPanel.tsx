import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { ChevronLeft, ChevronRight, ChevronUp, ChevronDown, FileText, RefreshCw, X, FolderOpen, Search } from "lucide-react";
import { cn } from "@/lib/utils";

interface FileEntry {
  name:  string;
  size:  number;
  mtime: string;
}

interface OutputFilesPanelProps {
  sessionId:  string;
  refreshKey: number;
}

function fmtSize(n: number): string {
  if (n < 1024)        return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function OutputFilesPanel({ sessionId, refreshKey }: OutputFilesPanelProps) {
  const [open,     setOpen]     = useState(true);
  const [files,    setFiles]    = useState<FileEntry[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [viewFile, setViewFile] = useState<{ name: string; content: string; truncated?: boolean } | null>(null);
  const [search,       setSearch]       = useState("");
  const [currentMatch, setCurrentMatch] = useState(0);
  const currentMatchRef = useRef<HTMLElement>(null);

  const matchData = useMemo(() => {
    if (!viewFile || !search) return { segments: null as null | Array<{ text: string; match: boolean; idx: number }>, total: 0 };
    const content = viewFile.content;
    const q       = search.toLowerCase();
    const lower   = content.toLowerCase();
    const segs: Array<{ text: string; match: boolean; idx: number }> = [];
    let i = 0, n = 0;
    while (i < content.length) {
      const hit = lower.indexOf(q, i);
      if (hit === -1) { segs.push({ text: content.slice(i), match: false, idx: -1 }); break; }
      if (hit > i)    segs.push({ text: content.slice(i, hit), match: false, idx: -1 });
      segs.push({ text: content.slice(hit, hit + q.length), match: true, idx: n++ });
      i = hit + q.length;
    }
    return { segments: segs, total: n };
  }, [viewFile, search]);

  useEffect(() => { setCurrentMatch(0); }, [search, viewFile]);
  useEffect(() => {
    if (matchData.total > 0) currentMatchRef.current?.scrollIntoView({ block: "center" });
  }, [currentMatch, matchData.total]);

  const closeViewer = () => { setViewFile(null); setSearch(""); setCurrentMatch(0); };
  const nextMatch   = () => { if (matchData.total) setCurrentMatch(m => (m + 1) % matchData.total); };
  const prevMatch   = () => { if (matchData.total) setCurrentMatch(m => (m - 1 + matchData.total) % matchData.total); };

  const fetchFiles = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/files?sessionId=${encodeURIComponent(sessionId)}`);
      const d = await r.json();
      setFiles(d.files || []);
    } catch (err) {
      console.error("fetch files:", err);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { fetchFiles(); }, [fetchFiles, refreshKey]);

  const openFile = async (name: string) => {
    try {
      const r = await fetch(
        `/api/files/content?sessionId=${encodeURIComponent(sessionId)}&name=${encodeURIComponent(name)}`
      );
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      setViewFile({ name: d.name, content: d.content || "", truncated: d.truncated });
    } catch (err) {
      console.error("open file:", err);
    }
  };

  // Collapsed: narrow strip
  if (!open) {
    return (
      <aside className="w-10 border-l shrink-0 bg-secondary/30 flex flex-col items-center py-2">
        <button
          onClick={() => setOpen(true)}
          className="p-2 rounded hover:bg-secondary text-muted-foreground hover:text-foreground"
          title="Show output files"
        >
          <FolderOpen className="h-4 w-4" />
        </button>
        {files.length > 0 && (
          <span className="mt-1 text-[10px] text-muted-foreground">{files.length}</span>
        )}
      </aside>
    );
  }

  // Expanded: full panel
  return (
    <aside className="w-72 border-l shrink-0 bg-secondary/30 flex flex-col min-h-0">
      <div className="flex items-center px-4 py-3 text-sm font-semibold text-foreground border-b shrink-0">
        <span className="flex items-center gap-2 flex-1">
          <FolderOpen className="h-3.5 w-3.5 text-muted-foreground" />
          Output Files
          <span className="text-xs text-muted-foreground font-normal">({files.length})</span>
        </span>
        <button
          onClick={fetchFiles}
          className="p-1 rounded hover:bg-secondary mr-1"
          title="Refresh"
        >
          <RefreshCw className={cn("h-3 w-3 text-muted-foreground", loading && "animate-spin")} />
        </button>
        <button
          onClick={() => setOpen(false)}
          className="p-1 rounded hover:bg-secondary"
          title="Collapse"
        >
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0">
        {files.length === 0 ? (
          <div className="px-4 py-3 text-xs text-muted-foreground">
            No output files yet. Ask the agent to save something.
          </div>
        ) : (
          files.map((f) => (
            <button
              key={f.name}
              onClick={() => openFile(f.name)}
              className="w-full flex items-center gap-2 px-4 py-2 text-left hover:bg-secondary/60 border-b border-border/30"
            >
              <FileText className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span className="text-xs font-mono text-foreground truncate flex-1" title={f.name}>
                {f.name}
              </span>
              <span className="text-xs text-muted-foreground shrink-0">{fmtSize(f.size)}</span>
            </button>
          ))
        )}
      </div>

      {viewFile && (
        <div
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={closeViewer}
        >
          <div
            className="bg-background border rounded-lg shadow-xl w-full max-w-4xl max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 px-4 py-3 border-b">
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                <span className="text-sm font-mono font-medium truncate">{viewFile.name}</span>
                {viewFile.truncated && (
                  <span className="text-xs text-warning shrink-0">(truncated)</span>
                )}
              </div>
              <div className="flex items-center gap-1 bg-secondary/50 border rounded px-2 py-1 shrink-0">
                <Search className="h-3.5 w-3.5 text-muted-foreground" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") { e.preventDefault(); e.shiftKey ? prevMatch() : nextMatch(); }
                    else if (e.key === "Escape") { e.preventDefault(); setSearch(""); }
                  }}
                  placeholder="Search in file..."
                  className="bg-transparent text-xs outline-none w-40 placeholder:text-muted-foreground"
                />
                {search && (
                  <span className="text-[10px] text-muted-foreground font-mono tabular-nums">
                    {matchData.total ? `${currentMatch + 1}/${matchData.total}` : "0/0"}
                  </span>
                )}
                <button
                  onClick={prevMatch}
                  disabled={!matchData.total}
                  className="p-0.5 rounded hover:bg-secondary disabled:opacity-30 disabled:cursor-not-allowed"
                  title="Previous match (Shift+Enter)"
                >
                  <ChevronUp className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={nextMatch}
                  disabled={!matchData.total}
                  className="p-0.5 rounded hover:bg-secondary disabled:opacity-30 disabled:cursor-not-allowed"
                  title="Next match (Enter)"
                >
                  <ChevronDown className="h-3.5 w-3.5" />
                </button>
              </div>
              <button
                onClick={closeViewer}
                className="p-1 rounded hover:bg-secondary shrink-0"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <pre className="flex-1 overflow-auto p-4 text-xs font-mono text-foreground whitespace-pre-wrap break-all">
              {matchData.segments
                ? matchData.segments.map((s, i) =>
                    s.match ? (
                      <mark
                        key={i}
                        ref={s.idx === currentMatch ? currentMatchRef : undefined}
                        className={cn(
                          "rounded-sm",
                          s.idx === currentMatch
                            ? "bg-warning text-warning-foreground"
                            : "bg-warning/30 text-foreground",
                        )}
                      >
                        {s.text}
                      </mark>
                    ) : (
                      <span key={i}>{s.text}</span>
                    ),
                  )
                : viewFile.content}
            </pre>
          </div>
        </div>
      )}
    </aside>
  );
}
