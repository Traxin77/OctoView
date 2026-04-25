import { useCallback, useEffect, useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PlusCircle, Download, Trash2, Loader2, Monitor, Server, Laptop, Container } from "lucide-react";
import { cn } from "@/lib/utils";

type AgentOS = "windows" | "linux" | "darwin" | "docker";

interface AgentFile {
  name:  string;
  size:  number;
  mtime: string;
  os:    AgentOS | string;
}

const OS_LABEL: Record<AgentOS, string> = {
  windows: "Windows (.exe)",
  linux:   "Linux (ELF)",
  darwin:  "macOS",
  docker:  "Docker bundle (.tar.gz)",
};

function osIcon(os: string) {
  if (os === "windows") return Monitor;
  if (os === "docker")  return Container;
  if (os === "darwin")  return Laptop;
  return Server;
}

function fmtSize(n: number) {
  if (n < 1024)        return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function NewAgentButton() {
  const [open,     setOpen]     = useState(false);
  const [os,       setOs]       = useState<AgentOS>("windows");
  const [building, setBuilding] = useState(false);
  const [agents,   setAgents]   = useState<AgentFile[]>([]);
  const [error,    setError]    = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const r = await fetch("/api/agents");
      const d = await r.json();
      setAgents(d.agents || []);
    } catch (err: any) {
      setError(err?.message || "failed to list agents");
    }
  }, []);

  useEffect(() => { if (open) { setError(null); reload(); } }, [open, reload]);

  const handleBuild = useCallback(async () => {
    setBuilding(true); setError(null);
    try {
      const r = await fetch("/api/agents/build", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ os }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `build failed (${r.status})`);
      await reload();
    } catch (err: any) {
      setError(err?.message || "build failed");
    } finally {
      setBuilding(false);
    }
  }, [os, reload]);

  const handleDelete = useCallback(async (name: string) => {
    try {
      await fetch(`/api/agents/${encodeURIComponent(name)}`, { method: "DELETE" });
      await reload();
    } catch { /* ignore */ }
  }, [reload]);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={cn(
          "w-full flex items-center justify-center gap-2 rounded-2xl",
          "bg-primary text-primary-foreground hover:bg-primary/90",
          "text-sm font-medium px-3 py-2 shadow-sm transition-colors",
        )}
      >
        <PlusCircle className="h-4 w-4" />
        Create new agent
      </button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="rounded-3xl sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Create new agent</DialogTitle>
            <DialogDescription>
              Builds a self-contained client binary with certificates + auto-connect baked in.
              Transfer to the target host and run it — no config file, no arguments, no install.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Target platform</label>
              <Select value={os} onValueChange={(v) => setOs(v as AgentOS)}>
                <SelectTrigger className="rounded-xl">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="rounded-xl">
                  <SelectItem value="windows">{OS_LABEL.windows}</SelectItem>
                  <SelectItem value="linux">{OS_LABEL.linux}</SelectItem>
                  <SelectItem value="darwin">{OS_LABEL.darwin}</SelectItem>
                  <SelectItem value="docker">{OS_LABEL.docker}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Button
              onClick={handleBuild}
              disabled={building}
              className="w-full rounded-xl"
            >
              {building
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Building…</>
                : <>Build agent</>}
            </Button>

            {error && (
              <div className="text-xs text-destructive bg-destructive/10 rounded-xl p-2 break-words">
                {error}
              </div>
            )}

            <div className="pt-2 border-t">
              <div className="text-xs font-medium text-muted-foreground mb-2">
                Built agents ({agents.length})
              </div>
              <div className="max-h-64 overflow-y-auto space-y-1.5">
                {agents.length === 0 && (
                  <div className="text-xs text-muted-foreground text-center py-4">
                    No agents built yet.
                  </div>
                )}
                {agents.map((a) => {
                  const Icon = osIcon(a.os);
                  return (
                    <div
                      key={a.name}
                      className="flex items-center gap-2 rounded-xl border bg-secondary/40 px-3 py-2"
                    >
                      <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-mono truncate">{a.name}</div>
                        <div className="text-[10px] text-muted-foreground">
                          {fmtSize(a.size)} · {new Date(a.mtime).toLocaleString()}
                        </div>
                      </div>
                      <a
                        href={`/api/agents/download/${encodeURIComponent(a.name)}`}
                        download
                        className="p-1.5 rounded-lg hover:bg-accent"
                        title="Download"
                      >
                        <Download className="h-3.5 w-3.5" />
                      </a>
                      <button
                        onClick={() => handleDelete(a.name)}
                        className="p-1.5 rounded-lg hover:bg-destructive/10 text-destructive"
                        title="Delete"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="secondary" onClick={() => setOpen(false)} className="rounded-xl">
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
