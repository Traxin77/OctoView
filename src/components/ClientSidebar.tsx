import { useState } from "react";
import { Search, Monitor, Server, Laptop, RefreshCw, EyeOff } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Input }    from "@/components/ui/input";
import { VRClient, ClientOS } from "@/types/client";
import { NewAgentButton } from "@/components/NewAgentButton";
import { cn }       from "@/lib/utils";

const osIcon: Record<ClientOS, typeof Monitor> = {
  windows: Monitor,
  linux:   Server,
  macos:   Laptop,
};

const statusColor: Record<string, string> = {
  active:  "bg-success",
  idle:    "bg-warning",
  offline: "bg-muted-foreground/40",
};

interface ClientSidebarProps {
  clients:        VRClient[];
  selected:       Set<string>;
  onToggle:       (clientId: string) => void;
  onSelectAll:    () => void;
  onDeselectAll:  () => void;
  isLoading?:     boolean;
}

function SkeletonRow() {
  return (
    <div className="w-full flex items-start gap-3 px-4 py-3 border-b border-border/50 animate-pulse">
      <div className="h-4 w-4 rounded bg-muted mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0 space-y-2">
        <div className="h-3.5 bg-muted rounded w-3/4" />
        <div className="h-3   bg-muted rounded w-1/2" />
        <div className="h-3   bg-muted rounded w-2/3" />
      </div>
    </div>
  );
}

export function ClientSidebar({
  clients, selected, onToggle, onSelectAll, onDeselectAll, isLoading = false,
}: ClientSidebarProps) {
  const [search,      setSearch]      = useState("");
  const [hideOffline, setHideOffline] = useState(false);

  const filtered = clients.filter((c) => {
    if (hideOffline && c.status === "offline") return false;
    return (
      c.hostname.toLowerCase().includes(search.toLowerCase()) ||
      c.clientId.toLowerCase().includes(search.toLowerCase()) ||
      c.ip.includes(search)
    );
  });

  const allSelected = filtered.length > 0 && filtered.every((c) => selected.has(c.clientId));
  const offlineCount = clients.filter((c) => c.status === "offline").length;

  return (
    <aside className="w-72 border-r bg-secondary/50 flex flex-col h-full shrink-0">
      {/* Header */}
      <div className="p-4 border-b">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-foreground">Connected Clients</h2>
          <div className="flex items-center gap-2">
            {/* Hide offline toggle */}
            {offlineCount > 0 && (
              <button
                onClick={() => setHideOffline(h => !h)}
                title={hideOffline ? "Show offline clients" : "Hide offline clients"}
                className={cn(
                  "flex items-center gap-1 text-xs px-1.5 py-0.5 rounded transition-colors",
                  hideOffline
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <EyeOff className="h-3 w-3" />
                {offlineCount}
              </button>
            )}
            {isLoading && <RefreshCw className="h-3.5 w-3.5 text-muted-foreground animate-spin" />}
          </div>
        </div>

        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search clients…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-sm bg-background"
          />
        </div>

        <div className="flex items-center justify-between mt-3">
          <span className="text-xs text-muted-foreground">{selected.size} selected</span>
          <button
            onClick={allSelected ? onDeselectAll : onSelectAll}
            className="text-xs text-primary hover:underline font-medium"
            disabled={isLoading && clients.length === 0}
          >
            {allSelected ? "Deselect all" : "Select all"}
          </button>
        </div>
      </div>

      {/* Client list */}
      <div className="flex-1 overflow-y-auto">
        {isLoading && clients.length === 0 && (
          <><SkeletonRow /><SkeletonRow /><SkeletonRow /><SkeletonRow /></>
        )}

        {filtered.map((client) => {
          const Icon       = osIcon[client.os];
          const isSelected = selected.has(client.clientId);
          const isOffline  = client.status === "offline";

          return (
            <button
              key={client.id}
              onClick={() => onToggle(client.clientId)}
              className={cn(
                "w-full flex items-start gap-3 px-4 py-3 text-left border-b border-border/50 transition-colors",
                isSelected  ? "bg-primary/5"    : "hover:bg-secondary",
                isOffline   ? "opacity-40"       : ""   // ← dim offline clients
              )}
            >
              <Checkbox
                checked={isSelected}
                className="mt-0.5 shrink-0"
                onClick={(e) => e.stopPropagation()}
                onCheckedChange={() => onToggle(client.clientId)}
              />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className={cn("text-sm font-medium truncate", isOffline && "line-through decoration-muted-foreground/50")}>
                    {client.hostname}
                  </span>
                  <span
                    className={cn("h-2 w-2 rounded-full shrink-0 ml-auto", statusColor[client.status])}
                    title={client.status}
                  />
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs font-mono text-muted-foreground truncate">
                    {client.clientId}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-0.5">
                  <span className="text-xs text-muted-foreground">{client.ip}</span>
                  <span className={cn("text-xs", isOffline ? "text-destructive/60" : "text-muted-foreground")}>
                    {isOffline ? `offline · ${client.lastSeen}` : client.lastSeen}
                  </span>
                </div>
              </div>
            </button>
          );
        })}

        {!isLoading && clients.length === 0 && (
          <div className="p-6 text-center">
            <p className="text-sm text-muted-foreground">No clients found.</p>
            <p className="text-xs text-muted-foreground mt-1">Make sure the backend is running.</p>
          </div>
        )}

        {!isLoading && clients.length > 0 && filtered.length === 0 && (
          <div className="p-4 text-sm text-muted-foreground text-center">
            {hideOffline && offlineCount > 0
              ? `${offlineCount} offline client${offlineCount > 1 ? "s" : ""} hidden`
              : "No clients match your search."
            }
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-3 border-t bg-secondary/30 space-y-2">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span className="text-success">{clients.filter(c => c.status === "active").length} active</span>
          <span className="opacity-50">{offlineCount} offline</span>
        </div>
        <NewAgentButton />
      </div>
    </aside>
  );
}