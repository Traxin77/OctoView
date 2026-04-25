import { useState, useEffect, useCallback } from "react";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import { MessageSquare, Plus, Trash2, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

export interface ChatSession {
  id:    string;
  name:  string;
  mtime: string;
}

interface ChatsDropdownProps {
  activeSessionId: string;
  onSwitchSession: (id: string) => void;
  onNewChat:       () => void;
  refreshKey?:     number;
}

export function ChatsDropdown({
  activeSessionId, onSwitchSession, onNewChat, refreshKey,
}: ChatsDropdownProps) {
  const [open,     setOpen]     = useState(false);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [loading,  setLoading]  = useState(false);

  const fetchSessions = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/sessions");
      const d = await r.json();
      setSessions(d.sessions || []);
    } catch (err) {
      console.error("fetch sessions:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSessions(); }, [fetchSessions, refreshKey]);
  useEffect(() => { if (open) fetchSessions(); }, [open, fetchSessions]);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (!confirm("Delete this chat and all of its output files?")) return;
    try {
      await fetch(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
      setSessions((prev) => prev.filter((s) => s.id !== id));
      if (id === activeSessionId) onNewChat();
    } catch (err) {
      console.error("delete session:", err);
    }
  };

  const handleNew    = () => { onNewChat();           setOpen(false); };
  const handleSwitch = (id: string) => { onSwitchSession(id); setOpen(false); };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          className="flex items-center gap-1.5 text-xs px-2 py-1 rounded hover:bg-secondary text-foreground"
          title="Chat sessions"
        >
          <MessageSquare className="h-3.5 w-3.5" />
          <span>Chats</span>
          <ChevronDown className="h-3 w-3 opacity-60" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-0 max-h-[70vh] flex flex-col">
        <button
          onClick={handleNew}
          className="flex items-center gap-2 px-3 py-2.5 text-sm font-medium border-b hover:bg-secondary shrink-0"
        >
          <Plus className="h-3.5 w-3.5 text-primary" />
          New Chat
        </button>

        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && sessions.length === 0 && (
            <div className="px-3 py-4 text-xs text-muted-foreground text-center">Loading…</div>
          )}

          {!loading && sessions.length === 0 && (
            <div className="px-3 py-4 text-xs text-muted-foreground text-center">No chats yet.</div>
          )}

          {sessions.map((s) => {
            const active = s.id === activeSessionId;
            return (
              <div
                key={s.id}
                role="button"
                tabIndex={0}
                onClick={() => handleSwitch(s.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") handleSwitch(s.id); }}
                className={cn(
                  "group flex items-center gap-2 px-3 py-2 border-b border-border/30 cursor-pointer hover:bg-secondary outline-none",
                  active && "bg-primary/5",
                )}
              >
                <MessageSquare
                  className={cn("h-3.5 w-3.5 shrink-0", active ? "text-primary" : "text-muted-foreground")}
                />
                <div className="flex-1 min-w-0">
                  <div
                    className={cn(
                      "text-xs truncate",
                      active ? "font-medium text-foreground" : "text-foreground",
                    )}
                    title={s.name}
                  >
                    {s.name || s.id}
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    {new Date(s.mtime).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={(e) => handleDelete(e, s.id)}
                  className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-destructive/10 hover:text-destructive text-muted-foreground shrink-0"
                  title="Delete chat and its output files"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}
