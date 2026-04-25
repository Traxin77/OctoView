import { ChatMessage } from "@/types/client";
import { cn }          from "@/lib/utils";
import { User, CheckCircle2, Loader2, AlertCircle, ChevronDown, ChevronUp ,Clock} from "lucide-react";
import { useState } from "react";

const statusConfig = {
  pending:  { icon: Clock,         label: "Queued",       className: "text-muted-foreground" },
  running:  { icon: Loader2,       label: "Thinking…",    className: "text-primary animate-spin" },
  complete: { icon: CheckCircle2,  label: "Complete",     className: "text-success" },
  error:    { icon: AlertCircle,   label: "Error",        className: "text-destructive" },
};

// ── Result table (for artifact rows) ──────────────────────────────────────────

function ResultTable({ rows }: { rows: Record<string, unknown>[] }) {
  const [expanded, setExpanded] = useState(true);
  if (!rows.length) return null;

  const columns = Object.keys(rows[0]).slice(0, 8); // max 8 columns
  const preview = rows.slice(0, 50);                // show first 50 rows

  return (
    <div className="mt-3 pt-3 border-t">
      <button
        onClick={() => setExpanded(e => !e)}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground mb-2"
      >
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        {rows.length} rows
        {rows.length > 50 && " (showing first 50)"}
      </button>

      {expanded && (
        <div className="overflow-x-auto rounded border border-border/50">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-muted/50">
                {columns.map(col => (
                  <th key={col} className="px-2 py-1.5 text-left font-medium text-muted-foreground truncate max-w-[160px]">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {preview.map((row, i) => (
                <tr key={i} className={cn("border-t border-border/30", i % 2 === 0 ? "" : "bg-muted/20")}>
                  {columns.map(col => (
                    <td key={col} className="px-2 py-1 font-mono truncate max-w-[200px]" title={String(row[col] ?? "")}>
                      {String(row[col] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main ChatThread ────────────────────────────────────────────────────────────

interface ChatThreadProps {
  messages: ChatMessage[];
}

export function ChatThread({ messages }: ChatThreadProps) {
  if (messages.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center max-w-md">
          <img src="/OctoView.png" alt="OctoView" className="h-24 w-24 object-contain mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-foreground mb-2">OctoView</h3>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Select one or more clients from the sidebar, then describe what you
            want to collect in natural language.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      {messages.map((msg) => {
        const isUser = msg.role === "user";

        return (
          <div
            key={msg.id}
            className={cn(
              "rounded-lg border p-4 max-w-3xl",
              isUser ? "ml-auto bg-background" : "mr-auto bg-secondary/50"
            )}
          >
            {/* Header */}
            <div className="flex items-center gap-2 mb-2">
              {isUser ? (
                <div className="h-6 w-6 rounded-md flex items-center justify-center shrink-0 bg-foreground/10">
                  <User className="h-3.5 w-3.5 text-foreground" />
                </div>
              ) : (
                <img src="/OctoView.png" alt="OctoView" className="h-7 w-7 object-contain shrink-0" />
              )}
              <span className="text-xs font-medium text-muted-foreground">
                {isUser ? "You" : "OctoView"}
              </span>
              {msg.targetClients && (
                <span className="text-xs text-muted-foreground ml-auto">
                  → {msg.targetClients.length} endpoint{msg.targetClients.length !== 1 ? "s" : ""}
                </span>
              )}
            </div>

            {/* Content */}
            <div className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">
              {msg.content}
            </div>

            {/* Artifact tags */}
            {msg.artifacts && msg.artifacts.length > 0 && (
              <div className="mt-3 pt-3 border-t flex flex-wrap gap-1">
                {msg.artifacts.map(a => (
                  <span key={a} className="text-xs font-mono bg-primary/5 text-primary px-2 py-1 rounded">
                    {a}
                  </span>
                ))}
              </div>
            )}

            {/* Streaming result rows */}
            {msg.rows && msg.rows.length > 0 && <ResultTable rows={msg.rows} />}

            {/* Status indicator */}
            {msg.status && statusConfig[msg.status] && (
              <div className="mt-3 pt-3 border-t flex items-center gap-2">
                {(() => {
                  const cfg  = statusConfig[msg.status!];
                  const Icon = cfg.icon;
                  return (
                    <>
                      <Icon className={cn("h-3.5 w-3.5", cfg.className)} />
                      <span className={cn("text-xs font-medium text-primary")}>{cfg.label}</span>
                    </>
                  );
                })()}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}