import { useState } from "react";
import { ShieldAlert, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { ChatMessage } from "@/types/client";

interface ThreatIntelButtonProps {
  sessionId: string;
  messages:  ChatMessage[];
}

export function ThreatIntelButton({ sessionId, messages }: ThreatIntelButtonProps) {
  const [busy, setBusy] = useState(false);

  const hasContent =
    messages.some(m => (m.rows && m.rows.length > 0) || (m.content && m.content.length > 40));

  const handleClick = async () => {
    if (busy || !hasContent) return;
    setBusy(true);
    try {
      const r = await fetch(
        `/api/threat-intel/${encodeURIComponent(sessionId)}/scan`,
        {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ messages }),
        },
      );
      if (!r.ok) {
        const text = await r.text();
        throw new Error(
          r.status === 413
            ? "Chat is too large to scan (>50 MB). Trim rows or split the session."
            : `scan failed: HTTP ${r.status} ${text.slice(0, 200)}`,
        );
      }
      const d = await r.json();
      if (!d.scanId) throw new Error(d.error || "scan failed to start");
      window.open(
        `/threat-intel/${encodeURIComponent(sessionId)}?scanId=${encodeURIComponent(d.scanId)}`,
        "_blank",
        "noopener,noreferrer",
      );
    } catch (err) {
      console.error("threat-intel scan:", err);
    } finally {
      setBusy(false);
    }
  };

  const disabled = busy || !hasContent;

  return (
    <button
      onClick={handleClick}
      disabled={disabled}
      title={
        !hasContent
          ? "Collect some data first — the scan looks at rows and text already in this chat."
          : "Score hashes/IPs/domains/URLs from this chat against VirusTotal + AbuseIPDB."
      }
      className={cn(
        "flex items-center gap-1.5 text-xs px-2 py-1 rounded",
        disabled
          ? "text-muted-foreground cursor-not-allowed opacity-60"
          : "text-foreground hover:bg-secondary",
      )}
    >
      {busy
        ? <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
        : <ShieldAlert className="h-3.5 w-3.5" />}
      <span>Threat Intel</span>
    </button>
  );
}
