import { useState, useCallback, useRef } from "react";
import { ClientSidebar }     from "@/components/ClientSidebar";
import { ChatThread }        from "@/components/ChatThread";
import { CommandBar }        from "@/components/CommandBar";
import { OutputFilesPanel }  from "@/components/OutputFilesPanel";
import { ChatsDropdown }     from "@/components/ChatsDropdown";
import { ThreatIntelButton } from "@/components/ThreatIntelButton";
import { RefreshCw, AlertTriangle } from "lucide-react";
import { useVelociraptorClients } from "@/hooks/useVelociraptorClients";
import { ChatMessage }     from "@/types/client";

const SESSION_STORAGE_KEY = "velociprompt-session-id";

function loadInitialSessionId(): string {
  const existing = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) return existing;
  const fresh = `session-${Date.now()}`;
  sessionStorage.setItem(SESSION_STORAGE_KEY, fresh);
  return fresh;
}

const Index = () => {
  const { clients, isLoading, isError, errorMessage, lastFetchedAt } =
    useVelociraptorClients();

  const [sessionId,    setSessionId]    = useState<string>(loadInitialSessionId);
  const [selected,     setSelected]     = useState<Set<string>>(new Set());
  const [messages,     setMessages]     = useState<ChatMessage[]>([]);
  const [isRunning,    setIsRunning]    = useState(false);
  const [filesRefresh, setFilesRefresh] = useState(0);
  const [chatsRefresh, setChatsRefresh] = useState(0);
  const abortRef = useRef<(() => void) | null>(null);

  const handleNewChat = useCallback(() => {
    abortRef.current?.();
    const fresh = `session-${Date.now()}`;
    sessionStorage.setItem(SESSION_STORAGE_KEY, fresh);
    setSessionId(fresh);
    setMessages([]);
    setIsRunning(false);
    setFilesRefresh((x) => x + 1);
    setChatsRefresh((x) => x + 1);
  }, []);

  const handleSwitchSession = useCallback(async (id: string) => {
    if (id === sessionId) return;
    abortRef.current?.();
    sessionStorage.setItem(SESSION_STORAGE_KEY, id);
    setSessionId(id);
    setMessages([]);
    setIsRunning(false);
    setFilesRefresh((x) => x + 1);
    try {
      const r = await fetch(`/api/sessions/${encodeURIComponent(id)}/messages`);
      const d = await r.json();
      setMessages(d.messages || []);
    } catch (err) {
      console.error("load session messages:", err);
    }
  }, [sessionId]);

  const handleToggle      = useCallback((id: string) => setSelected(prev => {
    const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next;
  }), []);
  const handleSelectAll   = useCallback(() => setSelected(new Set(clients.map(c => c.clientId))), [clients]);
  const handleDeselectAll = useCallback(() => setSelected(new Set()), []);

  const addMsg    = (msg: ChatMessage) => setMessages(prev => [...prev, msg]);
  const updateMsg = (id: string, patch: Partial<ChatMessage>) =>
    setMessages(prev => prev.map(m => m.id === id ? { ...m, ...patch } : m));
  const appendText = (id: string, text: string) =>
    setMessages(prev => prev.map(m =>
      m.id === id ? { ...m, content: m.content + text } : m
    ));

  const handleSend = useCallback(async (content: string) => {
    if (isRunning) return;
    setIsRunning(true);

    // User message
    addMsg({
      id: crypto.randomUUID(), role: "user", content,
      timestamp: new Date().toISOString(),
      targetClients: Array.from(selected),
    });

    // Assistant placeholder
    const assistantId = crypto.randomUUID();
    addMsg({
      id: assistantId, role: "assistant", content: "",
      timestamp: new Date().toISOString(), status: "pending",
    });

    // Open SSE via POST /api/chat
    const controller = new AbortController();
    abortRef.current = () => controller.abort();

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: content, clientIds: Array.from(selected), sessionId }),
        signal: controller.signal,
      });
      console.log("fetch status:", response.status, response.headers.get("content-type"));
      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: "Unknown error" }));
        throw new Error(err.error);
      }

      const reader  = response.body!.getReader();
      const decoder = new TextDecoder();
      let   sseBuffer = "";

      // Track per-flow result message IDs
      const flowMsgIds: Record<string, string> = {};
      // Track tool calls for display
      let toolSummary: string[] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        sseBuffer += decoder.decode(value, { stream: true });
        const parts = sseBuffer.split("\n\n");
        sseBuffer   = parts.pop() || "";

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith("data: ")) continue;
          const raw = line.slice(6).trim();
          if (!raw) continue;
          let event: any;
          try { event = JSON.parse(raw); } catch { continue; }

          switch (event.type) {
            case "thinking":
              // Show thinking as dimmed prefix
              break;

            case "token":
              appendText(assistantId, event.text);
              break;

            case "tool_call":
              updateMsg(assistantId, { status: "running" });
              toolSummary.push(`🔧 ${event.name}(${Object.entries(event.args || {}).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(", ")})`);
              updateMsg(assistantId, {
                content: toolSummary.join("\n"),
                status: "running",
              });
              break;

            case "tool_result":
              // Already shown via tool_call — no extra UI update needed
              break;

            case "artifact":
              updateMsg(assistantId, { artifacts: event.names });
              break;

            case "flow": {
              // Agent scheduled a collection — open a result stream for it
              const flowMsgId = crypto.randomUUID();
              flowMsgIds[event.flowId] = flowMsgId;
              addMsg({
                id: flowMsgId, role: "assistant",
                content: `Collecting ${event.artifactName} from ${event.clientId}...`,
                timestamp: new Date().toISOString(),
                status: "running", rows: [],
                artifactName: event.artifactName,
              });
              // Open SSE stream for this flow
              openFlowStream(event.clientId, event.flowId, event.artifactName, flowMsgId);
              break;
            }

            case "done":
              if (event.answer) {
                // Replace tool summary with final answer
                updateMsg(assistantId, { content: event.answer, status: "complete" });
              } else {
                updateMsg(assistantId, { status: "complete" });
              }
              setIsRunning(false);
              setFilesRefresh((x) => x + 1);
              setChatsRefresh((x) => x + 1);
              break;

            case "error":
              updateMsg(assistantId, {
                content: event.message || "Unknown error",
                status: "error",
              });
              setIsRunning(false);
              break;

            case "status":
              // Status messages — append to content
              updateMsg(assistantId, {
                content: (event.message || ""),
                status: "running",
              });
              break;
          }
        }
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        updateMsg(assistantId, { content: `Error: ${err.message}`, status: "error" });
      }
      setIsRunning(false);
    }
  }, [selected, isRunning, sessionId]);

  // Open SSE stream for a Velociraptor flow and update a message with rows
  const openFlowStream = (clientId: string, flowId: string, artifactName: string, msgId: string) => {
    const params = new URLSearchParams({ clientId, flowId, artifactName });
    const es     = new EventSource(`/api/stream?${params}`);

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "rows") {
        setMessages(prev => prev.map(m =>
          m.id === msgId ? { ...m, rows: [...(m.rows || []), ...data.rows] } : m
        ));
      }
      if (data.type === "done") {
        updateMsg(msgId, {
          content: `${artifactName} — ${data.totalRows} rows collected`,
          status: "complete",
        });
        setFilesRefresh((x) => x + 1);
        es.close();
      }
      if (data.type === "error") {
        updateMsg(msgId, { content: `Error: ${data.message}`, status: "error" });
        es.close();
      }
    };
    es.onerror = () => {
      updateMsg(msgId, { status: "error", content: "Stream lost" });
      es.close();
    };
  };

  return (
    <div className="h-screen flex flex-col">
      <header className="relative h-14 border-b flex items-center px-4 shrink-0 bg-background">
        <div className="flex items-center gap-2.5">
          <img src="/OctoView.png" alt="OctoView" className="h-10 w-10 object-contain" />
          <span className="font-semibold text-base text-foreground">OctoView</span>
        </div>
        <span className="text-xs text-muted-foreground ml-4">Velociraptor NLP Interface</span>
        <div className="absolute left-1/2 -translate-x-1/2">
          <ChatsDropdown
            activeSessionId={sessionId}
            onSwitchSession={handleSwitchSession}
            onNewChat={handleNewChat}
            refreshKey={chatsRefresh}
          />
        </div>
        <div className="ml-auto flex items-center gap-2">
          <ThreatIntelButton sessionId={sessionId} messages={messages} />
          {isLoading && <div className="flex items-center gap-1.5 text-xs text-muted-foreground"><RefreshCw className="h-3 w-3 animate-spin" /><span>Connecting...</span></div>}
          {isError   && <div className="flex items-center gap-1.5 text-xs text-destructive"><AlertTriangle className="h-3 w-3" /><span title={errorMessage ?? undefined}>Backend unreachable</span></div>}
          {!isLoading && !isError && lastFetchedAt && <div className="flex items-center gap-1.5 text-xs text-muted-foreground"><span className="h-1.5 w-1.5 rounded-full bg-success inline-block" /><span>Live</span></div>}
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        <ClientSidebar
          clients={clients} selected={selected}
          onToggle={handleToggle} onSelectAll={handleSelectAll}
          onDeselectAll={handleDeselectAll} isLoading={isLoading}
        />
        <main className="flex-1 flex flex-col min-w-0">
          <ChatThread messages={messages} />
          <CommandBar targetCount={selected.size} onSend={handleSend} disabled={isRunning} />
        </main>
        <OutputFilesPanel sessionId={sessionId} refreshKey={filesRefresh} />
      </div>
    </div>
  );
};

export default Index;