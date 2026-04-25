import { useQuery } from "@tanstack/react-query";
import { useCallback, useRef } from "react";
import { VRClient } from "@/types/client";

// ─── /api/clients ─────────────────────────────────────────────────────────────

interface ClientsResponse {
  clients: VRClient[];
  lastFetchedAt: string | null;
  error: string | null;
}

async function fetchClients(): Promise<ClientsResponse> {
  const res = await fetch("/api/clients");
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.details || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * useVelociraptorClients
 * Fetches the live client list from the backend, refreshed every 15 s.
 */
export function useVelociraptorClients() {
  const { data, isLoading, isError, error, dataUpdatedAt } = useQuery<
    ClientsResponse,
    Error
  >({
    queryKey: ["velociraptorClients"],
    queryFn: fetchClients,
    refetchInterval: 15_000,
    staleTime: 10_000,
    retry: 2,
  });

  return {
    clients: data?.clients ?? [],
    isLoading,
    isError,
    errorMessage: isError
      ? (error?.message ?? "Unknown error")
      : (data?.error ?? null),
    lastFetchedAt: data?.lastFetchedAt ?? null,
  };
}

// ─── /api/query/stream ────────────────────────────────────────────────────────

export interface VQLStreamEvent {
  type: "rows" | "log" | "done" | "error";
  rows?: Record<string, unknown>[];
  message?: string;
}

export interface UseVQLStreamOptions {
  onRows?:  (rows: Record<string, unknown>[]) => void;
  onLog?:   (message: string) => void;
  onDone?:  () => void;
  onError?: (message: string) => void;
}

/**
 * useVQLStream
 * Returns a `runQuery(vql)` function that opens an SSE stream to /api/query/stream
 * and calls the provided callbacks as results arrive.
 * Returns a `cancel()` function to stop an in-progress query.
 *
 * Usage in ChatThread / CommandBar:
 *   const { runQuery, cancel, isRunning } = useVQLStream({ onRows, onLog, onDone });
 */
export function useVQLStream(options: UseVQLStreamOptions) {
  const esRef = useRef<EventSource | null>(null);
  const isRunningRef = useRef(false);

  const cancel = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    isRunningRef.current = false;
  }, []);

  const runQuery = useCallback(
    (vql: string) => {
      // Cancel any in-progress query first
      cancel();

      isRunningRef.current = true;
      const es = new EventSource(
        `/api/query/stream?vql=${encodeURIComponent(vql)}`
      );
      esRef.current = es;

      es.onmessage = (event) => {
        try {
          const data: VQLStreamEvent = JSON.parse(event.data);
          switch (data.type) {
            case "rows":
              if (data.rows?.length) options.onRows?.(data.rows);
              break;
            case "log":
              if (data.message) options.onLog?.(data.message);
              break;
            case "done":
              options.onDone?.();
              cancel();
              break;
            case "error":
              if (data.message) options.onError?.(data.message);
              cancel();
              break;
          }
        } catch {
          /* malformed event — ignore */
        }
      };

      es.onerror = () => {
        options.onError?.("Stream connection lost");
        cancel();
      };
    },
    [cancel, options]
  );

  return { runQuery, cancel };
}