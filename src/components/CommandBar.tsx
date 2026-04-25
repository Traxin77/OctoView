import { useState } from "react";
import { Send, Crosshair } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CommandBarProps {
  targetCount: number;
  onSend: (message: string) => void;
  disabled?: boolean;
}

export function CommandBar({ targetCount, onSend, disabled }: CommandBarProps) {
  const [input, setInput] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || disabled) return;
    onSend(input.trim());
    setInput("");
  };

  return (
    <div className="border-t bg-background p-4">
      {targetCount > 0 && (
        <div className="flex items-center gap-2 mb-2 justify-center">
          <Crosshair className="h-3.5 w-3.5 text-primary" />
          <span className="text-xs font-medium text-muted-foreground">
            Targeting: <span className="text-foreground">{targetCount} endpoint{targetCount > 1 ? "s" : ""}</span>
          </span>
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="max-w-2xl mx-auto flex items-end gap-2"
      >
        <div className="flex-1 relative">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSubmit(e);
              }
            }}
            placeholder={
              targetCount === 0
                ? "Ask anything (local mode) or select clients for Velociraptor..."
                : `Describe what to collect from ${targetCount} endpoint${targetCount > 1 ? "s" : ""}...`
            }
            disabled={disabled}
            rows={1}
            className={cn(
              "w-full resize-none rounded-lg border bg-background px-4 py-3 text-sm",
              "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring",
              "disabled:opacity-50 disabled:cursor-not-allowed",
              "min-h-[44px] max-h-[120px]"
            )}
            style={{ fieldSizing: "content" } as React.CSSProperties}
          />
        </div>
        <Button
          type="submit"
          size="icon"
          disabled={!input.trim() || disabled}
          className="h-[44px] w-[44px] shrink-0"
        >
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </div>
  );
}
