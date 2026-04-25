import { VRClient, ChatMessage } from "@/types/client";

export const mockClients: VRClient[] = [
  {
    id: "1",
    clientId: "C.1a2b3c4d5e6f",
    hostname: "DESKTOP-FORENSIC01",
    os: "windows",
    status: "active",
    lastSeen: "2 min ago",
    ip: "192.168.1.105",
  },
  {
    id: "2",
    clientId: "C.7g8h9i0j1k2l",
    hostname: "WORKSTATION-HR03",
    os: "windows",
    status: "active",
    lastSeen: "1 min ago",
    ip: "192.168.1.112",
  },
  {
    id: "3",
    clientId: "C.3m4n5o6p7q8r",
    hostname: "srv-web-prod-01",
    os: "linux",
    status: "idle",
    lastSeen: "15 min ago",
    ip: "10.0.0.42",
  },
  {
    id: "4",
    clientId: "C.9s0t1u2v3w4x",
    hostname: "LAPTOP-EXEC-CFO",
    os: "windows",
    status: "active",
    lastSeen: "Just now",
    ip: "192.168.1.201",
  },
  {
    id: "5",
    clientId: "C.5y6z7a8b9c0d",
    hostname: "dev-build-server",
    os: "linux",
    status: "offline",
    lastSeen: "3 hours ago",
    ip: "10.0.0.88",
  },
  {
    id: "6",
    clientId: "C.1e2f3g4h5i6j",
    hostname: "MacBook-Analyst-02",
    os: "macos",
    status: "idle",
    lastSeen: "8 min ago",
    ip: "192.168.1.155",
  },
];

export const mockMessages: ChatMessage[] = [
  {
    id: "1",
    role: "user",
    content: "Collect all browser history from the last 7 days and save to browser_history.txt",
    timestamp: "2026-03-18T10:23:00Z",
    targetClients: ["C.1a2b3c4d5e6f", "C.7g8h9i0j1k2l"],
  },
  {
    id: "2",
    role: "assistant",
    content: "I'll collect browser history from 2 endpoints. This will run the following artifacts:\n\n• `Windows.Applications.Chrome.History`\n• `Windows.Applications.Firefox.History`\n• `Windows.Applications.Edge.History`\n\nResults will be saved to `browser_history.txt` on each endpoint.",
    timestamp: "2026-03-18T10:23:05Z",
    artifacts: [
      "Windows.Applications.Chrome.History",
      "Windows.Applications.Firefox.History",
      "Windows.Applications.Edge.History",
    ],
    status: "complete",
  },
];
