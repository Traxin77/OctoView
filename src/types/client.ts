export type ClientStatus = "active" | "idle" | "offline";
export type ClientOS     = "windows" | "linux" | "macos";

export interface VRClient {
  id:         string;
  clientId:   string;
  hostname:   string;
  os:         ClientOS;
  status:     ClientStatus;
  lastSeen:   string;
  ip:         string;
}

export interface ChatMessage {
  id:            string;
  role:          "user" | "assistant";
  content:       string;
  timestamp:     string;
  targetClients?: string[];
  artifacts?:    string[];
  artifactName?: string;
  rows?:         Record<string, unknown>[];
  status?:       "pending" | "running" | "complete" | "error";
}

export type IocType       = "hash" | "ip" | "domain" | "url";
export type ThreatVerdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface ThreatIntelSource {
  provider: string;
  verdict:  ThreatVerdict;
  score:    number;
  detail:   Record<string, unknown>;
}

export interface ThreatIntelResult {
  ioc:      string;
  iocType:  IocType;
  verdict:  ThreatVerdict;
  score:    number;
  sources:  ThreatIntelSource[];
  foundIn:  { messageId: string; column?: string | null }[];
}

export interface ThreatIntelRecommendation {
  artifactName: string;
  reason:       string;
}