export type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  provider?: string;
};

export type ScreeningResult = {
  verdict?: string;
  risk_score?: number;
  confidence?: number;
  threat_category?: string;
  prompt_injection_detected?: boolean;
  mitre_techniques?: string[];
  summary?: string;
  findings?: string[];
  recommended_action?: string;
  iocs?: Record<string, string[]>;
  sources?: { citation: string; source: string; id: string; title: string; url?: string | null }[];
  filename?: string;
};