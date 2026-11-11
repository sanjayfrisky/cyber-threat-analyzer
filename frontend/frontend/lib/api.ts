
import type { ScreeningResult } from "@/lib/types";

const API_BASE = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");

export function apiUrl(path: string) {
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

export async function checkBackend(): Promise<boolean> {
  try {
    const response = await fetch(apiUrl("/openapi.json"), {
      cache: "no-store",
    });
    return response.ok;
  } catch {
    return false;
  }
}

export async function sendChat(
  prompt: string,
  sessionId: string,
  onChunk: (text: string) => void,
  signal?: AbortSignal
): Promise<string> {
  const response = await fetch(apiUrl("/api/chat"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
    },
    body: JSON.stringify({
      prompt,
      session_id: sessionId,
    }),
    signal,
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(
      `Chat API ${response.status}: ${detail || response.statusText}`
    );
  }

  if (!response.body) {
    throw new Error("The browser did not receive a response stream.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";
  let fullText = "";

  // Parse both normal JSON and escaped JSON payloads.
  const parsePayload = (raw: string) => {
    let data = raw.trim();

    // Remove literal escaped SSE separators at the end.
    data = data.replace(/\\r?\\n\\r?\\n$/, "");

    try {
      let parsed = JSON.parse(data);

      // Handle JSON encoded as a JSON string.
      if (typeof parsed === "string") {
        parsed = JSON.parse(parsed);
      }

      return parsed;
    } catch {
      // Handle escaped JSON such as {\"type\":\"done\"}.
      const normalized = data.replace(/\\"/g, '"');

      try {
        return JSON.parse(normalized);
      } catch {
        console.warn("Could not parse SSE payload:", raw);
        return null;
      }
    }
  };

  const processEvent = (event: string) => {
    const data = event
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("\n");

    if (!data) return;

    const parsed = parsePayload(data);

    if (!parsed || typeof parsed !== "object") return;

    if (parsed.type === "chunk" && typeof parsed.text === "string") {
      fullText += parsed.text;
      onChunk(parsed.text);
    }

    if (parsed.type === "error") {
      throw new Error(parsed.detail || "Chat request failed.");
    }

    if (parsed.type === "sources") {
      console.log("Retrieved sources:", parsed.sources || []);
      console.log("Retrieved count:", parsed.retrieved_count ?? 0);
    }

    if (parsed.type === "done") {
      console.log("Chat stream completed:", parsed.provider || "Unknown provider");
    }
  };

  const processBuffer = (final = false) => {
    // Convert escaped separators between SSE events into real separators.
    buffer = buffer.replace(/\\n\\n(?=\s*data:)/g, "\n\n");

    const events = buffer.split(/\r?\n\r?\n/);

    // Keep the incomplete event until more data arrives.
    buffer = final ? "" : events.pop() || "";

    for (const event of events) {
      if (event.trim()) processEvent(event);
    }

    if (final && buffer.trim()) {
      processEvent(buffer);
    }
  };

  while (true) {
    const { value, done } = await reader.read();

    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    processBuffer();
  }

  buffer += decoder.decode();

  // Process the final event, including a final escaped separator.
  buffer = buffer.replace(/\\r?\\n\\r?\\n/g, "\n\n");
  processBuffer(true);

  if (!fullText) {
    console.warn("Chat stream finished without any text chunks.");
  }

  return fullText;
}

export async function screenEvidence(input: {
  content?: string;
  file?: File;
  context?: string;
}): Promise<ScreeningResult> {
  const form = new FormData();

  if (input.content) form.append("content", input.content);
  if (input.file) form.append("file", input.file);
  if (input.context) form.append("context", input.context);

  const response = await fetch(apiUrl("/api/screening"), {
    method: "POST",
    body: form,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.detail || `Screening API ${response.status}`);
  }

  return data as ScreeningResult;
}
