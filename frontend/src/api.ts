export type Severity = "low" | "medium" | "high" | "critical";

export interface SecurityEvent {
  id: string;
  source: string;
  event_type: string;
  severity: Severity;
  message: string;
  host: string | null;
  occurred_at: string;
  metadata: Record<string, unknown>;
  ingested_at: string;
}

export interface EventPage {
  items: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8787";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; service: string; version: string }>("/api/health"),
  events: (filters: { search?: string; severity?: string } = {}) => {
    const params = new URLSearchParams({ limit: "100" });
    if (filters.search) params.set("search", filters.search);
    if (filters.severity) params.set("severity", filters.severity);
    return request<EventPage>(`/api/events?${params.toString()}`);
  },
  createEvent: (event: {
    source: string; event_type: string; severity: Severity; message: string;
    host?: string; metadata?: Record<string, unknown>;
  }) => request<SecurityEvent>("/api/events", {
    method: "POST",
    body: JSON.stringify({ ...event, occurred_at: new Date().toISOString() }),
  }),
};
