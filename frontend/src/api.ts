export type Severity = "low" | "medium" | "high" | "critical";
export interface SecurityEvent {
  id: string; source: string; event_type: string; severity: Severity; message: string;
  host: string | null; occurred_at: string; metadata: Record<string, unknown>; ingested_at: string;
}
export interface EventPage { items: SecurityEvent[]; total: number; limit: number; offset: number; }
export interface NetworkInterface { interface: string; address: string; network: string; prefix_length: number; }
export interface AlertRecord {
  id: string; event_id: string; rule_id: string; title: string; severity: Severity;
  status: "open" | "acknowledged" | "resolved"; description: string; created_at: string; updated_at: string;
}
export interface EditionFeature { id: string; name: string; tier: "normal" | "advanced"; status: "available" | "planned"; description: string; included: boolean; }\nexport interface EditionManifest { edition: "normal" | "advanced"; display_name: string; features: EditionFeature[]; license_enforcement: string; notice: string; }\nexport interface ScanRecord {
  id: string; scan_type: "system" | "network"; status: "queued" | "running" | "completed" | "failed";
  target: string; started_at: string; completed_at: string | null; result: Record<string, unknown> | null; error: string | null;
  progress: Record<string, unknown> | null;
}
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8787";
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init, headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
export const api = {
  alerts: () => request<{ items: AlertRecord[]; total: number }>("/api/alerts?limit=50"),
  updateAlert: (id: string, status: "acknowledged" | "resolved") =>
    request<AlertRecord>(`/api/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  health: () => request<{ status: string; service: string; version: string }>("/api/health"),\n  edition: () => request<EditionManifest>("/api/edition"),
  events: (filters: { search?: string; severity?: string } = {}) => {
    const params = new URLSearchParams({ limit: "100" });
    if (filters.search) params.set("search", filters.search);
    if (filters.severity) params.set("severity", filters.severity);
    return request<EventPage>(`/api/events?${params.toString()}`);
  },
  createEvent: (event: { source: string; event_type: string; severity: Severity; message: string; host?: string; metadata?: Record<string, unknown> }) =>
    request<SecurityEvent>("/api/events", { method: "POST", body: JSON.stringify({ ...event, occurred_at: new Date().toISOString() }) }),
  scans: () => request<{ items: ScanRecord[] }>("/api/scans"),
  scan: (id: string) => request<ScanRecord>(`/api/scans/${encodeURIComponent(id)}`),
  networks: () => request<{ items: NetworkInterface[] }>("/api/scanner/networks"),
  startSystemScan: () => request<{ id: string; status: string }>("/api/scans/system", { method: "POST" }),
  startNetworkScan: (network: string) => request<{ id: string; status: string }>("/api/scans/network", { method: "POST", body: JSON.stringify({ network }) }),
};
