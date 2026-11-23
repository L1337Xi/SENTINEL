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
export interface EditionFeature { id: string; name: string; tier: "normal" | "advanced"; status: "available" | "planned"; description: string; included: boolean; }
export interface EditionManifest { edition: "normal" | "advanced"; display_name: string; features: EditionFeature[]; license_enforcement: string; notice: string; }
export interface RouterProbeResult {
  reachable: boolean; status: string; http_status?: number; final_url: string; title: string;
  vendor_hint?: string; login_form_detected: boolean; form_count?: number; password_fields?: number;
  capabilities: string[]; message: string; security_note?: string;
}
export interface RouterLoginResult {
  session_id: string; authenticated: boolean; vendor_hint: string; title: string;
  expires_in_seconds: number; message: string; transport_warning?: string | null; capabilities: string[];
}
export interface RouterDataTable {
  page_title: string; url: string; headers: string[]; rows: Record<string, string>[];
}
export interface RouterSnapshot {
  authenticated: boolean; vendor_hint: string; collected_at: string; pages_inspected: { title: string; url: string; http_status: number }[];
  tables: RouterDataTable[]; devices: RouterDataTable[]; traffic: RouterDataTable[]; domains: RouterDataTable[];
  capabilities: { device_inventory: boolean; per_device_traffic: boolean; domain_activity: boolean; router_blocking: boolean };
  limitations: string[];
}
export interface ScanRecord {
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
  integrationKeys: () => request<IntegrationKeysStatus>("/api/integrations/keys"),
  saveIntegrationKeys: (keys: { malwarebazaar?: string; virustotal?: string; malwarebytes_client_id?: string; malwarebytes_client_secret?: string; malwarebytes_account_id?: string }) =>
    request<IntegrationKeysStatus>("/api/integrations/keys", { method: "PUT", body: JSON.stringify(keys) }),
  verifyIntegration: (provider: "malwarebazaar" | "virustotal" | "malwarebytes") =>
    request<IntegrationKeysStatus>("/api/integrations/" + provider + "/verify", { method: "POST" }),

  alerts: () => request<{ items: AlertRecord[]; total: number }>("/api/alerts?limit=50"),
  updateAlert: (id: string, status: "acknowledged" | "resolved") =>
    request<AlertRecord>(`/api/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  health: () => request<{ status: string; service: string; version: string }>("/api/health"),
  edition: () => request<EditionManifest>("/api/edition"),
  events: (filters: { search?: string; severity?: string } = {}) => {
    const params = new URLSearchParams({ limit: "100" });
    if (filters.search) params.set("search", filters.search);
    if (filters.severity) params.set("severity", filters.severity);
    return request<EventPage>(`/api/events?${params.toString()}`);
  },
  createEvent: (event: { source: string; event_type: string; severity: Severity; message: string; host?: string; metadata?: Record<string, unknown> }) =>
    request<SecurityEvent>("/api/events", { method: "POST", body: JSON.stringify({ ...event, occurred_at: new Date().toISOString() }) }),
  scans: () => request<{ items: ScanRecord[] }>("/api/scans?limit=100"),
  scan: (id: string) => request<ScanRecord>(`/api/scans/${encodeURIComponent(id)}`),
  deleteScan: (id: string) => request<{ id: string; deleted: boolean }>(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  clearHostScanHistory: () => request<{ deleted: number; message: string }>("/api/scans/system", { method: "DELETE" }),
  networks: () => request<{ items: NetworkInterface[] }>("/api/scanner/networks"),
  probeRouter: (address: string) => request<RouterProbeResult>("/api/network/router/probe", { method: "POST", body: JSON.stringify({ address }) }),
  loginRouter: (address: string, username: string, password: string) => request<RouterLoginResult>("/api/network/router/login", { method: "POST", body: JSON.stringify({ address, username, password }) }),
  routerSnapshot: (sessionId: string) => request<RouterSnapshot>("/api/network/router/" + encodeURIComponent(sessionId) + "/snapshot"),
  disconnectRouter: (sessionId: string) => request<{ disconnected: boolean }>("/api/network/router/" + encodeURIComponent(sessionId), { method: "DELETE" }),
  startSystemScan: () => request<{ id: string; status: string }>("/api/scans/system", { method: "POST" }),
  startNetworkScan: (network: string) => request<{ id: string; status: string }>("/api/scans/network", { method: "POST", body: JSON.stringify({ network }) }),
  investigateFinding: (scanId: string, findingId: string) =>
    request<Record<string, unknown>>(`/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/investigate`, { method: "POST" }),
  respondToFinding: (scanId: string, findingId: string, action: "quarantine" | "delete", confirmation = "") =>
    request<Record<string, unknown>>(`/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/response`, { method: "POST", body: JSON.stringify({ action, confirmation }) }),
  quarantine: () => request<{ items: Record<string, unknown>[] }>("/api/quarantine"),
  restoreQuarantine: (id: string) =>
    request<Record<string, unknown>>(`/api/quarantine/${encodeURIComponent(id)}/restore`, { method: "POST" }),
};

export interface IntegrationProviderState {
  configured: boolean;
  configuration: "configured" | "incomplete_credentials" | "legacy_single_key" | "missing";
  storage: "environment" | "local_file" | "none";
  verification: { status: string; message: string; checked_at?: string; http_status?: number };
}
export interface IntegrationKeysStatus {
  providers: { malwarebazaar: IntegrationProviderState; virustotal: IntegrationProviderState; malwarebytes: IntegrationProviderState };
  storage_note: string;
}
