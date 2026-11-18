import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ArrowRight } from "lucide-react";
import { api, type AlertRecord, type NetworkInterface, type ScanRecord, type SecurityEvent, type Severity, type EditionManifest } from "./api";
import DoodleCrewFooter from "@/components/ui/doodle-crew-footer";

type View = "home" | "overview" | "events" | "alerts" | "host" | "network";
const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
const navItems: { id: View; label: string; code: string }[] = [
  { id: "home", label: "Home", code: "00" },
  { id: "overview", label: "Overview", code: "01" },
  { id: "events", label: "Event stream", code: "02" },
  { id: "alerts", label: "Detection alerts", code: "03" },
  { id: "host", label: "Host assessment", code: "04" },
  { id: "network", label: "Network discovery", code: "05" },
];

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
function bytes(value?: number): string {
  if (value === undefined || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "GB", "TB"];
  let amount = value; let index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function asArray<T>(value: unknown): T[] { return Array.isArray(value) ? value as T[] : []; }
function statusLabel(status: ScanRecord["status"]): string {
  return status === "completed" ? "Complete" : status === "failed" ? "Failed" : status === "running" ? "Running" : "Queued";
}
function downloadJson(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [view, setView] = useState<View>(() => {
    const route = window.location.hash.slice(1);
    return navItems.some((item) => item.id === route) ? route as View : "home";
  });
  const navigate = useCallback((next: View) => {
    setView(next);
    if (window.location.hash !== `#${next}`) window.location.hash = next;
  }, []);
  useEffect(() => {
    const syncRoute = () => {
      const route = window.location.hash.slice(1);
      navigate(navItems.some((item) => item.id === route) ? route as View : "home");
    };
    window.addEventListener("hashchange", syncRoute);
    return () => window.removeEventListener("hashchange", syncRoute);
  }, []);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking");
  const [edition, setEdition] = useState<EditionManifest | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [networks, setNetworks] = useState<NetworkInterface[]>([]);
  const [selectedNetwork, setSelectedNetwork] = useState("");
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [status, page, history, alertPage, editionInfo] = await Promise.all([api.health(), api.events({ search: search.trim(), severity }), api.scans(), api.alerts(), api.edition()]);
      setHealth(status.status === "ok" ? "online" : "offline");
      setEdition(editionInfo);
      setEvents(page.items); setTotal(page.total); setScans(history.items); setAlerts(alertPage.items); setError("");
      setActiveScan((current) => {
        if (current && ["queued", "running"].includes(current.status)) return current;
        return history.items.find((item) => item.scan_type === "system" && ["queued", "running"].includes(item.status)) ?? current;
      });
    } catch (err) {
      setHealth("offline");
      setError(err instanceof Error ? err.message : "Unable to reach the local SENTINEL API.");
    }
  }, [search, severity]);

  const loadNetworks = useCallback(async () => {
    try {
      const response = await api.networks();
      setNetworks(response.items);
      setSelectedNetwork((current) => current || response.items[0]?.network || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read local network interfaces.");
    }
  }, []);

  useEffect(() => { void refresh(); void loadNetworks(); }, [refresh, loadNetworks]);

  useEffect(() => {
    if (!activeScan || !["queued", "running"].includes(activeScan.status)) return;
    const timer = window.setInterval(async () => {
      try {
        const updated = await api.scan(activeScan.id);
        setActiveScan(updated);
        if (updated.status === "completed" || updated.status === "failed") {
          const history = await api.scans();
          setScans(history.items);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to retrieve scan status.");
      }
    }, 1400);
    return () => window.clearInterval(timer);
  }, [activeScan?.id, activeScan?.status]);

  const counts = useMemo(() => ({
    critical: events.filter((event) => event.severity === "critical").length,
    high: events.filter((event) => event.severity === "high").length,
    medium: events.filter((event) => event.severity === "medium").length,
    low: events.filter((event) => event.severity === "low").length,
  }), [events]);

  async function startScan(kind: "system" | "network") {
    setBusy(true); setError("");
    try {
      const started = kind === "system" ? await api.startSystemScan() : await api.startNetworkScan(selectedNetwork);
      const scan = await api.scan(started.id);
      setActiveScan(scan);
      navigate(kind === "system" ? "host" : "network");
      const history = await api.scans(); setScans(history.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The scan could not be started.");
    } finally { setBusy(false); }
  }

  async function deleteHostScan(id: string) {
    if (!window.confirm("Delete this host assessment result? This permanently removes the saved scan record, but does not change files on the machine or delete network scans, alerts, or cases.")) return;
    setError("");
    try {
      await api.deleteScan(id);
      const history = await api.scans();
      setScans(history.items);
      setActiveScan((current) => current?.id === id
        ? history.items.find((item) => item.scan_type === "system") ?? null
        : current);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the host assessment result.");
    }
  }

  async function clearHostScanHistory() {
    const completedCount = scans.filter((item) => item.scan_type === "system" && ["completed", "failed"].includes(item.status)).length;
    if (!completedCount) return;
    if (!window.confirm("Delete all completed/failed host assessment results? Active scans, network scans, alerts, and cases will be kept. This cannot be undone.")) return;
    setError("");
    try {
      await api.clearHostScanHistory();
      const history = await api.scans();
      setScans(history.items);
      setActiveScan((current) => current && ["queued", "running"].includes(current.status)
        ? current
        : history.items.find((item) => item.scan_type === "system") ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not clear host assessment history.");
    }
  }

  async function changeAlertStatus(id: string, status: "acknowledged" | "resolved") {
    try {
      await api.updateAlert(id, status);
      const result = await api.alerts();
      setAlerts(result.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update alert status.");
    }
  }

  async function addSample() {
    setBusy(true);
    try {
      await api.createEvent({
        source: "sentinel-demo", event_type: "authentication", severity: "medium",
        message: "Sample event: repeated authentication failures detected",
        host: "lab-workstation", metadata: { sample: true, attempts: 5 },
      });
      await refresh();
    } catch (err) { setError(err instanceof Error ? err.message : "Could not create sample event."); }
    finally { setBusy(false); }
  }

  if (view === "home") return <Landing health={health} onEnter={() => navigate("overview")} onOpen={navigate} />;

  const currentTitle = navItems.find((item) => item.id === view)?.label ?? "Overview";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="wordmark" onClick={() => navigate("overview")} aria-label="SENTINEL home">
          <span><strong>SENTINEL</strong><small>SECURITY OPERATIONS</small></span>
        </button>
        <div className="side-caption">CONSOLE</div>
        <nav className="side-nav" aria-label="Primary navigation">
          {navItems.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? "selected" : ""}`} onClick={() => navigate(item.id)}>
            <span className="nav-code">{item.code}</span><span>{item.label}</span>{view === item.id && <span className="nav-indicator" />}
          </button>)}
        </nav>
        <div className="side-bottom">
          <div className="instance-card"><span className={`status-dot ${health}`} /><div><strong>LOCAL INSTANCE</strong><small>{health === "online" ? "API connected" : health === "checking" ? "Checking connection" : "API unavailable"}</small></div></div>
          <div className="side-version"><span>BUILD 0.3.0</span><span>LOCAL ONLY</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="crumb"><span>CONSOLE</span><b>/</b>{currentTitle.toUpperCase()}</div>
          <div className="topbar-right"><span className={`edition-chip ${edition?.edition ?? "normal"}`}>{edition?.display_name ?? "SENTINEL Normal"}</span><span className="environment"><i /> PRIVATE WORKSTATION</span><span className="top-divider" /><span className="api-state"><i className={health} />{health === "online" ? "CONNECTED" : health.toUpperCase()}</span></div>
        </header>

        {error && <div className="error-banner"><span className="error-mark">!</span><div><strong>Operation notice</strong><small>{error}</small></div><button onClick={() => void refresh()}>RETRY</button><button className="dismiss" onClick={() => setError("")} aria-label="Dismiss notice">×</button></div>}

        {view === "overview" && <Overview events={events} total={total} counts={counts} scans={scans} busy={busy} health={health} onNavigate={navigate} onStart={startScan} onAddSample={addSample} />}
        {view === "events" && <EventsView events={events} total={total} search={search} severity={severity} setSearch={setSearch} setSeverity={setSeverity} onRefresh={() => void refresh()} />}
        {view === "alerts" && <AlertsView alerts={alerts} onChangeStatus={changeAlertStatus} onRefresh={() => void refresh()} />}
        {view === "host" && <HostView scan={activeScan?.scan_type === "system" ? activeScan : scans.find((scan) => scan.scan_type === "system") ?? null} scans={scans} busy={busy} onStart={() => void startScan("system")} onDeleteScan={(id) => void deleteHostScan(id)} onClearHistory={() => void clearHostScanHistory()} />}
        {view === "network" && <NetworkView networks={networks} selected={selectedNetwork} setSelected={setSelectedNetwork} scan={activeScan?.scan_type === "network" ? activeScan : scans.find((scan) => scan.scan_type === "network") ?? null} scans={scans} busy={busy} onStart={() => void startScan("network")} onReload={() => void loadNetworks()} />}
      </main>
    </div>
  );
}

function Landing({ health, onEnter, onOpen }: { health: "checking" | "online" | "offline"; onEnter: () => void; onOpen: (view: View) => void }) {
  const sections = navItems.filter((item) => item.id !== "home");
  return (
    <div className="landing">
      <DoodleCrewFooter className="dcf-top landing-hero" backToTop={false} />
      <section className="landing-console">
        <div className="landing-console-head">
          <div>
            <span className="eyebrow">SECURITY OPERATIONS CONSOLE</span>
            <h2>Analyst workspace</h2>
            <p>Event intake, triage, host assessment and scoped discovery — served from this machine only. No cloud, no telemetry, no invented findings.</p>
          </div>
          <button className="button button-primary landing-enter" onClick={onEnter}>Enter console <ArrowRight size={15} /></button>
        </div>
        <div className="landing-sections">
          {sections.map((item) => (
            <button key={item.id} className="landing-section" onClick={() => onOpen(item.id)}>
              <span className="nav-code">{item.code}</span>
              <span>{item.label}</span>
              <ArrowRight size={13} />
            </button>
          ))}
        </div>
        <div className="landing-state"><i className={health} />{health === "online" ? "Local API connected" : health === "checking" ? "Checking local API" : "Local API offline — start the backend to load live data"}</div>
      </section>
    </div>
  );
}

function PageHeading({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</div>;
}
function ActionButton({ children, onClick, disabled = false, secondary = false }: { children: ReactNode; onClick: () => void; disabled?: boolean; secondary?: boolean }) {
  return <button className={secondary ? "button button-secondary" : "button button-primary"} onClick={onClick} disabled={disabled}>{children}</button>;
}
function Overview({ events, total, counts, scans, busy, health, onNavigate, onStart, onAddSample }: {
  events: SecurityEvent[]; total: number; counts: { critical: number; high: number; medium: number; low: number };
  scans: ScanRecord[]; busy: boolean; health: string; onNavigate: (view: View) => void;
  onStart: (kind: "system" | "network") => void; onAddSample: () => void;
}) {
  const latest = scans[0];
  return <>
    <PageHeading eyebrow="SECURITY OPERATIONS / COMMAND" title="Operations overview" description="A consolidated view of local telemetry, host posture and network activity.">
      <ActionButton onClick={() => onStart("system")} disabled={busy || health !== "online"}>Run host assessment <span>↗</span></ActionButton>
    </PageHeading>
    <section className="summary-grid">
      <article className="summary-card"><div className="card-kicker">EVENTS INGESTED</div><div className="summary-value">{total.toLocaleString()}</div><div className="summary-foot">Current event query</div><span className="card-index">01</span></article>
      <article className="summary-card"><div className="card-kicker">CRITICAL FINDINGS</div><div className="summary-value crimson">{counts.critical.toLocaleString()}</div><div className="summary-foot">In loaded event set</div><span className="card-index">02</span></article>
      <article className="summary-card"><div className="card-kicker">HIGH SEVERITY</div><div className="summary-value">{counts.high.toLocaleString()}</div><div className="summary-foot">In loaded event set</div><span className="card-index">03</span></article>
      <article className="summary-card"><div className="card-kicker">LOCAL SCANS</div><div className="summary-value">{scans.length.toLocaleString()}</div><div className="summary-foot">Recorded scan jobs</div><span className="card-index">04</span></article>
    </section>

    <section className="section-block">
      <div className="section-head"><div><div className="eyebrow">ASSESSMENT TOOLS</div><h2>Local security assessments</h2></div><span className="section-note">EXECUTED ON THIS MACHINE</span></div>
      <div className="tool-grid">
        <article className="tool-card">
          <div className="tool-top"><span className="tool-number">A / 01</span><span className="tool-tag">READ-ONLY</span></div>
          <div className="tool-icon host-icon"><span>H</span></div>
          <h3>Host assessment</h3>
          <p>Collect operating-system details, hardware resources, network interfaces, running process metadata and listening services.</p>
          <div className="tool-meta"><span>LOCAL HOST</span><span>NO FILE MODIFICATION</span></div>
          <ActionButton onClick={() => onStart("system")} disabled={busy || health !== "online"}>Start host assessment <span>→</span></ActionButton>
        </article>
        <article className="tool-card">
          <div className="tool-top"><span className="tool-number">A / 02</span><span className="tool-tag">SCOPED TCP</span></div>
          <div className="tool-icon network-icon"><span>N</span></div>
          <h3>Network discovery</h3>
          <p>Discover responsive devices on a private subnet attached to an active interface, using a fixed list of common TCP ports.</p>
          <div className="tool-meta"><span>LOCAL PRIVATE SUBNET</span><span>NO EXPLOITATION</span></div>
          <ActionButton secondary onClick={() => onNavigate("network")}>Configure network scan <span>→</span></ActionButton>
        </article>
      </div>
      <div className="scope-note"><span className="scope-mark">i</span><p><strong>Scope and limitations.</strong> Host assessment is read-only inventory, not a full disk malware scan. Network discovery checks a limited set of TCP services; it is not a vulnerability assessment. Only scan systems and networks you own or are authorised to assess.</p></div>
    </section>

    <section className="section-block overview-lower">
      <div className="panel event-panel">
        <div className="panel-title"><div><div className="eyebrow">TELEMETRY</div><h2>Recent events</h2></div><button className="text-action" onClick={() => onNavigate("events")}>VIEW EVENT STREAM ↗</button></div>
        <EventTable events={events.slice(0, 6)} />
        {events.length === 0 && <div className="empty-state">No telemetry has been ingested yet.</div>}
        <div className="panel-bottom"><span>{events.length} events loaded</span><button onClick={onAddSample} disabled={busy}>INSERT TEST EVENT</button></div>
      </div>
      <div className="panel activity-panel">
        <div className="panel-title"><div><div className="eyebrow">ACTIVITY</div><h2>Latest scan</h2></div><span className="live-label">LOCAL</span></div>
        {latest ? <div className="latest-scan"><div className="latest-type">{latest.scan_type === "system" ? "HOST ASSESSMENT" : "NETWORK DISCOVERY"}</div><strong>{latest.target}</strong><div className="scan-state-row"><span className={`scan-state ${latest.status}`}>{statusLabel(latest.status)}</span><time>{formatDate(latest.started_at)}</time></div><button className="text-action" onClick={() => onNavigate(latest.scan_type === "system" ? "host" : "network")}>OPEN RESULTS ↗</button></div> : <div className="empty-state compact">No scan jobs recorded.<br />Start an assessment to see results here.</div>}
      </div>
    </section>
  </>;
}

function AlertsView({ alerts, onChangeStatus, onRefresh }: {
  alerts: AlertRecord[];
  onChangeStatus: (id: string, status: "acknowledged" | "resolved") => void;
  onRefresh: () => void;
}) {
  const openCount = alerts.filter((alert) => alert.status === "open").length;
  const acknowledgedCount = alerts.filter((alert) => alert.status === "acknowledged").length;
  return <>
    <PageHeading eyebrow="DETECTION / ALERT MANAGEMENT" title="Detection alerts" description="Review rule matches generated from ingested security events.">
      <ActionButton secondary onClick={onRefresh}>↻ Refresh alerts</ActionButton>
    </PageHeading>
    <section className="summary-grid alert-summary">
      <article className="summary-card"><div className="card-kicker">OPEN ALERTS</div><div className="summary-value crimson">{openCount}</div><div className="summary-foot">Require triage</div></article>
      <article className="summary-card"><div className="card-kicker">ACKNOWLEDGED</div><div className="summary-value">{acknowledgedCount}</div><div className="summary-foot">Under investigation</div></article>
      <article className="summary-card"><div className="card-kicker">TOTAL MATCHES</div><div className="summary-value">{alerts.length}</div><div className="summary-foot">Latest 50 alerts</div></article>
    </section>
    <section className="panel full-panel">
      <div className="panel-title"><div><div className="eyebrow">RULE ENGINE / MATCHES</div><h2>Alert queue</h2></div><span className="section-note">DETERMINISTIC RULES</span></div>
      {alerts.length === 0 ? <div className="empty-state">No detection alerts yet. Ingest an event matching an enabled rule to populate this queue.</div> :
        <div className="alert-list">{alerts.map((alert) => <article className="alert-row" key={alert.id}>
          <div className="alert-main"><div className="alert-meta"><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span><span className={`alert-status ${alert.status}`}>{alert.status}</span><span className="alert-rule">{alert.rule_id}</span></div><h3>{alert.title}</h3><p>{alert.description}</p><small>Event {alert.event_id.slice(0, 8)} · Created {formatDate(alert.created_at)}</small></div>
          <div className="alert-actions">{alert.status === "open" && <button className="button button-secondary" onClick={() => onChangeStatus(alert.id, "acknowledged")}>Acknowledge</button>}{alert.status !== "resolved" && <button className="button button-secondary" onClick={() => onChangeStatus(alert.id, "resolved")}>Resolve</button>}</div>
        </article>)}</div>}
      <div className="panel-bottom"><span>Rule matches are stored locally and linked to their source event.</span><span>ALERTS / SQLITE</span></div>
    </section>
  </>;
}

function EventsView({ events, total, search, severity, setSearch, setSeverity, onRefresh }: {
  events: SecurityEvent[]; total: number; search: string; severity: string;
  setSearch: (value: string) => void; setSeverity: (value: string) => void; onRefresh: () => void;
}) {
  return <>
    <PageHeading eyebrow="TELEMETRY / EVENT MANAGEMENT" title="Event stream" description="Search and review security events stored in the local SENTINEL database.">
      <ActionButton secondary onClick={onRefresh}>↻ Refresh data</ActionButton>
    </PageHeading>
    <section className="panel full-panel">
      <div className="filter-bar"><label className="search-field"><span>⌕</span><input aria-label="Search events" placeholder="Search message, source, host…" value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{severityOrder.map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><span className="result-count">{total} RECORDS</span></div>
      <EventTable events={events} />
      {events.length === 0 && <div className="empty-state">No events match the current filters.</div>}
      <div className="panel-bottom"><span>Showing {events.length} of {total} records · latest 100</span><span>SQLITE / LOCAL STORAGE</span></div>
    </section>
  </>;
}
function EventTable({ events }: { events: SecurityEvent[] }) {
  return <div className="table-scroll"><table className="data-table"><thead><tr><th>SEVERITY</th><th>EVENT DESCRIPTION</th><th>SOURCE</th><th>HOST</th><th>OBSERVED</th></tr></thead><tbody>
    {events.map((event) => <tr key={event.id}><td><span className={`severity-badge ${event.severity}`}>{event.severity}</span></td><td><strong>{event.message}</strong><small>{event.event_type}</small></td><td>{event.source}</td><td>{event.host ?? "—"}</td><td className="date-cell">{formatDate(event.occurred_at)}</td></tr>)}
  </tbody></table></div>;
}

function ScanHeader({ scan }: { scan: ScanRecord | null }) {
  if (!scan) return <div className="scan-placeholder">No assessment results are available. Start a scan to collect local inventory.</div>;
  return <div className="scan-summary"><div><span className="eyebrow">SCAN JOB / {scan.id.slice(0, 8).toUpperCase()}</span><strong>{scan.target}</strong><small>Started {formatDate(scan.started_at)}{scan.completed_at ? ` · Completed ${formatDate(scan.completed_at)}` : ""}</small></div><span className={`scan-state ${scan.status}`}>{statusLabel(scan.status)}</span></div>;
}
function HostView({ scan, scans, busy, onStart, onDeleteScan, onClearHistory }: {
  scan: ScanRecord | null; scans: ScanRecord[]; busy: boolean; onStart: () => void;
  onDeleteScan: (id: string) => void; onClearHistory: () => void;
}) {
  const hostScans = scans.filter((item) => item.scan_type === "system");
  const deletableHostScans = hostScans.filter((item) => item.status === "completed" || item.status === "failed");
  const result = asObject(scan?.result);
  const memory = asObject(result.memory); const disk = asObject(result.disk);
  const interfaces = asArray<{name?: string; address?: string; netmask?: string}>(result.interfaces);
  const processes = asArray<{pid?: number; name?: string; user?: string; status?: string}>(result.processes);
  const listeners = asArray<{process?: string; address?: string; port?: number | string; pid?: number | string}>(result.listening_services);
  const localNetworks = asArray<{interface?: string; network?: string; address?: string}>(result.local_networks);
  const done = scan?.status === "completed";
  const assessment = asObject(result.security_assessment);
  const assessmentSummary = asObject(assessment.summary);
  const liveProgress = asObject(scan?.progress);
  const isAssessing = scan?.scan_type === "system" && (scan.status === "queued" || scan.status === "running");
  const progressPhase = String(liveProgress.phase ?? "starting").replace(/_/g, " ");
  const findings = asArray<Record<string, unknown>>(assessment.findings);
  const capabilities = asArray<Record<string, unknown>>(assessment.script_capabilities);
  const malwareFindings = findings.filter((finding) => finding.category === "malware");
  const malwareEngines = asObject(assessment.malware_engines);
  const clamav = asObject(malwareEngines.clamav);
  const threatIntel = asObject(assessment.threat_intelligence);
  const malwareBazaar = asObject(threatIntel.malwarebazaar);
  const circlIntel = asObject(threatIntel.circl_hashlookup);
  const knownFileContext = asArray<Record<string, unknown>>(threatIntel.known_file_context);
  const persistence = asArray<Record<string, unknown>>(assessment.persistence_inventory);
  const privilegedAccounts = asObject(assessment.privileged_accounts);
  const uidZeroAccounts = asArray<Record<string, unknown>>(privilegedAccounts.uid_zero_accounts);
  const privilegedGroups = asArray<Record<string, unknown>>(privilegedAccounts.privileged_groups);
  const [investigations, setInvestigations] = useState<Record<string, Record<string, unknown>>>({});
  const [responseMessages, setResponseMessages] = useState<Record<string, string>>({});
  const [quarantineItems, setQuarantineItems] = useState<Record<string, unknown>[]>([]);
  const [responseBusy, setResponseBusy] = useState<string | null>(null);
  useEffect(() => { void api.quarantine().then((data) => setQuarantineItems(data.items)).catch(() => setQuarantineItems([])); }, [scan?.id]);
  const investigateFinding = async (finding: Record<string, unknown>) => {
    if (!scan?.id) return;
    const id = String(finding.id);
    setResponseBusy(id); setResponseMessages((current) => ({ ...current, [id]: "" }));
    try {
      const report = await api.investigateFinding(scan.id, id);
      setInvestigations((current) => ({ ...current, [id]: report }));
    } catch (error) { setResponseMessages((current) => ({ ...current, [id]: error instanceof Error ? error.message : "Investigation failed." })); }
    finally { setResponseBusy(null); }
  };
  const respondFinding = async (finding: Record<string, unknown>, action: "quarantine" | "delete") => {
    if (!scan?.id) return;
    const id = String(finding.id); const digest = String(finding.sha256 ?? "");
    let confirmation = "";
    if (action === "quarantine") {
      if (!window.confirm("Move this file into SENTINEL quarantine? The original path will be removed after the quarantine copy is verified.")) return;
    } else {
      confirmation = window.prompt(`Permanent deletion cannot be undone. Type exactly: DELETE ${digest}`) ?? "";
      if (!confirmation) return;
    }
    setResponseBusy(id);
    try {
      const result = await api.respondToFinding(scan.id, id, action, confirmation);
      setResponseMessages((current) => ({ ...current, [id]: action === "quarantine" ? `Quarantined · ID ${String(result.id)}` : "Permanently deleted." }));
      const data = await api.quarantine(); setQuarantineItems(data.items);
    } catch (error) { setResponseMessages((current) => ({ ...current, [id]: error instanceof Error ? error.message : "Response action failed." })); }
    finally { setResponseBusy(null); }
  };
  const restoreItem = async (item: Record<string, unknown>) => {
    const id = String(item.id); if (!window.confirm(`Restore quarantined file to ${String(item.original_path)}?`)) return;
    setResponseBusy(id);
    try { await api.restoreQuarantine(id); const data = await api.quarantine(); setQuarantineItems(data.items); }
    catch (error) { setResponseMessages((current) => ({ ...current, [id]: error instanceof Error ? error.message : "Restore failed." })); }
    finally { setResponseBusy(null); }
  };

  const processRows = processes.map((item) => (
    <div className="simple-row" key={String(item.pid)}>
      <strong>{String(item.name)}</strong>
      <span>PID {String(item.pid)}</span>
      <small>{String(item.user ?? "—")} · {String(item.status ?? "—")}</small>
    </div>
  ));

  return <>
    <PageHeading eyebrow="ASSESSMENT / LOCAL HOST" title="Host assessment" description="Read-only inventory of the machine running the SENTINEL backend.">
      <ActionButton onClick={onStart} disabled={busy}>↻ Run assessment</ActionButton>
    </PageHeading>
    <div className="scope-note host-scope"><span className="scope-mark">i</span><p>This performs a bounded, read-only local assessment: host inventory, SHA-256 file hashing against local indicators and optional MalwareBazaar/CIRCL hash intelligence, static script-pattern review and selected security-configuration checks. CIRCL lookups send only SHA-256 hashes; the MalwareBazaar integration retrieves feed metadata. File contents and local paths are never uploaded. Suspicious files are never executed, changed or quarantined. File-count, size and time limits apply; a clean result does not prove the system is malware-free.</p></div>
    <section className="panel full-panel scan-panel"><div className="panel-title"><div><div className="eyebrow">ASSESSMENT STATUS</div><h2>Latest host inventory</h2></div><span className="section-note">{hostScans.length} TOTAL RUNS</span></div><ScanHeader scan={scan} />
      <section className="host-history" aria-label="Previous host assessment results">
        <div className="result-heading"><div><h3>Previous scan history</h3><span>{hostScans.length} SAVED RESULTS</span></div>
          <button className="button button-danger" onClick={onClearHistory} disabled={deletableHostScans.length === 0}>Clear completed history</button>
        </div>
        {hostScans.length === 0 ? <div className="empty-state">No previous host assessment results.</div> : hostScans.map((item) => (
          <div className="host-history-row" key={item.id}>
            <div className="host-history-info"><strong>{item.target}</strong><small>{formatDate(item.started_at)} · {statusLabel(item.status)}</small></div>
            {item.status === "running" || item.status === "queued"
              ? <span className="history-protected">ACTIVE</span>
              : <button className="text-action history-delete" onClick={() => onDeleteScan(item.id)} aria-label={`Delete host scan from ${formatDate(item.started_at)}`}>DELETE RESULT</button>}
          </div>
        ))}
        <p className="history-note">Deleting a result removes only its saved host scan record. It does not modify scanned files or affect network scans, alerts, cases, or evidence.</p>
      </section>
      {isAssessing && <section className="live-assessment" aria-live="polite">
        <div className="result-heading"><h3>Live assessment activity</h3><span className="scan-state running">{progressPhase.toUpperCase()}</span></div>
        <div className="resource-grid">
          <Resource label="FILES VISITED" value={String(liveProgress.files_seen ?? 0)} detail={`${String(liveProgress.files_hashed ?? 0)} successfully hashed`} />
          <Resource label="MALWARE MATCHES" value={String(liveProgress.malware_matches ?? 0)} detail="Local hash matches so far · ClamAV reports after its pass" />
          <Resource label="SCRIPT INDICATORS" value={String(liveProgress.script_indicators ?? 0)} detail="Static indicators; not confirmed malware" />
          <Resource label="ELAPSED" value={`${Number(liveProgress.elapsed_seconds ?? 0).toFixed(1)} s`} detail={`Filesystem budget remaining: ${Number(liveProgress.time_budget_remaining ?? 180).toFixed(1)} s`} />
        </div>
        <div className="live-progress-track" role="progressbar" aria-label="Assessment activity" aria-valuetext={progressPhase}>
          <span className="live-progress-indicator" />
        </div>
        {progressPhase === "clamav" && <Resource label="CLAMAV FILES SCANNED" value={String(liveProgress.clamav_files_scanned ?? 0)} detail="Files reported by ClamAV as its scan runs" />}
        <div className="live-current"><span className="meta-label">{progressPhase === "clamav" ? "CLAMAV CURRENT FILE" : "CURRENT FILE / LOCATION"}</span><code>{String(liveProgress.current_path ?? (progressPhase === "clamav" ? "Waiting for ClamAV to report its first file…" : progressPhase === "threat intelligence" ? "Checking optional hash intelligence providers…" : "Preparing assessment…"))}</code></div>
        <p className="live-note">Updates are polled from the local scanner. The filesystem time remaining is a scan budget, not a guaranteed completion ETA. ClamAV progress is streamed from its local scan output; the file count reflects reported results.</p>
      </section>}
      {scan?.status === "failed" && <div className="scan-error">{scan.error ?? "The assessment failed."}</div>}
      {done && <div className="host-results">
        <div className="host-identity"><div className="host-initial">H</div><div><strong>{String(result.hostname ?? "Unknown host")}</strong><small>{String(result.operating_system ?? "Operating system unavailable")}</small></div></div>

        <div className="host-meta-grid">
          <div className="meta-card"><span className="meta-label">KERNEL</span><strong>{String(result.kernel ?? "—")}</strong></div>
          <div className="meta-card"><span className="meta-label">ARCHITECTURE</span><strong>{String(result.architecture ?? "—")}</strong></div>
          <div className="meta-card"><span className="meta-label">PROCESSOR</span><strong>{String(result.processor ?? "Not reported")}</strong></div>
          <div className="meta-card"><span className="meta-label">COLLECTED</span><strong>{formatDate(result.collected_at as string)}</strong></div>
        </div>

        <div className="resource-grid">
          <Resource label="CPU CORES" value={String(result.cpu_cores ?? "—")} detail={`${String(result.logical_processors ?? "—")} logical processors`} />
          <Resource label="MEMORY" value={bytes(Number(memory.total_bytes))} detail={`Used ${String(memory.used_percent ?? "—")}% · Avail ${bytes(Number(memory.available_bytes))}`} />
          <Resource label="ROOT DISK" value={bytes(Number(disk.total_bytes))} detail={`Used ${String(disk.used_percent ?? "—")}% · Free ${bytes(Number(disk.free_bytes))}`} />
          <Resource label="PROCESSES" value={String(result.process_count ?? "—")} detail={result.processes_truncated ? "First 100 displayed" : "All visible"} />
        </div>

        <div className="result-section"><div className="result-heading"><h3>Network interfaces</h3><span>{interfaces.length} INTERFACES</span></div><div className="simple-table">{interfaces.map((item, index) => <div className="simple-row" key={index}><strong>{String(item.name)}</strong><span>{String(item.address)}</span><small>{String(item.netmask ?? "—")}</small></div>)}</div></div>

        {localNetworks.length > 0 && <div className="result-section"><div className="result-heading"><h3>Local private networks</h3><span>{localNetworks.length} NETWORKS</span></div><div className="simple-table">{localNetworks.map((item, index) => <div className="simple-row" key={index}><strong>{String(item.interface)}</strong><span>{String(item.network)}</span><small>{String(item.address)}</small></div>)}</div></div>}

        <div className="result-section"><div className="result-heading"><h3>Listening services</h3><span>{listeners.length} SOCKETS</span></div><div className="simple-table">{listeners.length === 0 ? (<div className="empty-state">No listening services were visible to the scanner.</div>) : (listeners.map((item, index) => <div className="simple-row" key={index}><strong>{String(item.process ?? "Unknown process")}</strong><span>{String(item.address)}:{String(item.port)}</span><small>PID {String(item.pid ?? "—")}</small></div>))}</div></div>

        <div className="result-section"><div className="result-heading"><h3>Process inventory</h3><span>{processes.length} DISPLAYED / {String(result.process_count ?? "—")} TOTAL</span></div><div className="simple-table process-list">{processes.length === 0 ? <div className="empty-state">No processes were visible to the scanner.</div> : processRows}</div></div>

        {assessmentSummary.files_hashed !== undefined && <div className="result-section">
          <div className="result-heading"><h3>Security assessment report</h3><button className="button button-secondary" onClick={() => downloadJson(`sentinel-host-report-${scan?.id ?? "latest"}.json`, { scan, security_assessment: assessment })}>Export JSON report ↓</button></div>
          <div className="resource-grid">
            <Resource label="FILES HASHED" value={String(assessmentSummary.files_hashed ?? 0)} detail={`${String(assessmentSummary.files_seen ?? 0)} files visited`} />
            <Resource label="MALWARE MATCHES" value={String(assessmentSummary.malware_matches ?? 0)} detail="Exact local and MalwareBazaar hash matches" />
            <Resource label="CONFIG FINDINGS" value={String(assessmentSummary.configuration_findings ?? 0)} detail="Review required; not all are vulnerabilities" />
            <Resource label="SCAN STATUS" value={assessmentSummary.truncated ? "LIMIT REACHED" : "COMPLETED"} detail={assessmentSummary.truncated ? "File or time budget reached" : "Configured scan scope completed"} />
            <Resource label="CLAMAV ENGINE" value={clamav.executed ? "EXECUTED" : clamav.available ? "AVAILABLE" : "NOT INSTALLED"} detail={String(clamav.version ?? clamav.note ?? "No local engine detected")} />
            <Resource label="MALWAREBAZAAR" value={malwareBazaar.status === "ok" ? (malwareBazaar.cached ? "CACHED FEED" : "LIVE FEED") : malwareBazaar.status === "stale" ? "STALE CACHE" : malwareBazaar.status === "unavailable" ? "UNAVAILABLE" : "NOT CONFIGURED"} detail={malwareBazaar.status === "ok" || malwareBazaar.status === "stale" ? `${String(malwareBazaar.records_received ?? 0)} recent hashes · ${malwareBazaar.cache_age_seconds === undefined ? "just refreshed" : `${String(malwareBazaar.cache_age_seconds)}s cache age`}` : String(malwareBazaar.note ?? "Optional live malware hash feed")} />
            <Resource label="CIRCL HASHLOOKUP" value={circlIntel.status === "ok" ? `${String(circlIntel.known_file_matches ?? 0)} KNOWN FILES` : String(circlIntel.status ?? "NOT RUN").toUpperCase()} detail={`${String(circlIntel.lookups_performed ?? 0)} remote lookups · ${String(circlIntel.cache_hits ?? 0)} cache hits · context only`} />
          </div>
          {knownFileContext.length > 0 && <div className="result-section">
            <div className="result-heading"><h3>Known-file context · CIRCL</h3><span>{knownFileContext.length} HASH MATCHES</span></div>
            <p className="history-note">Reference-database matches provide file context only. They are not malware detections and do not prove a file is safe. CIRCL trust is a database aggregation score, not a safety rating.</p>
            <div className="simple-table inventory-list">{knownFileContext.map((item, index) => <div className="simple-row" key={String(item.sha256) + index} style={{gridTemplateColumns:"1fr auto"}}>
              <strong>{String(item.file_name || "Known file")}</strong><small>{String(item.product_name || item.source || item.database || "Reference database")} · trust {String(item.trust ?? "not supplied")}</small>
              <span>{asArray<string>(item.paths).join(", ")}</span>
            </div>)}</div>
          </div>}
          <AssessmentFindingCharts findings={findings} capabilities={capabilities} />
          <div className="result-section">
            <div className="result-heading"><h3>Persistence inventory</h3><span>{persistence.length} STARTUP ENTRIES</span></div>
            <div className="simple-table inventory-list">{persistence.length === 0 ? <div className="empty-state">No entries were visible in the inspected startup locations.</div> : persistence.map((item, index) => <div className="simple-row" key={String(item.path) + index} style={{gridTemplateColumns:"1fr auto"}}>
              <strong>{String(item.path)}</strong><small>{String(item.category)} · {String(item.type)}</small>
            </div>)}</div>
          </div>
          <div className="result-section">
            <div className="result-heading"><h3>Privileged account review</h3><span>{uidZeroAccounts.length} UID 0 ACCOUNTS</span></div>
            <div className="simple-table">
              {uidZeroAccounts.map((item, index) => <div className="simple-row" key={String(item.username) + index} style={{gridTemplateColumns:"1fr 1fr"}}>
                <strong>{String(item.username)}</strong><span>UID {String(item.uid)}</span><small>{String(item.shell)}</small>
              </div>)}
              {privilegedGroups.map((item, index) => <div className="simple-row" key={String(item.group) + index} style={{gridTemplateColumns:"1fr 1fr"}}>
                <strong>{String(item.group)} group</strong><span>{asArray<string>(item.members).join(", ") || "No supplementary members listed"}</span>
              </div>)}
              {uidZeroAccounts.length === 0 && privilegedGroups.length === 0 && <div className="empty-state">Account details were unavailable.</div>}
            </div>
            <div className="scope-note"><span className="scope-mark">i</span><p>UID 0 and administrative group membership are inventory items for analyst review, not automatic proof of compromise.</p></div>
          </div>
          {malwareFindings.length > 0 && <div className="result-section">
            <div className="result-heading"><h3>Malware capability analysis</h3><span>STATIC EVIDENCE ONLY</span></div>
            {malwareFindings.map((finding, index) => {
              const mapped = asArray<Record<string, unknown>>(finding.capabilities);
              const inferred = capabilities.filter((item) => item.path === finding.path);
              const labels = [...mapped, ...inferred];
              const findingId = String(finding.id ?? index);
              const investigation = asObject(investigations[findingId]);
              const packageInfo = asObject(investigation.package);
              const assessmentInfo = asObject(investigation.assessment);
              const hasInvestigation = Boolean(investigation.assessment);
              const isPackageManaged = packageInfo.owned === true;
              return <div className="capability-report" key={findingId}>
                <div className="capability-flow">
                  <div className="flow-node"><small>FILE / SAMPLE</small><strong>{String(finding.title ?? "Detected file")}</strong><span>{String(finding.path ?? "Path unavailable")}</span></div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node"><small>DETECTION</small><strong>{String(finding.source ?? "Local detection")}</strong><span>{String(finding.confidence ?? "unknown")} confidence</span></div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node"><small>CAPABILITY EVIDENCE</small><strong>{labels.length ? labels.map((item) => String(item.label ?? item.id ?? "Indicator")).join(", ") : "Not established"}</strong><span>{labels.length ? "Static indicators; not runtime proof" : "No capability metadata available for this detection"}</span></div>
                </div>
                {typeof finding.sha256 === "string" && <small className="hash-line">SHA-256 · {finding.sha256}</small>}
                <div className="finding-response-actions">
                  <button className="button button-secondary" onClick={() => void investigateFinding(finding)} disabled={responseBusy === findingId}>{responseBusy === findingId ? "Investigating…" : investigation.assessment ? "Re-investigate file" : "Investigate file"}</button>
                  {hasInvestigation && <span className="history-protected">{String(assessmentInfo.verdict ?? "unverified").replace(/_/g, " ").toUpperCase()} · {String(assessmentInfo.confidence ?? "unknown")} CONFIDENCE</span>}
                  <button className="button button-danger" onClick={() => void respondFinding(finding, "quarantine")} disabled={responseBusy === findingId || isPackageManaged || !finding.sha256}>Quarantine</button>
                  <button className="text-action history-delete" onClick={() => void respondFinding(finding, "delete")} disabled={responseBusy === findingId || isPackageManaged || !finding.sha256}>Delete permanently</button>
                </div>
                {hasInvestigation && <div className="scope-note"><span className="scope-mark">i</span><p>{String(assessmentInfo.rationale ?? "")} {isPackageManaged ? `Package: ${String(packageInfo.package)} · Integrity: ${String(packageInfo.integrity)} · Provenance: ${String(packageInfo.provenance)}` : "No owning package was confirmed."} File type: {String(investigation.file_type ?? "unknown")}.</p></div>}
                {responseMessages[findingId] && <p className="history-note">{responseMessages[findingId]}</p>}
                {isPackageManaged && <p className="history-note">Package-managed file: SENTINEL disables quarantine and permanent deletion. Use the OS package manager after investigation.</p>}
              </div>;
            })}
            <div className="scope-note"><span className="scope-mark">i</span><p>Flow nodes distinguish a detection from its possible capabilities. Capabilities come only from local indicator metadata or low-confidence script-pattern matches; SENTINEL does not execute malware, so runtime behaviour is not verified.</p></div>
          </div>}
          <div className="result-section">
            <div className="result-heading"><h3>Quarantine</h3><span>{quarantineItems.length} STORED ITEMS</span></div>
            {quarantineItems.length === 0 ? <p className="history-note">No files are currently quarantined.</p> : quarantineItems.map((item) => <div className="host-history-row" key={String(item.id)}><div className="host-history-info"><strong>{String(item.original_path)}</strong><small>SHA-256 {String(item.sha256)} · {formatDate(String(item.quarantined_at))}</small></div><button className="button button-secondary" disabled={responseBusy === String(item.id)} onClick={() => void restoreItem(item)}>Restore</button></div>)}
            <p className="history-note">Quarantined files are stored locally with restricted permissions. Restore never overwrites an existing file and verifies the SHA-256 before restoring.</p>
          </div>
          {capabilities.length > 0 && <div className="result-section">
            <div className="result-heading"><h3>Static capability indicators</h3><span>INFERRED FROM SCRIPT TEXT · LOW CONFIDENCE</span></div>
            <div className="simple-table inventory-list">{capabilities.map((item, index) => <div className="simple-row" key={String(item.path) + String(item.id) + index} style={{gridTemplateColumns:"1fr 1fr"}}>
              <strong>{String(item.label)}</strong><span>{String(item.path)}</span><small>Inferred · low confidence</small>
            </div>)}</div>
            <div className="scope-note"><span className="scope-mark">i</span><p>These are static indicators only. They do not prove the script ran or performed the described action. SENTINEL does not execute samples to observe behaviour.</p></div>
          </div>}
          {asArray<string>(assessment.limitations).length > 0 && <div className="scope-note"><span className="scope-mark">i</span><p>{asArray<string>(assessment.limitations).join(" ")}</p></div>}
        </div>}
      </div>}
    </section>
  </>;
}
function AssessmentFindingCharts({ findings, capabilities }: { findings: Record<string, unknown>[]; capabilities: Record<string, unknown>[] }) {
  const [selectedSeverity, setSelectedSeverity] = useState("all");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const severityLevels = ["critical", "high", "medium", "low"] as const;
  const categoryLabel = (value: unknown) => String(value ?? "other").replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  const records = [
    ...findings.map((finding, index) => {
      const mapped = asArray<Record<string, unknown>>(finding.capabilities);
      const categories = [...new Set([categoryLabel(finding.category), ...mapped.map((item) => categoryLabel(item.label ?? item.id))])];
      return { id: String(finding.id ?? `finding-${index}`), title: String(finding.title ?? "Assessment finding"), severity: String(finding.severity ?? "low").toLowerCase(), path: String(finding.path ?? finding.evidence ?? "Local configuration"), description: String(finding.description ?? "Review the evidence."), categories, source: String(finding.source ?? "local assessment"), sha256: typeof finding.sha256 === "string" ? finding.sha256 : "" };
    }),
    ...capabilities.map((item, index) => ({
      id: `static-${String(item.id ?? index)}-${String(item.path ?? index)}`,
      title: String(item.label ?? item.id ?? "Static behaviour indicator"),
      severity: "low",
      path: String(item.path ?? "Path unavailable"),
      description: "Static script-text indicator only. It does not prove execution or malicious intent.",
      categories: [categoryLabel(item.label ?? item.id), "Static script indicator"],
      source: "static script pattern",
      sha256: "",
    })),
  ];
  const categoryCounts = Object.entries(records.reduce<Record<string, number>>((counts, record) => {
    record.categories.forEach((category) => { counts[category] = (counts[category] ?? 0) + 1; });
    return counts;
  }, {})).sort((a, b) => b[1] - a[1]);
  const severityCounts = severityLevels.map((level) => ({ level, count: records.filter((record) => record.severity === level).length }));
  const maxSeverity = Math.max(1, ...severityCounts.map((item) => item.count));
  const maxCategory = Math.max(1, ...categoryCounts.map((item) => item[1]));
  const filtered = records.filter((record) =>
    (selectedSeverity === "all" || record.severity === selectedSeverity) &&
    (selectedCategory === "all" || record.categories.includes(selectedCategory))
  );
  const chooseCategory = (category: string) => setSelectedCategory((current) => current === category ? "all" : category);
  return (
    <div className="finding-analytics" aria-label="Assessment finding charts and filters">
      <div className="finding-chart-card">
        <div className="finding-chart-head"><div><span className="eyebrow">RISK PROFILE</span><h3>Findings by severity</h3></div><strong>{records.length}<small> RECORDS</small></strong></div>
        <button className={`chart-filter-all ${selectedSeverity === "all" ? "active" : ""}`} onClick={() => setSelectedSeverity("all")}>All severities</button>
        {severityCounts.map((item) => (
          <button className={`severity-chart-row chart-selectable ${selectedSeverity === item.level ? "selected" : ""}`} key={item.level} onClick={() => setSelectedSeverity((current) => current === item.level ? "all" : item.level)} aria-pressed={selectedSeverity === item.level}>
            <span className={`severity-badge ${item.level}`}>{item.level}</span>
            <span className="chart-track"><span className={`chart-fill ${item.level}`} style={{ width: `${(item.count / maxSeverity) * 100}%` }} /></span>
            <strong>{item.count}</strong>
          </button>
        ))}
        <div className="chart-footnote">Select a severity to filter the evidence below. Static behaviour indicators are classified as low confidence, not confirmed malware.</div>
      </div>
      <div className="finding-chart-card">
        <div className="finding-chart-head"><div><span className="eyebrow">BEHAVIOUR & FINDING CATEGORIES</span><h3>Investigate by category</h3></div><strong>{categoryCounts.length}<small> CATEGORIES</small></strong></div>
        <button className={`chart-filter-all ${selectedCategory === "all" ? "active" : ""}`} onClick={() => setSelectedCategory("all")}>All categories</button>
        {categoryCounts.length === 0 ? <div className="chart-empty">No findings or behaviour indicators to chart.</div> : categoryCounts.map(([category, count]) => (
          <button className={`category-chart-row chart-selectable ${selectedCategory === category ? "selected" : ""}`} key={category} onClick={() => chooseCategory(category)} aria-pressed={selectedCategory === category}>
            <span>{category}</span><span className="chart-track"><span className="chart-fill category" style={{ width: `${(count / maxCategory) * 100}%` }} /></span><strong>{count}</strong>
          </button>
        ))}
        <div className="chart-footnote">Categories include credential/key access, network communication, persistence, command execution, destructive actions and privilege changes when detected.</div>
      </div>
      <div className="finding-evidence-list">
        <div className="finding-chart-head"><div><span className="eyebrow">FILTERED EVIDENCE</span><h3>Assessment records</h3></div><strong>{filtered.length}<small> MATCHING</small></strong></div>
        <div className="active-filters">
          <span>{selectedSeverity === "all" ? "All severities" : selectedSeverity.toUpperCase()}</span>
          <label className="category-filter-label"><span className="sr-only">Filter by category</span><select aria-label="Filter assessment records by category" value={selectedCategory} onChange={(event) => setSelectedCategory(event.target.value)}><option value="all">All categories</option>{categoryCounts.map(([category]) => <option key={category} value={category}>{category}</option>)}</select></label>
          {(selectedSeverity !== "all" || selectedCategory !== "all") && <button onClick={() => { setSelectedSeverity("all"); setSelectedCategory("all"); }}>Clear filters</button>}
        </div>
        {filtered.length === 0 ? <div className="chart-empty">No records match these filters.</div> : filtered.map((record) => (
          <article className="finding-evidence-row" key={record.id}>
            <span className={`severity-badge ${record.severity}`}>{record.severity.toUpperCase()}</span>
            <div className="finding-evidence-main"><strong>{record.title}</strong><small>{record.categories.join(" · ")}</small><code>{record.path}</code><p>{record.description}</p>{record.sha256 && <small>SHA-256: {record.sha256}</small>}</div>
            <span className="finding-evidence-source">{record.source}</span>
          </article>
        ))}
      </div>
    </div>
  );
}
function Resource({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="resource-card"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}
function NetworkView({ networks, selected, setSelected, scan, scans, busy, onStart, onReload }: {
  networks: NetworkInterface[]; selected: string; setSelected: (value: string) => void; scan: ScanRecord | null;
  scans: ScanRecord[]; busy: boolean; onStart: () => void; onReload: () => void;
}) {
  const result = asObject(scan?.result);
  const hosts = asArray<Record<string, unknown>>(result.hosts);
  return <>
    <PageHeading eyebrow="ASSESSMENT / NETWORK" title="Network discovery" description="Identify responsive devices and common TCP services on an attached private subnet.">
      <ActionButton secondary onClick={onReload}>↻ Refresh interfaces</ActionButton>
    </PageHeading>
    <section className="panel network-config">
      <div className="panel-title"><div><div className="eyebrow">SCAN CONFIGURATION</div><h2>Choose a local network</h2></div><span className="section-note">PRIVATE IPV4 ONLY</span></div>
      <div className="network-controls"><label><span>ATTACHED NETWORK / CIDR</span><select value={selected} onChange={(event) => setSelected(event.target.value)} disabled={networks.length === 0}>{networks.map((item) => <option key={item.network + item.interface} value={item.network}>{item.interface} · {item.network} · {item.address}</option>)}</select></label><ActionButton onClick={onStart} disabled={busy || !selected}>{busy ? "Starting…" : "Start discovery →"}</ActionButton></div>
      {networks.length === 0 && <div className="empty-state">No active private IPv4 network was detected on this machine.</div>}
      <div className="scope-note"><span className="scope-mark">!</span><p>Discovery is limited to a private IPv4 range attached to an active local interface, up to /24 in size. It checks 11 common TCP ports with short connection timeouts. No credentials, exploits, packet capture or vulnerability checks are used. Only scan networks you are authorised to assess.</p></div>
    </section>
    <section className="panel full-panel scan-panel"><div className="panel-title"><div><div className="eyebrow">DISCOVERY RESULTS</div><h2>Latest network scan</h2></div><span className="section-note">{scans.filter((item) => item.scan_type === "network").length} TOTAL RUNS</span></div><ScanHeader scan={scan} />
      {scan?.status === "failed" && <div className="scan-error">{scan.error ?? "The discovery scan failed."}</div>}
      {scan?.status === "completed" && <>
        <div className="resource-grid network-metrics"><Resource label="TARGET RANGE" value={String(result.network ?? scan.target)} detail="Local private subnet" /><Resource label="ADDRESSES CHECKED" value={String(result.addresses_checked ?? 0)} detail="Usable host addresses" /><Resource label="RESPONSIVE HOSTS" value={String(result.responsive_hosts ?? 0)} detail="At least one checked port open" /><Resource label="PORTS CHECKED" value={String(asArray(result.ports_checked).length)} detail="Fixed TCP service list" /></div>
        <div className="result-section"><div className="result-heading"><h3>Discovered devices</h3><span>{hosts.length} RESPONSIVE</span></div><div className="table-scroll"><table className="data-table"><thead><tr><th>IP ADDRESS</th><th>OPEN PORT</th><th>SERVICE</th></tr></thead><tbody>{hosts.flatMap((host) => asArray<Record<string, unknown>>(host.open_services).map((service, index) => <tr key={String(host.address) + String(service.port)}>{index === 0 && <td rowSpan={asArray(host.open_services).length}><strong>{String(host.address)}</strong></td>}<td>{String(service.port)}</td><td>{String(service.service)}</td></tr>))}</tbody></table></div>{hosts.length === 0 && <div className="empty-state">No hosts responded on the selected TCP ports. This does not prove that the subnet is empty.</div>}</div>
      </>}
    </section>
  </>;
}
