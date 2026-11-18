import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, type NetworkInterface, type ScanRecord, type SecurityEvent, type Severity } from "./api";

type View = "overview" | "events" | "host" | "network";
const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
const navItems: { id: View; label: string; code: string }[] = [
  { id: "overview", label: "Overview", code: "01" },
  { id: "events", label: "Event stream", code: "02" },
  { id: "host", label: "Host assessment", code: "03" },
  { id: "network", label: "Network discovery", code: "04" },
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

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking");
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
      const [status, page, history] = await Promise.all([api.health(), api.events({ search: search.trim(), severity }), api.scans()]);
      setHealth(status.status === "ok" ? "online" : "offline");
      setEvents(page.items); setTotal(page.total); setScans(history.items); setError("");
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
      setView(kind === "system" ? "host" : "network");
      const history = await api.scans(); setScans(history.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The scan could not be started.");
    } finally { setBusy(false); }
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

  const currentTitle = navItems.find((item) => item.id === view)?.label ?? "Overview";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="wordmark" onClick={() => setView("overview")} aria-label="SENTINEL home">
          <span className="wordmark-symbol"><i /><i /><i /></span>
          <span><strong>SENTINEL</strong><small>SECURITY OPERATIONS</small></span>
        </button>
        <div className="side-caption">CONSOLE</div>
        <nav className="side-nav" aria-label="Primary navigation">
          {navItems.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? "selected" : ""}`} onClick={() => setView(item.id)}>
            <span className="nav-code">{item.code}</span><span>{item.label}</span>{view === item.id && <span className="nav-indicator" />}
          </button>)}
        </nav>
        <div className="side-bottom">
          <div className="instance-card"><span className={`status-dot ${health}`} /><div><strong>LOCAL INSTANCE</strong><small>{health === "online" ? "API connected" : health === "checking" ? "Checking connection" : "API unavailable"}</small></div></div>
          <div className="side-version"><span>BUILD 0.2.0</span><span>LOCAL ONLY</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="crumb"><span>CONSOLE</span><b>/</b>{currentTitle.toUpperCase()}</div>
          <div className="topbar-right"><span className="environment"><i /> PRIVATE WORKSTATION</span><span className="top-divider" /><span className="api-state"><i className={health} />{health === "online" ? "CONNECTED" : health.toUpperCase()}</span></div>
        </header>

        {error && <div className="error-banner"><span className="error-mark">!</span><div><strong>Operation notice</strong><small>{error}</small></div><button onClick={() => void refresh()}>RETRY</button><button className="dismiss" onClick={() => setError("")} aria-label="Dismiss notice">×</button></div>}

        {view === "overview" && <Overview events={events} total={total} counts={counts} scans={scans} busy={busy} health={health} onNavigate={setView} onStart={startScan} onAddSample={addSample} />}
        {view === "events" && <EventsView events={events} total={total} search={search} severity={severity} setSearch={setSearch} setSeverity={setSeverity} onRefresh={() => void refresh()} />}
        {view === "host" && <HostView scan={activeScan?.scan_type === "system" ? activeScan : scans.find((scan) => scan.scan_type === "system") ?? null} scans={scans} busy={busy} onStart={() => void startScan("system")} />}
        {view === "network" && <NetworkView networks={networks} selected={selectedNetwork} setSelected={setSelectedNetwork} scan={activeScan?.scan_type === "network" ? activeScan : scans.find((scan) => scan.scan_type === "network") ?? null} scans={scans} busy={busy} onStart={() => void startScan("network")} onReload={() => void loadNetworks()} />}
        <footer className="footer"><span>L1337XI SENTINEL</span><span>LOCAL-FIRST SECURITY OPERATIONS</span><span>EARLY ACCESS BUILD</span></footer>
      </main>
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
function HostView({ scan, scans, busy, onStart }: { scan: ScanRecord | null; scans: ScanRecord[]; busy: boolean; onStart: () => void }) {
  const result = asObject(scan?.result);
  const memory = asObject(result.memory); const disk = asObject(result.disk);
  const interfaces = asArray<Record<string, unknown>>(result.interfaces);
  const processes = asArray<Record<string, unknown>>(result.processes);
  const listeners = asArray<Record<string, unknown>>(result.listening_services);
  const done = scan?.status === "completed";
  return <>
    <PageHeading eyebrow="ASSESSMENT / LOCAL HOST" title="Host assessment" description="Read-only inventory of the machine running the SENTINEL backend.">
      <ActionButton onClick={onStart} disabled={busy}>↻ Run assessment</ActionButton>
    </PageHeading>
    <div className="scope-note host-scope"><span className="scope-mark">i</span><p>This collects system metadata, resource usage, process names, listening sockets and network interfaces. It does not inspect file contents, remove malware or change system settings. Process visibility depends on the permissions used to run the backend.</p></div>
    <section className="panel full-panel scan-panel"><div className="panel-title"><div><div className="eyebrow">ASSESSMENT STATUS</div><h2>Latest host inventory</h2></div><span className="section-note">{scans.filter((item) => item.scan_type === "system").length} TOTAL RUNS</span></div><ScanHeader scan={scan} />
      {scan?.status === "failed" && <div className="scan-error">{scan.error ?? "The assessment failed."}</div>}
      {done && <div className="host-results">
        <div className="host-identity"><div className="host-initial">H</div><div><strong>{String(result.hostname ?? "Unknown host")}</strong><small>{String(result.operating_system ?? "Operating system unavailable")}</small></div></div>
        <div className="resource-grid">
          <Resource label="CPU CORES" value={String(result.cpu_cores ?? "—")} detail={`${String(result.logical_processors ?? "—")} logical processors`} />
          <Resource label="MEMORY" value={bytes(Number(memory.total_bytes))} detail={`${String(memory.used_percent ?? "—")}% utilised`} />
          <Resource label="ROOT DISK" value={bytes(Number(disk.total_bytes))} detail={`${String(disk.used_percent ?? "—")}% utilised`} />
          <Resource label="PROCESSES" value={String(result.process_count ?? "—")} detail={result.processes_truncated ? "First 100 displayed" : "Visible processes"} />
        </div>
        <div className="result-section"><div className="result-heading"><h3>Network interfaces</h3><span>{interfaces.length} INTERFACES</span></div><div className="simple-table">{interfaces.map((item, index) => <div className="simple-row" key={index}><strong>{String(item.name)}</strong><span>{String(item.address)}</span><small>{String(item.netmask ?? "—")}</small></div>)}</div></div>
        <div className="result-section"><div className="result-heading"><h3>Listening services</h3><span>{listeners.length} SOCKETS</span></div><div className="simple-table">{listeners.slice(0, 30).map((item, index) => <div className="simple-row" key={index}><strong>{String(item.process ?? "Unknown process")}</strong><span>{String(item.address)}:{String(item.port)}</span><small>PID {String(item.pid ?? "—")}</small></div>)}{listeners.length === 0 && <div className="empty-state">No listening services were visible to the scanner.</div>}</div></div>
        <div className="result-section"><div className="result-heading"><h3>Process inventory</h3><span>{processes.length} DISPLAYED</span></div><div className="simple-table process-list">{processes.slice(0, 40).map((item) => <div className="simple-row" key={String(item.pid)}><strong>{String(item.name)}</strong><span>PID {String(item.pid)}</span><small>{String(item.user ?? "—")}</small></div>)}</div></div>
      </div>}
    </section>
  </>;
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
