import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type SecurityEvent, type Severity } from "./api";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium", timeStyle: "short",
  }).format(new Date(value));
}

export default function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [status, page] = await Promise.all([
        api.health(),
        api.events({ search: search.trim(), severity }),
      ]);
      setHealth(status.status === "ok" ? "online" : "offline");
      setEvents(page.items);
      setTotal(page.total);
      setError("");
    } catch (err) {
      setHealth("offline");
      setError(err instanceof Error ? err.message : "Unable to reach the SENTINEL API.");
    }
  }, [search, severity]);

  useEffect(() => { void refresh(); }, [refresh]);

  const counts = useMemo(() => ({
    critical: events.filter((event) => event.severity === "critical").length,
    high: events.filter((event) => event.severity === "high").length,
    medium: events.filter((event) => event.severity === "medium").length,
    low: events.filter((event) => event.severity === "low").length,
  }), [events]);

  async function addSample() {
    setBusy(true);
    try {
      await api.createEvent({
        source: "sentinel-demo",
        event_type: "authentication",
        severity: "medium",
        message: "Sample event: repeated authentication failures detected",
        host: "lab-workstation",
        metadata: { sample: true, attempts: 5 },
      });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create sample event.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">S</div><div><strong>SENTINEL</strong><span> L1337XI SECURITY</span></div></div>
        <div className="nav-label">WORKSPACE</div>
        <a className="nav-item active" href="#overview"><span>◈</span> Overview</a>
        <a className="nav-item" href="#events"><span>▤</span> Event stream</a>
        <a className="nav-item disabled" aria-disabled="true"><span>⌁</span> Detection rules <small>SOON</small></a>
        <a className="nav-item disabled" aria-disabled="true"><span>▣</span> Incidents <small>SOON</small></a>
        <a className="nav-item disabled" aria-disabled="true"><span>⌕</span> Threat hunting <small>SOON</small></a>
        <div className="sidebar-bottom"><div className="local-indicator"><i /> LOCAL INSTANCE</div><p>Early development build<br />v0.1.0</p></div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> Overview</div><div className="top-status"><i className={health} /> API {health === "checking" ? "CHECKING" : health.toUpperCase()}</div></header>
        <section className="page-heading">
          <div><div className="eyebrow">SECURITY OPERATIONS CENTER</div><h1>Overview</h1><p>Local telemetry intake and security event visibility.</p></div>
          <button className="primary-button" onClick={addSample} disabled={busy || health !== "online"}>{busy ? "ADDING…" : "+ Add sample event"}</button>
        </section>

        {error && <div className="error-banner"><strong>Connection issue</strong><span>{error}</span><button onClick={() => void refresh()}>Retry</button></div>}

        <section className="metric-grid" aria-label="Event summary">
          <Metric label="TOTAL EVENTS" value={total} detail="Matching current filters" />
          <Metric label="CRITICAL" value={counts.critical} detail="Critical severity" tone="critical" />
          <Metric label="HIGH" value={counts.high} detail="High severity" tone="high" />
          <Metric label="MEDIUM / LOW" value={counts.medium + counts.low} detail="Lower severity" tone="normal" />
        </section>

        <section className="panel" id="events">
          <div className="panel-heading"><div><div className="eyebrow">TELEMETRY</div><h2>Recent events</h2><p>Events stored in your local SENTINEL database.</p></div><button className="quiet-button" onClick={() => void refresh()}>↻ Refresh</button></div>
          <div className="filters"><label className="search-box"><span>⌕</span><input aria-label="Search events" placeholder="Search message, source, host…" value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{severityOrder.map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select></div>
          <div className="table-wrap"><table><thead><tr><th>SEVERITY</th><th>EVENT</th><th>SOURCE</th><th>HOST</th><th>TIME</th></tr></thead><tbody>
            {events.map((event) => <tr key={event.id}><td><span className={`severity ${event.severity}`}>{event.severity}</span></td><td><strong>{event.message}</strong><small>{event.event_type}</small></td><td>{event.source}</td><td>{event.host ?? "—"}</td><td className="time-cell">{formatDate(event.occurred_at)}</td></tr>)}
            {events.length === 0 && <tr><td colSpan={5} className="empty-state">{health === "online" ? "No events match this view. Add a sample event or ingest data through the API." : "Waiting for the local API connection…"}</td></tr>}
          </tbody></table></div>
          <div className="table-footer"><span>Showing {events.length} of {total} events</span><span>LOCAL DATABASE · SQLITE</span></div>
        </section>
        <footer> L1337XI SENTINEL <span>·</span> LOCAL-FIRST SECURITY OPERATIONS <span>·</span> NOT FOR PRODUCTION USE</footer>
      </main>
    </div>
  );
}

function Metric({ label, value, detail, tone = "normal" }: { label: string; value: number; detail: string; tone?: string }) {
  return <article className="metric-card"><div className="metric-label">{label}</div><div className={`metric-value ${tone}`}>{value.toLocaleString()}</div><div className="metric-detail">{detail}</div></article>;
}
