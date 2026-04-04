import { useEffect, useMemo, useState } from "react";

const apiBaseUrl =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:5050/api";

const dashboardDefaults = {
  metrics: {
    repositories: 0,
    scanJobs: 0,
    vulnerabilityReports: 0,
    severityTotals: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  },
  latestSubmission: null,
  repositories: [],
  findings: [],
  recentReports: [],
};

const defaultForm = {
  repositoryUrl: "",
  branch: "main",
  scanMode: "Quick Scan",
};

const pipelineStages = [
  "Static Code Analysis",
  "Dependency Scan",
  "DAST Validation",
  "Policy Gate Review",
];

const severityCards = [
  { key: "critical", label: "Critical", accent: "critical" },
  { key: "high", label: "High", accent: "high" },
  { key: "medium", label: "Medium", accent: "medium" },
  { key: "total", label: "Total Findings", accent: "info" },
];

const formatRepositoryPath = (repositoryUrl) =>
  repositoryUrl
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "");

function App() {
  const [dashboard, setDashboard] = useState(dashboardDefaults);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [form, setForm] = useState(defaultForm);

  const loadData = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${apiBaseUrl}/dashboard`);

      if (!response.ok) {
        throw new Error("Unable to load dashboard data.");
      }

      const payload = await response.json();
      setDashboard(payload);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  const submitScan = async (event) => {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError("");
      setSuccess("");

      const response = await fetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          repositoryUrl: form.repositoryUrl,
          branch: form.branch,
          scanMode: form.scanMode,
          tool: "semgrep",
          triggeredBy: "frontend-dashboard",
        }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.message || "Unable to queue scan.");
      }

      setSuccess(`Scan queued for ${payload.repository.name}.`);
      setTimeout(() => {
        loadData();
      }, 1500);
      await loadData();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  };

  const stageStatuses = useMemo(() => {
    const currentStatus = dashboard.latestSubmission?.status || "idle";

    if (currentStatus === "completed") {
      return pipelineStages.map((stage) => ({ stage, status: "Complete" }));
    }

    if (currentStatus === "running") {
      return pipelineStages.map((stage, index) => ({
        stage,
        status: index === 0 ? "Running" : "Waiting",
      }));
    }

    if (currentStatus === "queued") {
      return pipelineStages.map((stage) => ({ stage, status: "Waiting" }));
    }

    return pipelineStages.map((stage) => ({ stage, status: "Waiting" }));
  }, [dashboard.latestSubmission]);

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">SF</div>
          <div>
            <h1 className="brand-title">SecureFlow</h1>
            <p className="brand-subtitle">DevSecOps Platform</p>
          </div>
        </div>

        <nav className="nav-list">
          <button className="nav-item active">Dashboard</button>
          <button className="nav-item">Pipelines</button>
          <button className="nav-item">Repositories</button>
          <button className="nav-item">Reports</button>
        </nav>

        <div className="sidebar-footer">
          <span className="footer-label">Deployment Gate</span>
          <strong>{dashboard.latestSubmission?.status || "Waiting"}</strong>
        </div>
      </aside>

      <main className="workspace">
        <section className="workspace-hero">
          <div>
            <h2>Security Operations Dashboard</h2>
            <p>
              Shift-left scanning for repositories before deployment approval.
            </p>
          </div>
          <button className="status-pill" onClick={loadData}>
            Sync Status
          </button>
        </section>

        {error ? <div className="banner error">{error}</div> : null}
        {success ? <div className="banner success">{success}</div> : null}
        {loading ? <div className="banner">Loading dashboard data...</div> : null}

        <section className="summary-grid">
          {severityCards.map((card) => (
            <article className={`summary-card ${card.accent}`} key={card.key}>
              <span>{card.label}</span>
              <strong>
                {card.key === "total"
                  ? dashboard.metrics.severityTotals.total
                  : dashboard.metrics.severityTotals[card.key]}
              </strong>
            </article>
          ))}
        </section>

        <section className="content-grid">
          <div className="left-column">
            <section className="panel">
              <div className="panel-header">
                <h3>Submit Repository</h3>
                <span className="soft-pill">Manual Trigger</span>
              </div>

              <form className="repo-form" onSubmit={submitScan}>
                <label>
                  <span>Repository / URL</span>
                  <input
                    type="url"
                    value={form.repositoryUrl}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        repositoryUrl: event.target.value,
                      }))
                    }
                    placeholder="https://github.com/org/project"
                    required
                  />
                </label>

                <div className="form-row">
                  <label>
                    <span>Branch</span>
                    <input
                      type="text"
                      value={form.branch}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          branch: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    <span>Scan Mode</span>
                    <select
                      value={form.scanMode}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          scanMode: event.target.value,
                        }))
                      }
                    >
                      <option>Quick Scan</option>
                      <option>Full Scan</option>
                    </select>
                  </label>
                </div>

                <button className="action-button" disabled={submitting}>
                  {submitting ? "Starting..." : "Start Scan"}
                </button>
              </form>
            </section>

            <section className="panel">
              <div className="panel-header">
                <h3>Scan Status</h3>
                <span className="soft-pill">Live Pipeline</span>
              </div>

              <div className="status-list">
                {stageStatuses.map((item) => (
                  <div className="status-row" key={item.stage}>
                    <div className="status-row-title">
                      <span className={`status-dot ${item.status.toLowerCase()}`} />
                      <span>{item.stage}</span>
                    </div>
                    <strong>{item.status}</strong>
                  </div>
                ))}
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <h3>Tracked Repositories</h3>
              </div>

              <div className="repository-list">
                {dashboard.repositories.length ? (
                  dashboard.repositories.map((repository) => (
                    <div className="repository-item" key={repository.id}>
                      <div className="repository-copy">
                        <strong>{repository.name}</strong>
                        <p
                          className="repository-path"
                          title={repository.url}
                        >
                          {formatRepositoryPath(repository.url)}
                        </p>
                      </div>
                      <span className="branch-badge">{repository.branch}</span>
                    </div>
                  ))
                ) : (
                  <p className="empty-state">No repositories submitted yet.</p>
                )}
              </div>
            </section>
          </div>

          <section className="panel reports-panel">
            <div className="panel-header">
              <div>
                <h3>Vulnerability Reports</h3>
                <p className="panel-copy">
                  Enter a repository URL and run a scan to load the latest
                  report.
                </p>
              </div>
              <span className="soft-pill">
                {dashboard.latestSubmission?.scanMode || "Awaiting Scan"}
              </span>
            </div>

            <div className="report-context">
              <span>
                Repository:{" "}
                {dashboard.latestSubmission?.repositoryUrl || "Not selected"}
              </span>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Tool</th>
                    <th>Category</th>
                    <th>Location</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {dashboard.findings.length ? (
                    dashboard.findings.map((finding) => (
                      <tr key={finding.id}>
                        <td>{finding.id}</td>
                        <td>{finding.tool}</td>
                        <td>{finding.category}</td>
                        <td>{finding.location}</td>
                        <td>
                          <span
                            className={`severity-badge ${finding.severity.toLowerCase()}`}
                          >
                            {finding.severity}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" className="empty-table">
                        No vulnerability data yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </section>
      </main>
    </div>
  );
}

export default App;
