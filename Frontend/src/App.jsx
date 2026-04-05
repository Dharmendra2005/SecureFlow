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
    jobStatusCounts: {
      pending: 0,
      active: 0,
      completed: 0,
      failed: 0,
    },
  },
  latestSubmission: null,
  repositories: [],
  findings: [],
  toolRuns: [],
  scanJobs: [],
  recentReports: [],
};

const paginatedDefaults = {
  data: [],
  pagination: {
    page: 1,
    limit: 5,
    totalItems: 0,
    totalPages: 0,
  },
  filters: {},
};

const defaultForm = {
  repositoryUrl: "",
  branch: "main",
  scanMode: "Quick Scan",
  targetUrl: "",
};

const severityCards = [
  { key: "critical", label: "Critical", accent: "critical" },
  { key: "high", label: "High", accent: "high" },
  { key: "medium", label: "Medium", accent: "medium" },
  { key: "low", label: "Low", accent: "low" },
];

const navigationItems = [
  { id: "overview", label: "Dashboard" },
  { id: "jobs", label: "Pipelines" },
  { id: "repositories", label: "Repositories" },
  { id: "reports", label: "Reports" },
];

const pipelineStages = [
  "Repository Intake",
  "SAST and Secrets",
  "Dependency and Container",
  "DAST and Reporting",
];

const formatRepositoryPath = (repositoryUrl) =>
  repositoryUrl
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "");

const formatTimestamp = (value) =>
  value ? new Date(value).toLocaleString() : "Not available";

const statusTone = (status) => String(status || "").toLowerCase();

function App() {
  const [activeView, setActiveView] = useState("overview");
  const [dashboard, setDashboard] = useState(dashboardDefaults);
  const [reportsState, setReportsState] = useState(paginatedDefaults);
  const [jobsState, setJobsState] = useState(paginatedDefaults);
  const [loadingDashboard, setLoadingDashboard] = useState(true);
  const [loadingReports, setLoadingReports] = useState(false);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [form, setForm] = useState(defaultForm);
  const [reportFilters, setReportFilters] = useState({
    page: 1,
    limit: 5,
    severity: "",
    type: "",
    repository: "",
  });
  const [jobFilters, setJobFilters] = useState({
    page: 1,
    limit: 5,
    status: "",
    scanType: "",
    repository: "",
  });
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [findingSort, setFindingSort] = useState("severity");

  const buildQueryString = (filters) => {
    const params = new URLSearchParams();

    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value !== null && value !== undefined) {
        params.set(key, value);
      }
    });

    return params.toString();
  };

  const loadDashboard = async () => {
    try {
      setLoadingDashboard(true);
      setError("");

      const response = await fetch(`${apiBaseUrl}/dashboard`);

      if (!response.ok) {
        throw new Error("Unable to load dashboard data.");
      }

      setDashboard(await response.json());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoadingDashboard(false);
    }
  };

  const loadReports = async (filters = reportFilters) => {
    try {
      setLoadingReports(true);
      const query = buildQueryString(filters);
      const response = await fetch(`${apiBaseUrl}/reports?${query}`);

      if (!response.ok) {
        throw new Error("Unable to load report history.");
      }

      setReportsState(await response.json());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoadingReports(false);
    }
  };

  const loadJobs = async (filters = jobFilters) => {
    try {
      setLoadingJobs(true);
      const query = buildQueryString(filters);
      const response = await fetch(`${apiBaseUrl}/scan-jobs?${query}`);

      if (!response.ok) {
        throw new Error("Unable to load scan history.");
      }

      setJobsState(await response.json());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoadingJobs(false);
    }
  };

  const refreshAll = async () => {
    await Promise.all([loadDashboard(), loadReports(reportFilters), loadJobs(jobFilters)]);
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
          targetUrl: form.targetUrl,
          tool: "scanner-engine",
          triggeredBy: "frontend-dashboard",
        }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.message || "Unable to queue scan.");
      }

      setSuccess(`Scan queued for ${payload.repository.name}.`);
      setActiveView("overview");
      await refreshAll();
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

    if (currentStatus === "active") {
      return pipelineStages.map((stage, index) => ({
        stage,
        status: index < 2 ? "Running" : "Waiting",
      }));
    }

    if (currentStatus === "pending") {
      return pipelineStages.map((stage, index) => ({
        stage,
        status: index === 0 ? "Queued" : "Waiting",
      }));
    }

    if (currentStatus === "failed") {
      return pipelineStages.map((stage, index) => ({
        stage,
        status: index === 0 ? "Failed" : "Waiting",
      }));
    }

    return pipelineStages.map((stage) => ({ stage, status: "Waiting" }));
  }, [dashboard.latestSubmission]);

  const severityDistribution = useMemo(() => {
    const total = dashboard.metrics.severityTotals.total || 1;

    return severityCards.map((card) => ({
      ...card,
      value: dashboard.metrics.severityTotals[card.key],
      width:
        ((dashboard.metrics.severityTotals[card.key] || 0) / total) * 100,
    }));
  }, [dashboard.metrics.severityTotals]);

  const jobDistribution = useMemo(() => {
    const total = dashboard.metrics.scanJobs || 1;

    return Object.entries(dashboard.metrics.jobStatusCounts).map(
      ([status, value]) => ({
        status,
        value,
        width: (value / total) * 100,
      }),
    );
  }, [dashboard.metrics.jobStatusCounts, dashboard.metrics.scanJobs]);

  const sortedFindings = useMemo(() => {
    const findings = [...dashboard.findings];

    if (findingSort === "severity") {
      const severityOrder = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
      };

      return findings.sort(
        (left, right) =>
          (severityOrder[right.severity] || 0) -
          (severityOrder[left.severity] || 0),
      );
    }

    return findings.sort((left, right) =>
      String(left[findingSort] || "").localeCompare(String(right[findingSort] || "")),
    );
  }, [dashboard.findings, findingSort]);

  useEffect(() => {
    refreshAll();
  }, []);

  useEffect(() => {
    loadReports(reportFilters);
  }, [reportFilters.page, reportFilters.limit, reportFilters.severity, reportFilters.type, reportFilters.repository]);

  useEffect(() => {
    loadJobs(jobFilters);
  }, [jobFilters.page, jobFilters.limit, jobFilters.status, jobFilters.scanType, jobFilters.repository]);

  useEffect(() => {
    const interval = setInterval(() => {
      loadDashboard();
      if (activeView === "reports") {
        loadReports(reportFilters);
      }
      if (activeView === "jobs") {
        loadJobs(jobFilters);
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [activeView, reportFilters, jobFilters]);

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
          {navigationItems.map((item) => (
            <button
              className={`nav-item ${activeView === item.id ? "active" : ""}`}
              key={item.id}
              onClick={() => setActiveView(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="footer-label">Deployment Gate</span>
          <strong>{dashboard.latestSubmission?.status || "Waiting"}</strong>
          <p className="sidebar-copy">
            Latest queue job: {dashboard.latestSubmission?.queueJobId || "n/a"}
          </p>
        </div>
      </aside>

      <main className="workspace">
        <section className="workspace-hero">
          <div>
            <h2>Security Operations Dashboard</h2>
            <p>
              Monitor repository intake, scan execution, and vulnerability
              intelligence in one responsive workspace.
            </p>
          </div>
          <div className="hero-actions">
            <button className="status-pill" onClick={refreshAll}>
              Sync Status
            </button>
            <span className={`hero-badge ${statusTone(dashboard.latestSubmission?.status)}`}>
              {dashboard.latestSubmission?.status || "idle"}
            </span>
          </div>
        </section>

        {error ? <div className="banner error">{error}</div> : null}
        {success ? <div className="banner success">{success}</div> : null}
        {loadingDashboard ? (
          <div className="banner">Loading platform telemetry...</div>
        ) : null}

        <section className="summary-grid">
          {severityCards.map((card) => (
            <article className={`summary-card ${card.accent}`} key={card.key}>
              <span>{card.label}</span>
              <strong>{dashboard.metrics.severityTotals[card.key]}</strong>
              <p>Across recent report history</p>
            </article>
          ))}
        </section>

        <section className="overview-grid">
          <section className="panel form-panel">
            <div className="panel-header">
              <div>
                <h3>Submit Repository</h3>
                <p className="panel-copy">
                  Queue a new repository scan with optional DAST target.
                </p>
              </div>
              <span className="soft-pill">Manual Trigger</span>
            </div>

            <form className="repo-form" onSubmit={submitScan}>
              <label>
                <span>Repository URL</span>
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

              <label>
                <span>Target URL For DAST</span>
                <input
                  type="url"
                  value={form.targetUrl}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      targetUrl: event.target.value,
                    }))
                  }
                  placeholder="http://localhost:3000"
                />
              </label>

              <button className="action-button" disabled={submitting}>
                {submitting ? "Queueing Scan..." : "Start Scan"}
              </button>
            </form>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>Severity Distribution</h3>
                <p className="panel-copy">
                  Vulnerability mix across the most recent scan history.
                </p>
              </div>
              <span className="soft-pill">Live Metrics</span>
            </div>

            <div className="chart-list">
              {severityDistribution.map((item) => (
                <div className="chart-row" key={item.key}>
                  <div className="chart-label">
                    <span>{item.label}</span>
                    <strong>{item.value}</strong>
                  </div>
                  <div className="chart-track">
                    <div
                      className={`chart-fill ${item.accent}`}
                      style={{ width: `${item.width}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>Queue Health</h3>
                <p className="panel-copy">
                  Track pending, running, and completed jobs in real time.
                </p>
              </div>
              <span className="soft-pill">BullMQ</span>
            </div>

            <div className="chart-list">
              {jobDistribution.map((item) => (
                <div className="chart-row" key={item.status}>
                  <div className="chart-label">
                    <span>{item.status}</span>
                    <strong>{item.value}</strong>
                  </div>
                  <div className="chart-track">
                    <div
                      className={`chart-fill status-${item.status}`}
                      style={{ width: `${item.width}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="status-list compact">
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
        </section>

        <section className="content-grid expanded">
          <section className="panel primary-panel">
            <div className="panel-header">
              <div>
                <h3>Latest Vulnerability Findings</h3>
                <p className="panel-copy">
                  Sort and inspect the current report findings in detail.
                </p>
              </div>
              <div className="header-tools">
                <label className="inline-filter">
                  <span>Sort</span>
                  <select
                    value={findingSort}
                    onChange={(event) => setFindingSort(event.target.value)}
                  >
                    <option value="severity">Severity</option>
                    <option value="tool">Tool</option>
                    <option value="category">Category</option>
                    <option value="location">Location</option>
                  </select>
                </label>
                <span className="soft-pill">
                  {dashboard.latestSubmission?.scanMode || "Awaiting Scan"}
                </span>
              </div>
            </div>

            <div className="report-context">
              <span>
                Repository: {dashboard.latestSubmission?.repositoryUrl || "Not selected"}
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
                  {sortedFindings.length ? (
                    sortedFindings.map((finding) => (
                      <tr
                        key={finding.id}
                        className={selectedFinding?.id === finding.id ? "selected-row" : ""}
                        onClick={() => setSelectedFinding(finding)}
                      >
                        <td>{finding.id}</td>
                        <td>{finding.tool}</td>
                        <td>{finding.category}</td>
                        <td>{finding.location}</td>
                        <td>
                          <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
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

            <div className="tool-run-list">
              {dashboard.toolRuns.map((run) => (
                <div className="tool-run-row" key={`${run.tool}-${run.completedAt}`}>
                  <div>
                    <strong>{run.tool}</strong>
                    <p>{run.message}</p>
                  </div>
                  <span className={`job-status ${run.status}`}>{run.status}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="panel detail-panel">
            <div className="panel-header">
              <div>
                <h3>Issue Detail</h3>
                <p className="panel-copy">
                  Select a finding to review context, description, and next actions.
                </p>
              </div>
              <span className="soft-pill">Deep Dive</span>
            </div>

            {selectedFinding ? (
              <div className="detail-card">
                <span className={`severity-badge ${selectedFinding.severity.toLowerCase()}`}>
                  {selectedFinding.severity}
                </span>
                <h4>{selectedFinding.category}</h4>
                <p><strong>Tool:</strong> {selectedFinding.tool}</p>
                <p><strong>Location:</strong> {selectedFinding.location}</p>
                <p><strong>Description:</strong> {selectedFinding.description}</p>
                <p>
                  <strong>Suggested Fix:</strong> Review the affected file, reproduce
                  the issue locally, and patch the root cause before rerunning the scan.
                </p>
              </div>
            ) : (
              <div className="empty-detail">
                <h4>No Issue Selected</h4>
                <p>Click any finding in the table to inspect the vulnerability detail view.</p>
              </div>
            )}
          </section>
        </section>

        <section className="history-grid">
          <section className={`panel history-panel ${activeView === "reports" ? "active-panel" : ""}`}>
            <div className="panel-header">
              <div>
                <h3>Historical Reports</h3>
                <p className="panel-copy">
                  Filter by repository, severity, and type with paginated history.
                </p>
              </div>
              <span className="soft-pill">{reportsState.pagination.totalItems} reports</span>
            </div>

            <div className="filter-grid">
              <input
                value={reportFilters.repository}
                onChange={(event) =>
                  setReportFilters((current) => ({
                    ...current,
                    repository: event.target.value,
                    page: 1,
                  }))
                }
                placeholder="Filter repository"
              />
              <select
                value={reportFilters.severity}
                onChange={(event) =>
                  setReportFilters((current) => ({
                    ...current,
                    severity: event.target.value,
                    page: 1,
                  }))
                }
              >
                <option value="">All severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={reportFilters.type}
                onChange={(event) =>
                  setReportFilters((current) => ({
                    ...current,
                    type: event.target.value,
                    page: 1,
                  }))
                }
              >
                <option value="">All types</option>
                <option value="sast">SAST</option>
                <option value="secrets">Secrets</option>
                <option value="dependency">Dependency</option>
                <option value="container">Container</option>
                <option value="dast">DAST</option>
              </select>
            </div>

            {loadingReports ? <p className="inline-loading">Loading reports...</p> : null}

            <div className="history-list">
              {reportsState.data.map((report) => (
                <article className="history-card" key={report.id}>
                  <div>
                    <strong>{report.repository?.name || "Unknown repository"}</strong>
                    <p>{report.repository?.url || "No repository URL"}</p>
                  </div>
                  <div className="history-meta">
                    <span>{report.findingsCount} findings</span>
                    <span>{formatTimestamp(report.createdAt)}</span>
                  </div>
                </article>
              ))}
            </div>

            <div className="pagination-row">
              <button
                className="status-pill"
                disabled={reportsState.pagination.page <= 1}
                onClick={() =>
                  setReportFilters((current) => ({
                    ...current,
                    page: current.page - 1,
                  }))
                }
              >
                Previous
              </button>
              <span>
                Page {reportsState.pagination.page} of{" "}
                {Math.max(reportsState.pagination.totalPages, 1)}
              </span>
              <button
                className="status-pill"
                disabled={
                  reportsState.pagination.page >= reportsState.pagination.totalPages
                }
                onClick={() =>
                  setReportFilters((current) => ({
                    ...current,
                    page: current.page + 1,
                  }))
                }
              >
                Next
              </button>
            </div>
          </section>

          <section className={`panel history-panel ${activeView === "jobs" ? "active-panel" : ""}`}>
            <div className="panel-header">
              <div>
                <h3>Scan Job Timeline</h3>
                <p className="panel-copy">
                  Explore queue history with status and scan-type filters.
                </p>
              </div>
              <span className="soft-pill">{jobsState.pagination.totalItems} jobs</span>
            </div>

            <div className="filter-grid">
              <input
                value={jobFilters.repository}
                onChange={(event) =>
                  setJobFilters((current) => ({
                    ...current,
                    repository: event.target.value,
                    page: 1,
                  }))
                }
                placeholder="Filter repository"
              />
              <select
                value={jobFilters.status}
                onChange={(event) =>
                  setJobFilters((current) => ({
                    ...current,
                    status: event.target.value,
                    page: 1,
                  }))
                }
              >
                <option value="">All status</option>
                <option value="pending">Pending</option>
                <option value="active">Active</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
              </select>
              <select
                value={jobFilters.scanType}
                onChange={(event) =>
                  setJobFilters((current) => ({
                    ...current,
                    scanType: event.target.value,
                    page: 1,
                  }))
                }
              >
                <option value="">All scan types</option>
                <option value="Quick Scan">Quick Scan</option>
                <option value="Full Scan">Full Scan</option>
              </select>
            </div>

            {loadingJobs ? <p className="inline-loading">Loading job history...</p> : null}

            <div className="job-list">
              {jobsState.data.map((job) => (
                <div className="job-list-row bordered" key={job.id}>
                  <div>
                    <strong>{job.repository?.name || "Unknown repository"}</strong>
                    <p>
                      {job.scanType} / {job.tool} / {job.queueJobId || "No queue id"}
                    </p>
                  </div>
                  <div className="job-list-side">
                    <span className={`job-status ${job.status}`}>{job.status}</span>
                    <span>{formatTimestamp(job.createdAt)}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="pagination-row">
              <button
                className="status-pill"
                disabled={jobsState.pagination.page <= 1}
                onClick={() =>
                  setJobFilters((current) => ({
                    ...current,
                    page: current.page - 1,
                  }))
                }
              >
                Previous
              </button>
              <span>
                Page {jobsState.pagination.page} of{" "}
                {Math.max(jobsState.pagination.totalPages, 1)}
              </span>
              <button
                className="status-pill"
                disabled={jobsState.pagination.page >= jobsState.pagination.totalPages}
                onClick={() =>
                  setJobFilters((current) => ({
                    ...current,
                    page: current.page + 1,
                  }))
                }
              >
                Next
              </button>
            </div>
          </section>
        </section>
      </main>
    </div>
  );
}

export default App;
