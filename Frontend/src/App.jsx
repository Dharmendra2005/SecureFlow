import { useEffect, useMemo, useState } from "react";

const apiBaseUrl = import.meta.env.DEV
  ? import.meta.env.VITE_API_BASE_URL || "http://localhost:5050/api"
  : import.meta.env.VITE_API_BASE_URL || "/api";
const authStorageKey = "secureflow-auth";

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
  latestReportId: null,
  latestSecurityScore: null,
  securityAnalytics: {
    latest: null,
    previous: null,
    delta: 0,
    trend: [],
  },
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

const defaultLoginForm = {
  email: "",
  password: "",
  name: "",
  mode: "login",
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
const formatList = (items) =>
  Array.isArray(items) ? items.filter(Boolean) : [];
const formatDelta = (value) => `${value > 0 ? "+" : ""}${Number(value || 0)}`;

const findingInsightStatus = (finding) => {
  const status = String(finding?.ai?.status || "").toLowerCase();

  if (status === "generated") {
    return "AI generated";
  }

  if (status === "fallback") {
    return "Fallback guidance";
  }

  if (status === "unavailable") {
    return "AI unavailable";
  }

  return "Pending insight";
};

const riskTone = (riskLevel) => {
  const normalized = String(riskLevel || "").toLowerCase();

  if (normalized === "high-risk") {
    return "critical";
  }

  if (normalized === "moderate") {
    return "medium";
  }

  return "low";
};

const parseApiResponse = async (response) => {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();

  if (text.trim().startsWith("<!DOCTYPE") || text.trim().startsWith("<html")) {
    throw new Error(
      "The frontend reached an HTML page instead of the backend API. Restart the frontend dev server and make sure the backend is running on port 5050.",
    );
  }

  return {
    message: text || "Unexpected non-JSON response from the server.",
  };
};

function App() {
  const [auth, setAuth] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem(authStorageKey) || "null");
    } catch {
      return null;
    }
  });
  const [loginForm, setLoginForm] = useState(defaultLoginForm);
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
  const [creatingRemediation, setCreatingRemediation] = useState(false);
  const [remediationMessage, setRemediationMessage] = useState("");
  const [deletingReportId, setDeletingReportId] = useState("");
  const liveScanInProgress = ["pending", "active"].includes(
    String(dashboard.latestSubmission?.status || "").toLowerCase(),
  );

  const buildQueryString = (filters) => {
    const params = new URLSearchParams();

    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value !== null && value !== undefined) {
        params.set(key, value);
      }
    });

    return params.toString();
  };

  const saveAuth = (payload) => {
    setAuth(payload);
    localStorage.setItem(authStorageKey, JSON.stringify(payload));
  };

  const clearAuth = () => {
    setAuth(null);
    localStorage.removeItem(authStorageKey);
  };

  const fetchWithAuth = async (url, options = {}) => {
    const headers = {
      ...(options.headers || {}),
      ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
    };

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      clearAuth();
    }

    return response;
  };

  const loadDashboard = async () => {
    try {
      setLoadingDashboard(true);
      setError("");

      const response = await fetchWithAuth(`${apiBaseUrl}/dashboard`);

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
      const response = await fetchWithAuth(`${apiBaseUrl}/reports?${query}`);

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
      const response = await fetchWithAuth(`${apiBaseUrl}/scan-jobs?${query}`);

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

  const createRemediationPullRequest = async () => {
    if (!dashboard.latestReportId || !selectedFinding?.id) {
      setError("The latest report or selected finding is not available for remediation.");
      return;
    }

    try {
      setCreatingRemediation(true);
      setError("");
      setSuccess("");
      setRemediationMessage("");

      const response = await fetchWithAuth(
        `${apiBaseUrl}/reports/${dashboard.latestReportId}/findings/${selectedFinding.id}/remediation-pr`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        },
      );

      const payload = await parseApiResponse(response);

      if (!response.ok) {
        throw new Error(payload.message || "Unable to create remediation pull request.");
      }

      setRemediationMessage(
        payload.data?.pullRequestUrl
          ? `Pull request created: ${payload.data.pullRequestUrl}`
          : "Remediation request completed.",
      );
      await refreshAll();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCreatingRemediation(false);
    }
  };

  const deleteReportHistory = async (event, reportId) => {
    event.preventDefault();
    event.stopPropagation();

    const confirmed = window.confirm(
      "Delete this report history entry? This will remove the saved report and related remediation records.",
    );

    if (!confirmed) {
      return;
    }

    try {
      setDeletingReportId(reportId);
      setError("");
      setSuccess("");
      setRemediationMessage("");

      const response = await fetchWithAuth(`${apiBaseUrl}/reports/${reportId}`, {
        method: "DELETE",
      });
      const payload = await parseApiResponse(response);

      if (!response.ok) {
        throw new Error(payload.message || "Unable to delete report history.");
      }

      setReportsState((current) => ({
        ...current,
        data: current.data.filter((report) => report.id !== reportId),
        pagination: {
          ...current.pagination,
          totalItems: Math.max(0, (current.pagination.totalItems || 0) - 1),
        },
      }));
      setDashboard((current) => ({
        ...current,
        recentReports: (current.recentReports || []).filter(
          (report) => report.id !== reportId,
        ),
        latestReportId:
          current.latestReportId === reportId ? null : current.latestReportId,
      }));
      setSuccess("Report history deleted successfully.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setDeletingReportId("");
    }
  };

  const deleteScanHistory = async (event, scanJobId) => {
    event.preventDefault();
    event.stopPropagation();

    const confirmed = window.confirm(
      "Delete this scan history entry? This will also remove its linked report and remediation records.",
    );

    if (!confirmed) {
      return;
    }

    try {
      setDeletingReportId(scanJobId);
      setError("");
      setSuccess("");
      setRemediationMessage("");

      const response = await fetchWithAuth(`${apiBaseUrl}/scan-jobs/${scanJobId}`, {
        method: "DELETE",
      });
      const payload = await parseApiResponse(response);

      if (!response.ok) {
        throw new Error(payload.message || "Unable to delete scan history.");
      }

      setJobsState((current) => ({
        ...current,
        data: current.data.filter((job) => job.id !== scanJobId),
        pagination: {
          ...current.pagination,
          totalItems: Math.max(0, (current.pagination.totalItems || 0) - 1),
        },
      }));
      setDashboard((current) => ({
        ...current,
        scanJobs: (current.scanJobs || []).filter((job) => job.id !== scanJobId),
        recentReports: payload.data?.reportId
          ? (current.recentReports || []).filter((report) => report.id !== payload.data.reportId)
          : current.recentReports,
      }));
      setSuccess("Scan history deleted successfully.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setDeletingReportId("");
    }
  };

  const submitScan = async (event) => {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError("");
      setSuccess("");

      const response = await fetchWithAuth(`${apiBaseUrl}/scans`, {
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

      const payload = await parseApiResponse(response);

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

  const submitAuth = async (event) => {
    event.preventDefault();

    try {
      setError("");
      const endpoint =
        loginForm.mode === "register" ? "/auth/register" : "/auth/login";
      const response = await fetch(`${apiBaseUrl}${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: loginForm.email,
          password: loginForm.password,
          name: loginForm.name,
        }),
      });
      const payload = await parseApiResponse(response);

      if (!response.ok) {
        throw new Error(payload.message || "Authentication failed.");
      }

      saveAuth(payload.data);
    } catch (requestError) {
      setError(requestError.message);
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

  const scoreTrend = useMemo(() => {
    const trend = dashboard.securityAnalytics?.trend || [];
    const maxScore = Math.max(100, ...trend.map((item) => item.score || 0));

    return trend.map((item) => ({
      ...item,
      width: Math.max(8, ((item.score || 0) / maxScore) * 100),
    }));
  }, [dashboard.securityAnalytics]);

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
    if (auth?.token) {
      refreshAll();
    }
  }, [auth?.token]);

  useEffect(() => {
    if (auth?.token) {
      loadReports(reportFilters);
    }
  }, [auth?.token, reportFilters.page, reportFilters.limit, reportFilters.severity, reportFilters.type, reportFilters.repository]);

  useEffect(() => {
    if (auth?.token) {
      loadJobs(jobFilters);
    }
  }, [auth?.token, jobFilters.page, jobFilters.limit, jobFilters.status, jobFilters.scanType, jobFilters.repository]);

  useEffect(() => {
    if (!liveScanInProgress) {
      return undefined;
    }

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
  }, [activeView, reportFilters, jobFilters, liveScanInProgress]);

  useEffect(() => {
    if (!dashboard.findings.length) {
      setSelectedFinding(null);
      return;
    }

    setSelectedFinding((current) => {
      if (!current) {
        return dashboard.findings[0];
      }

      return (
        dashboard.findings.find((finding) => finding.id === current.id) ||
        dashboard.findings[0]
      );
    });
  }, [dashboard.findings]);

  if (!auth?.token) {
    return (
      <div className="app-shell auth-shell">
        <main className="workspace auth-workspace">
          <section className="panel form-panel auth-panel">
            <div className="panel-header">
              <div>
                <h3>SecureFlow Access</h3>
                <p className="panel-copy">
                  Sign in to access scans, analytics, reports, and remediation actions.
                </p>
              </div>
              <span className="soft-pill">JWT Auth</span>
            </div>

            {error ? <div className="banner error">{error}</div> : null}

            <form className="repo-form" onSubmit={submitAuth}>
              <label>
                <span>Full Name</span>
                <input
                  type="text"
                  value={loginForm.name}
                  disabled={loginForm.mode !== "register"}
                  onChange={(event) =>
                    setLoginForm((current) => ({ ...current, name: event.target.value }))
                  }
                  placeholder="SecureFlow User"
                />
              </label>

              <label>
                <span>Email</span>
                <input
                  type="email"
                  value={loginForm.email}
                  onChange={(event) =>
                    setLoginForm((current) => ({ ...current, email: event.target.value }))
                  }
                  required
                />
              </label>

              <label>
                <span>Password</span>
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={(event) =>
                    setLoginForm((current) => ({ ...current, password: event.target.value }))
                  }
                  required
                />
              </label>

              <div className="form-row">
                <button className="action-button" type="submit">
                  {loginForm.mode === "register" ? "Create Account" : "Sign In"}
                </button>
                <button
                  className="action-button secondary-button"
                  type="button"
                  onClick={() =>
                    setLoginForm((current) => ({
                      ...current,
                      mode: current.mode === "login" ? "register" : "login",
                    }))
                  }
                >
                  {loginForm.mode === "login" ? "Switch To Register" : "Switch To Login"}
                </button>
              </div>
            </form>
          </section>
        </main>
      </div>
    );
  }

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
            <span className="soft-pill">{auth.user?.role || "developer"}</span>
            <button className="status-pill" onClick={refreshAll}>
              Sync Status
            </button>
            <button className="status-pill" onClick={clearAuth}>
              Sign Out
            </button>
            <span className={`hero-badge ${statusTone(dashboard.latestSubmission?.status)}`}>
              {dashboard.latestSubmission?.status || "idle"}
            </span>
          </div>
        </section>

        {error ? <div className="banner error">{error}</div> : null}
        {success ? <div className="banner success">{success}</div> : null}
        {remediationMessage ? (
          <div className="banner success">{remediationMessage}</div>
        ) : null}
        {loadingDashboard ? (
          <div className="banner">Loading platform telemetry...</div>
        ) : null}

        <section className="summary-grid">
          <article className="summary-card score-card">
            <span>Security Score</span>
            <strong>{dashboard.latestSecurityScore?.score ?? 100}</strong>
            <p>
              {dashboard.latestSecurityScore?.riskLevel || "secure"} / avg{" "}
              {dashboard.metrics.securityScoreAverage ?? 0}
            </p>
          </article>
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
                <h3>Security Analytics</h3>
                <p className="panel-copy">
                  Score movement, risk level, and repository posture over time.
                </p>
              </div>
              <span className={`severity-badge ${riskTone(dashboard.latestSecurityScore?.riskLevel)}`}>
                {dashboard.latestSecurityScore?.riskLevel || "secure"}
              </span>
            </div>

            <div className="score-hero">
              <div className="score-ring">
                <strong>{dashboard.latestSecurityScore?.score ?? 100}</strong>
                <span>score</span>
              </div>
              <div className="score-copy">
                <p>
                  Trend delta: {formatDelta(dashboard.securityAnalytics?.delta || 0)}
                </p>
                <p>
                  Secrets: {dashboard.latestSecurityScore?.contributingFactors?.secrets || 0}
                  {" "} / Dependencies:{" "}
                  {dashboard.latestSecurityScore?.contributingFactors?.dependencies || 0}
                </p>
                <p>
                  Badge grade: {dashboard.latestSecurityScore?.badge?.label || "A"}
                </p>
              </div>
            </div>

            <div className="chart-list">
              {scoreTrend.length ? (
                scoreTrend.map((item) => (
                  <div className="chart-row" key={item.reportId}>
                    <div className="chart-label">
                      <span>{formatTimestamp(item.createdAt)}</span>
                      <strong>{item.score}</strong>
                    </div>
                    <div className="chart-track">
                      <div
                        className={`chart-fill ${riskTone(item.riskLevel)}`}
                        style={{ width: `${item.width}%` }}
                      />
                    </div>
                  </div>
                ))
              ) : (
                <p className="panel-copy">Run more scans to build score history.</p>
              )}
            </div>
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

                <div className="insight-status-row">
                  <span className="soft-pill">{findingInsightStatus(selectedFinding)}</span>
                  <span className="detail-meta">
                    {selectedFinding.ai?.provider || "local"} /{" "}
                    {selectedFinding.ai?.model || "heuristic"}
                  </span>
                </div>

                <button
                  className="action-button secondary-button"
                  onClick={createRemediationPullRequest}
                  disabled={
                    creatingRemediation ||
                    !dashboard.latestReportId ||
                    auth.user?.role === "viewer"
                  }
                  type="button"
                >
                  {creatingRemediation
                    ? "Creating Pull Request..."
                    : "Create Remediation Pull Request"}
                </button>

                <details className="insight-section" open>
                  <summary>AI explanation</summary>
                  <p>
                    {selectedFinding.ai?.summary ||
                      "Insight is not available for this finding yet."}
                  </p>
                  <p>
                    <strong>Why it matters:</strong>{" "}
                    {selectedFinding.ai?.whyItMatters ||
                      "Review the affected code path and confirm the real exploitability before triaging."}
                  </p>
                </details>

                <details className="insight-section" open>
                  <summary>Potential impact</summary>
                  <ul className="insight-list">
                    {formatList(selectedFinding.ai?.potentialImpact).length ? (
                      formatList(selectedFinding.ai?.potentialImpact).map((item) => (
                        <li key={item}>{item}</li>
                      ))
                    ) : (
                      <li>Impact analysis is not available yet for this finding.</li>
                    )}
                  </ul>
                </details>

                <details className="insight-section" open>
                  <summary>Remediation steps</summary>
                  <ol className="insight-list ordered">
                    {formatList(selectedFinding.ai?.remediationSteps).length ? (
                      formatList(selectedFinding.ai?.remediationSteps).map((item) => (
                        <li key={item}>{item}</li>
                      ))
                    ) : (
                      <li>Review the affected file, patch the root cause, and rerun the scan.</li>
                    )}
                  </ol>
                </details>

                <details className="insight-section">
                  <summary>Secure coding tips</summary>
                  <ul className="insight-list">
                    {formatList(selectedFinding.ai?.secureCodingTips).length ? (
                      formatList(selectedFinding.ai?.secureCodingTips).map((item) => (
                        <li key={item}>{item}</li>
                      ))
                    ) : (
                      <li>Prefer framework security controls and automated regression tests.</li>
                    )}
                  </ul>
                </details>

                {selectedFinding.ai?.disclaimer ? (
                  <div className="insight-note">{selectedFinding.ai.disclaimer}</div>
                ) : null}
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
                    <p>
                      <a
                        href={`${apiBaseUrl}/reports/${report.id}/download.pdf`}
                        onClick={(event) => {
                          event.preventDefault();
                          fetchWithAuth(`${apiBaseUrl}/reports/${report.id}/download.pdf`)
                            .then(async (response) => {
                              if (!response.ok) {
                                const payload = await parseApiResponse(response);
                                throw new Error(
                                  payload.message || "Unable to download the PDF report.",
                                );
                              }

                              return response.blob();
                            })
                            .then((blob) => {
                              const url = URL.createObjectURL(blob);
                              const link = document.createElement("a");
                              link.href = url;
                              link.download = `secureflow-report-${report.id}.pdf`;
                              link.click();
                              URL.revokeObjectURL(url);
                            })
                            .catch((downloadError) => setError(downloadError.message));
                        }}
                      >
                        Download PDF report
                      </a>
                    </p>
                  </div>
                  <div className="history-meta">
                    <button
                      className="icon-button danger-button"
                      type="button"
                      onClick={(event) => deleteReportHistory(event, report.id)}
                      disabled={
                        auth.user?.role === "viewer" || deletingReportId === report.id
                      }
                      title="Delete report history"
                      aria-label="Delete report history"
                    >
                      {deletingReportId === report.id ? "Deleting..." : "Delete"}
                    </button>
                    <span>
                      Score {report.securityScore?.score ?? 100} /{" "}
                      {report.securityScore?.riskLevel || "secure"}
                    </span>
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
                    <button
                      className="icon-button danger-button"
                      type="button"
                      onClick={(event) => deleteScanHistory(event, job.id)}
                      disabled={
                        auth.user?.role === "viewer" || deletingReportId === job.id
                      }
                      title="Delete scan history"
                      aria-label="Delete scan history"
                    >
                      {deletingReportId === job.id ? "Deleting..." : "Delete"}
                    </button>
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
