const normalizeSeverity = (severity) => String(severity || "").toLowerCase();

const getRiskLevel = (score) => {
  if (score >= 85) {
    return "high-risk";
  }

  if (score >= 55) {
    return "moderate";
  }

  return "secure";
};

const calculateSecurityScore = ({ summary = {}, findings = [] }) => {
  const critical = Number(summary.critical || 0);
  const high = Number(summary.high || 0);
  const medium = Number(summary.medium || 0);
  const low = Number(summary.low || 0);
  const total = Number(summary.total || findings.length || 0);

  const secretCount = findings.filter(
    (finding) =>
      normalizeSeverity(finding.type) === "secrets" ||
      normalizeSeverity(finding.tool) === "gitleaks",
  ).length;
  const dependencyCount = findings.filter(
    (finding) => normalizeSeverity(finding.type) === "dependency",
  ).length;

  const weightedRisk =
    critical * 5 +
    high * 3 +
    medium * 1 +
    low * 0.5 +
    secretCount * 2 +
    dependencyCount * 1.5;

  const normalizedPenalty = Math.min(100, Math.round(weightedRisk * 4));
  const score = Math.max(0, 100 - normalizedPenalty);

  return {
    score,
    weightedRisk,
    riskLevel: getRiskLevel(normalizedPenalty),
    contributingFactors: {
      total,
      critical,
      high,
      medium,
      low,
      secrets: secretCount,
      dependencies: dependencyCount,
    },
    badge: {
      label:
        score >= 80 ? "A" : score >= 65 ? "B" : score >= 50 ? "C" : score >= 35 ? "D" : "F",
      color:
        score >= 80 ? "2ea44f" : score >= 65 ? "3fb950" : score >= 50 ? "d29922" : score >= 35 ? "db6d28" : "cf222e",
    },
  };
};

const buildRepositoryAnalytics = ({ reports = [] }) => {
  const trend = reports
    .map((report) => ({
      reportId: report._id,
      repositoryId: report.repository?._id || report.repository,
      repositoryName: report.repository?.name || "Unknown repository",
      createdAt: report.createdAt,
      score: report.securityScore?.score || 0,
      weightedRisk: report.securityScore?.weightedRisk || 0,
      riskLevel: report.securityScore?.riskLevel || "unknown",
      summary: report.summary || {},
    }))
    .sort((left, right) => new Date(left.createdAt) - new Date(right.createdAt));

  const latest = trend[trend.length - 1] || null;
  const previous = trend.length > 1 ? trend[trend.length - 2] : null;

  return {
    latest,
    previous,
    delta: latest && previous ? latest.score - previous.score : 0,
    trend,
  };
};

module.exports = {
  calculateSecurityScore,
  buildRepositoryAnalytics,
};
