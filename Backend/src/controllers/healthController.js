const Repository = require("../models/Repository");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");
const { getDatabaseHealth } = require("../config/db");
const { getRedisHealth } = require("../config/redis");

const getHealth = async (req, res) => {
  const { redisClient, queue, config } = req.app.locals;
  const [redis, queueCounts] = await Promise.all([
    getRedisHealth(redisClient),
    queue.getJobCounts("waiting", "active", "completed", "failed"),
  ]);

  const database = getDatabaseHealth();
  const overallStatus =
    database.status === "connected" && redis.status === "connected"
      ? "ok"
      : "degraded";

  res.json({
    status: overallStatus,
    timestamp: new Date().toISOString(),
    app: {
      name: config.app.name,
      env: config.app.env,
    },
    services: {
      database,
      redis,
      queue: {
        name: config.queue.name,
        status: redis.status === "connected" ? "ready" : "waiting",
        counts: queueCounts,
      },
    },
  });
};

const getDashboardSnapshot = async (req, res) => {
  const [repositoryCount, scanJobCount, vulnerabilityReports, recentRepositories, latestScanJob] = await Promise.all([
    Repository.countDocuments(),
    ScanJob.countDocuments(),
    VulnerabilityReport.find()
      .sort({ createdAt: -1 })
      .populate("repository", "name branch provider")
      .limit(5)
      .lean(),
    Repository.find().sort({ updatedAt: -1 }).limit(5).lean(),
    ScanJob.findOne().sort({ createdAt: -1 }).populate("repository").lean(),
  ]);

  const severityTotals = vulnerabilityReports.reduce(
    (accumulator, report) => {
      accumulator.total += report.summary.total || 0;
      accumulator.critical += report.summary.critical || 0;
      accumulator.high += report.summary.high || 0;
      accumulator.medium += report.summary.medium || 0;
      accumulator.low += report.summary.low || 0;
      return accumulator;
    },
    {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  );

  const latestFindings =
    vulnerabilityReports[0]?.findings?.map((finding, index) => ({
      id: finding.id || `F-${index + 1}`,
      tool: finding.tool || "semgrep",
      category: finding.category || "Security Rule",
      location: finding.location || "src/unknown.js",
      severity: finding.severity || "medium",
      description: finding.description || "",
    })) || [];

  res.json({
    metrics: {
      repositories: repositoryCount,
      scanJobs: scanJobCount,
      vulnerabilityReports: vulnerabilityReports.length,
      severityTotals,
    },
    latestSubmission: latestScanJob
      ? {
          repository: latestScanJob.repository?.name || "Unknown repository",
          repositoryUrl: latestScanJob.repository?.url || "",
          branch: latestScanJob.repository?.branch || "main",
          status: latestScanJob.status,
          scanMode: latestScanJob.metadata?.scanMode || "Quick Scan",
          tool: latestScanJob.tool,
        }
      : null,
    repositories: recentRepositories.map((repository) => ({
      id: repository._id,
      name: repository.name,
      owner: repository.owner,
      url: repository.url,
      branch: repository.branch,
      provider: repository.provider,
      localPath: repository.localPath,
      cloneStatus: repository.cloneStatus,
      submittedAt: repository.submittedAt,
    })),
    findings: latestFindings,
    recentReports: vulnerabilityReports.map((report) => ({
      id: report._id,
      repository: report.repository?.name || "Unknown repository",
      repositoryUrl: report.repository?.url || "",
      branch: report.repository?.branch || "main",
      provider: report.repository?.provider || "unknown",
      summary: report.summary,
      createdAt: report.createdAt,
    })),
  });
};

module.exports = {
  getHealth,
  getDashboardSnapshot,
};
