const { Worker } = require("bullmq");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");

const scanTemplates = {
  "Quick Scan": [
    {
      id: "SG-102",
      tool: "Semgrep",
      category: "Secrets Exposure",
      location: "src/config/github.js:18",
      severity: "high",
      description: "Potential hard-coded token detected in repository configuration.",
    },
    {
      id: "SG-214",
      tool: "Semgrep",
      category: "Dependency Hygiene",
      location: "package.json:27",
      severity: "medium",
      description: "Outdated package version should be reviewed before deployment.",
    },
  ],
  "Full Scan": [
    {
      id: "SG-301",
      tool: "Semgrep",
      category: "Injection Risk",
      location: "server/routes/webhook.js:44",
      severity: "critical",
      description: "Unsanitized input reaches a sensitive execution path.",
    },
    {
      id: "SG-144",
      tool: "Semgrep",
      category: "Access Control",
      location: "src/api/admin.ts:12",
      severity: "high",
      description: "Administrative endpoint is missing an authorization guard.",
    },
    {
      id: "SG-219",
      tool: "Semgrep",
      category: "Dependency Hygiene",
      location: "package-lock.json:1",
      severity: "medium",
      description: "Package lock contains a dependency with a known advisory.",
    },
    {
      id: "SG-411",
      tool: "Semgrep",
      category: "Logging",
      location: "src/utils/logger.ts:9",
      severity: "low",
      description: "Verbose logging may expose internal request details.",
    },
  ],
};

const summarizeFindings = (findings) =>
  findings.reduce(
    (summary, finding) => {
      summary.total += 1;
      summary[finding.severity] += 1;
      return summary;
    },
    {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  );

const createScanWorker = ({ queueName, connection }) =>
  new Worker(
    queueName,
    async (job) => {
      await ScanJob.findByIdAndUpdate(job.data.scanJobId, {
        status: "running",
      });

      await new Promise((resolve) => {
        setTimeout(resolve, 1200);
      });

      const findings =
        scanTemplates[job.data.scanMode] || scanTemplates["Quick Scan"];
      const summary = summarizeFindings(findings);

      await VulnerabilityReport.create({
        repository: job.data.repositoryId,
        scanJob: job.data.scanJobId,
        summary,
        findings,
      });

      await ScanJob.findByIdAndUpdate(job.data.scanJobId, {
        status: "completed",
        completedAt: new Date(),
      });

      return {
        completedAt: new Date().toISOString(),
      };
    },
    {
      connection,
    },
  );

module.exports = {
  createScanWorker,
};
