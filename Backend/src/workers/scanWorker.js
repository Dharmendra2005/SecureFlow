const { Worker } = require("bullmq");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");
const config = require("../config/env");
const { runRepositoryScans } = require("../services/scannerEngineService");
const { enrichFindingsWithInsights } = require("../services/vulnerabilityInsightService");
const { calculateSecurityScore } = require("../services/securityScoreService");
const {
  canSendGitHubFeedback,
  createCommitStatus,
  createPullRequestComment,
} = require("../services/githubFeedbackService");

const buildPullRequestComment = ({ repository, report }) => {
  const summary = report.summary || {};

  return [
    "## SecureFlow Scan Summary",
    "",
    `Repository: ${repository?.name || "Unknown repository"}`,
    `Total findings: ${summary.total || 0}`,
    `Critical: ${summary.critical || 0}`,
    `High: ${summary.high || 0}`,
    `Medium: ${summary.medium || 0}`,
    `Low: ${summary.low || 0}`,
    "",
    "Review the SecureFlow dashboard for full finding details and AI remediation guidance.",
  ].join("\n");
};

const createScanWorker = ({ queueName, connection }) =>
  new Worker(
    queueName,
    async (job) => {
      await ScanJob.findByIdAndUpdate(job.data.scanJobId, {
        status: "active",
        startedAt: new Date(),
        attemptsMade: job.attemptsMade + 1,
        lastError: "",
      });

      await new Promise((resolve) => {
        setTimeout(resolve, 1200);
      });

      const scanOutput = await runRepositoryScans({
        repoPath: job.data.repoPath,
        scanType: job.data.scanMode,
        targetUrl: job.data.targetUrl,
      });

      const insightOutput = await enrichFindingsWithInsights(scanOutput.findings);
      const securityScore = calculateSecurityScore({
        summary: scanOutput.summary,
        findings: insightOutput.findings,
      });

      const report = await VulnerabilityReport.create({
        repository: job.data.repositoryId,
        scanJob: job.data.scanJobId,
        summary: scanOutput.summary,
        findings: insightOutput.findings,
        toolRuns: scanOutput.toolRuns,
        securityScore,
      });

      const existingJob = await ScanJob.findById(job.data.scanJobId).lean();

      await ScanJob.findByIdAndUpdate(job.data.scanJobId, {
        status: "completed",
        completedAt: new Date(),
        failedAt: null,
        metadata: {
          ...(existingJob?.metadata || {}),
          scannerEngine: {
            toolRuns: scanOutput.toolRuns,
            findingsCount: scanOutput.findings.length,
          },
          aiInsights: {
            provider: config.ai.provider,
            model: config.ai.model,
            usage: insightOutput.usage,
          },
          securityScore,
        },
      });

      if (canSendGitHubFeedback(existingJob?.metadata)) {
        const github = existingJob.metadata.github;
        const dashboardUrl = `${config.app.clientUrl}`;
        const commitStatusState =
          (report.summary?.critical || 0) > 0 || (report.summary?.high || 0) > 0
            ? "failure"
            : "success";
        const description =
          commitStatusState === "failure"
            ? `SecureFlow found ${report.summary.total} issue(s), including high-severity findings.`
            : `SecureFlow scan completed with ${report.summary.total} finding(s).`;

        try {
          await createCommitStatus({
            owner: github.owner,
            repo: github.repo,
            sha: github.commitSha,
            state: commitStatusState,
            description,
            targetUrl: dashboardUrl,
          });

          if (github.pullRequestNumber) {
            await createPullRequestComment({
              owner: github.owner,
              repo: github.repo,
              issueNumber: github.pullRequestNumber,
              body: buildPullRequestComment({
                repository: job.data,
                report,
              }),
            });
          }
        } catch (error) {
          console.error("Failed to send GitHub scan completion feedback", {
            scanJobId: job.data.scanJobId,
            error: error.message,
          });
        }
      }

      return {
        scanType: job.data.scanMode,
        repositoryPath: job.data.repoPath,
        completedAt: new Date().toISOString(),
      };
    },
    {
      connection,
      concurrency: 4,
    },
  );

module.exports = {
  createScanWorker,
};
