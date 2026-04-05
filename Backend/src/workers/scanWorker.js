const { Worker } = require("bullmq");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");
const { runRepositoryScans } = require("../services/scannerEngineService");

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

      await VulnerabilityReport.create({
        repository: job.data.repositoryId,
        scanJob: job.data.scanJobId,
        summary: scanOutput.summary,
        findings: scanOutput.findings,
        toolRuns: scanOutput.toolRuns,
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
        },
      });

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
