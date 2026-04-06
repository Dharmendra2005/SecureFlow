const config = require("./config/env");
const { connectDatabase } = require("./config/db");
const { createRedisConnection } = require("./config/redis");
const { createScanQueue, createScanQueueEvents } = require("./queues/scanQueue");
const { createScanWorker } = require("./workers/scanWorker");
const { createApp } = require("./app");
const { updateScanJobByQueueId } = require("./services/scanJobService");
const { ensureBootstrapAdmin } = require("./services/authService");
const {
  canSendGitHubFeedback,
  createCommitStatus,
} = require("./services/githubFeedbackService");

const startServer = async () => {
  await connectDatabase(config.mongodb.uri);
  await ensureBootstrapAdmin();

  const redisClient = createRedisConnection(config.redis);
  const queueConnection = redisClient.duplicate();

  const queue = createScanQueue({
    queueName: config.queue.name,
    connection: queueConnection,
  });

  const queueEventsConnection = redisClient.duplicate();
  const queueEvents = createScanQueueEvents({
    queueName: config.queue.name,
    connection: queueEventsConnection,
  });
  await queueEvents.waitUntilReady();

  const workerConnection = redisClient.duplicate();
  const worker = createScanWorker({
    queueName: config.queue.name,
    connection: workerConnection,
  });

  queueEvents.on("active", async ({ jobId }) => {
    const scanJob = await updateScanJobByQueueId(jobId, {
      status: "active",
      startedAt: new Date(),
      lastError: "",
    });

    if (scanJob && canSendGitHubFeedback(scanJob.metadata)) {
      const github = scanJob.metadata.github;

      try {
        await createCommitStatus({
          owner: github.owner,
          repo: github.repo,
          sha: github.commitSha,
          state: "pending",
          description: "SecureFlow scan is in progress.",
          targetUrl: config.app.clientUrl,
        });
      } catch (error) {
        console.error("Failed to send GitHub pending status", {
          queueJobId: jobId,
          error: error.message,
        });
      }
    }
  });

  queueEvents.on("completed", async ({ jobId }) => {
    await updateScanJobByQueueId(jobId, {
      status: "completed",
      completedAt: new Date(),
    });
  });

  queueEvents.on("failed", async ({ jobId, failedReason }) => {
    const scanJob = await updateScanJobByQueueId(jobId, {
      status: "failed",
      failedAt: new Date(),
      lastError: failedReason || "Scan job failed.",
    });

    if (scanJob && canSendGitHubFeedback(scanJob.metadata)) {
      const github = scanJob.metadata.github;

      try {
        await createCommitStatus({
          owner: github.owner,
          repo: github.repo,
          sha: github.commitSha,
          state: "error",
          description: "SecureFlow scan failed before completion.",
          targetUrl: config.app.clientUrl,
        });
      } catch (error) {
        console.error("Failed to send GitHub failure status", {
          queueJobId: jobId,
          error: error.message,
        });
      }
    }
  });

  worker.on("failed", (job, error) => {
    console.error("Scan worker failed", {
      jobId: job?.id,
      error: error.message,
    });
  });

  const app = createApp({
    config,
    redisClient,
    queue,
  });

  app.listen(config.app.port, () => {
    console.log(
      `${config.app.name} listening on http://localhost:${config.app.port}`,
    );
  });
};

startServer().catch((error) => {
  console.error("Failed to start SecureFlow backend", error);
  process.exit(1);
});
