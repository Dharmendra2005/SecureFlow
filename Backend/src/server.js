const config = require("./config/env");
const { connectDatabase } = require("./config/db");
const { createRedisConnection } = require("./config/redis");
const { createScanQueue, createScanQueueEvents } = require("./queues/scanQueue");
const { createScanWorker } = require("./workers/scanWorker");
const { createApp } = require("./app");
const { updateScanJobByQueueId } = require("./services/scanJobService");

const startServer = async () => {
  await connectDatabase(config.mongodb.uri);

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
    await updateScanJobByQueueId(jobId, {
      status: "active",
      startedAt: new Date(),
      lastError: "",
    });
  });

  queueEvents.on("completed", async ({ jobId }) => {
    await updateScanJobByQueueId(jobId, {
      status: "completed",
      completedAt: new Date(),
    });
  });

  queueEvents.on("failed", async ({ jobId, failedReason }) => {
    await updateScanJobByQueueId(jobId, {
      status: "failed",
      failedAt: new Date(),
      lastError: failedReason || "Scan job failed.",
    });
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
