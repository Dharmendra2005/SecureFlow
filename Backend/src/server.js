const config = require("./config/env");
const { connectDatabase } = require("./config/db");
const { createRedisConnection } = require("./config/redis");
const { createScanQueue } = require("./queues/scanQueue");
const { createScanWorker } = require("./workers/scanWorker");
const { createApp } = require("./app");

const startServer = async () => {
  await connectDatabase(config.mongodb.uri);

  const redisClient = createRedisConnection(config.redis);
  const queueConnection = redisClient.duplicate();

  const queue = createScanQueue({
    queueName: config.queue.name,
    connection: queueConnection,
  });

  const workerConnection = redisClient.duplicate();
  const worker = createScanWorker({
    queueName: config.queue.name,
    connection: workerConnection,
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
