const { Queue, QueueEvents } = require("bullmq");

const createScanQueue = ({ queueName, connection }) =>
  new Queue(queueName, {
    connection,
    defaultJobOptions: {
      removeOnComplete: 50,
      removeOnFail: 100,
      attempts: 2,
      backoff: {
        type: "exponential",
        delay: 1000,
      },
    },
  });

const createScanQueueEvents = ({ queueName, connection }) =>
  new QueueEvents(queueName, {
    connection,
  });

module.exports = {
  createScanQueue,
  createScanQueueEvents,
};
