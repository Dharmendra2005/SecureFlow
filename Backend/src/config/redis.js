const IORedis = require("ioredis");

const createRedisConnection = (config) =>
  new IORedis({
    host: config.host,
    port: config.port,
    password: config.password || undefined,
    db: config.db,
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });

const getRedisHealth = async (client) => {
  try {
    const pong = await client.ping();
    return {
      status: pong === "PONG" ? "connected" : "degraded",
      details: pong,
    };
  } catch (error) {
    return {
      status: "error",
      details: error.message,
    };
  }
};

module.exports = {
  createRedisConnection,
  getRedisHealth,
};
