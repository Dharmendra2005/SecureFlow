const path = require("path");
const dotenv = require("dotenv");

dotenv.config({
  path: path.resolve(__dirname, "../../.env"),
});

const toNumber = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

module.exports = {
  app: {
    name: process.env.APP_NAME || "SecureFlow API",
    env: process.env.NODE_ENV || "development",
    port: toNumber(process.env.PORT, 5000),
    clientUrl: process.env.CLIENT_URL || "http://localhost:5173",
  },
  mongodb: {
    uri:
      process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/secureflow",
  },
  redis: {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: toNumber(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || "",
    db: toNumber(process.env.REDIS_DB, 0),
  },
  queue: {
    name: process.env.SCAN_QUEUE_NAME || "security-scans",
  },
  repositoryWorkspace:
    process.env.REPOSITORY_WORKSPACE ||
    path.resolve(__dirname, "../../workspace/repos"),
};
