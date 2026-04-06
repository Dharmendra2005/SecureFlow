const express = require("express");
const cors = require("cors");
const healthRoutes = require("./routes/healthRoutes");
const scanRoutes = require("./routes/scanRoutes");
const reportRoutes = require("./routes/reportRoutes");
const webhookRoutes = require("./routes/webhookRoutes");
const authRoutes = require("./routes/authRoutes");
const { requireAuth } = require("./middleware/authMiddleware");
const {
  createSecurityHeaders,
  createRequestLogger,
  createInMemoryRateLimiter,
} = require("./middleware/securityMiddleware");

const createApp = ({ config, redisClient, queue }) => {
  const app = express();

  app.locals.config = config;
  app.locals.redisClient = redisClient;
  app.locals.queue = queue;
  app.set("trust proxy", config.app.trustProxy);

  app.use(
    cors({
      origin: config.app.clientUrl,
    }),
  );
  app.use(createRequestLogger);
  app.use(createSecurityHeaders);
  app.use(
    createInMemoryRateLimiter({
      windowMs: 60 * 1000,
      maxRequests: 120,
    }),
  );
  app.use("/api/webhook", express.raw({ type: "application/json" }), webhookRoutes);
  app.use(express.json());

  app.get("/", (req, res) => {
    res.json({
      message: "SecureFlow backend is up and ready for Phase 0.",
    });
  });

  app.use("/api", healthRoutes);
  app.use("/api", authRoutes);
  app.use("/api", requireAuth, scanRoutes);
  app.use("/api", requireAuth, reportRoutes);

  app.use((error, req, res, next) => {
    res.status(500).json({
      message: "Unexpected server error.",
      error: error.message,
    });
  });

  return app;
};

module.exports = {
  createApp,
};
