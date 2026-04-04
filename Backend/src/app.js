const express = require("express");
const cors = require("cors");
const healthRoutes = require("./routes/healthRoutes");
const scanRoutes = require("./routes/scanRoutes");

const createApp = ({ config, redisClient, queue }) => {
  const app = express();

  app.locals.config = config;
  app.locals.redisClient = redisClient;
  app.locals.queue = queue;

  app.use(
    cors({
      origin: config.app.clientUrl,
    }),
  );
  app.use(express.json());

  app.get("/", (req, res) => {
    res.json({
      message: "SecureFlow backend is up and ready for Phase 0.",
    });
  });

  app.use("/api", healthRoutes);
  app.use("/api", scanRoutes);

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
