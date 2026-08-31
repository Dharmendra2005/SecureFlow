const mongoose = require("mongoose");

const DEFAULT_LOCAL_MONGODB_URI = "mongodb://127.0.0.1:27018/secureflow";

let databaseConnectionState = {
  status: "disconnected",
  lastError: null,
};

const shouldRetryWithLocalFallback = (error, attemptedUri) => {
  if (!attemptedUri || attemptedUri === DEFAULT_LOCAL_MONGODB_URI) {
    return false;
  }

  const normalizedError = (error?.message || "").toLowerCase();
  return (
    error?.code === "ENOTFOUND" ||
    normalizedError.includes("querysrv") ||
    normalizedError.includes("enotfound") ||
    normalizedError.includes("mongodb+srv")
  );
};

const connectDatabase = async (uri, options = {}) => {
  const candidateUris = [];
  const normalizedUri = typeof uri === "string" ? uri.trim() : "";

  if (normalizedUri) {
    candidateUris.push(normalizedUri);
  }

  if (!candidateUris.length || normalizedUri.startsWith("mongodb+srv://")) {
    candidateUris.push(DEFAULT_LOCAL_MONGODB_URI);
  }

  let lastError;

  for (const candidateUri of candidateUris) {
    try {
      await mongoose.connect(candidateUri, {
        serverSelectionTimeoutMS: 10000,
        connectTimeoutMS: 10000,
        ...options,
      });
      databaseConnectionState = {
        status: "connected",
        lastError: null,
      };
      return;
    } catch (error) {
      lastError = error;
      if (!shouldRetryWithLocalFallback(error, candidateUri)) {
        break;
      }
    }
  }

  databaseConnectionState = {
    status: "error",
    lastError: lastError?.message || "Unknown MongoDB connection error",
  };
  throw lastError;
};

const getDatabaseHealth = () => ({
  status:
    mongoose.connection.readyState === 1
      ? "connected"
      : databaseConnectionState.status,
  readyState: mongoose.connection.readyState,
  name: mongoose.connection.name || null,
  host: mongoose.connection.host || null,
  lastError: databaseConnectionState.lastError,
});

module.exports = {
  connectDatabase,
  getDatabaseHealth,
};
