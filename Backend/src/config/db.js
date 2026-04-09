const mongoose = require("mongoose");

let databaseConnectionState = {
  status: "disconnected",
  lastError: null,
};

const connectDatabase = async (uri, options = {}) => {
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      ...options,
    });
    databaseConnectionState = {
      status: "connected",
      lastError: null,
    };
  } catch (error) {
    databaseConnectionState = {
      status: "error",
      lastError: error.message,
    };
    throw error;
  }
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
