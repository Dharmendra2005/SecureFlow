const mongoose = require("mongoose");

const scanJobSchema = new mongoose.Schema(
  {
    repository: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Repository",
      required: true,
    },
    tool: {
      type: String,
      required: true,
      trim: true,
    },
    scanType: {
      type: String,
      default: "Quick Scan",
      trim: true,
    },
    status: {
      type: String,
      enum: ["pending", "active", "completed", "failed"],
      default: "pending",
    },
    triggeredBy: {
      type: String,
      default: "system",
      trim: true,
    },
    queueJobId: {
      type: String,
      default: "",
      trim: true,
    },
    repositoryPath: {
      type: String,
      default: "",
      trim: true,
    },
    userDetails: {
      type: Object,
      default: {},
    },
    metadata: {
      type: Object,
      default: {},
    },
    startedAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    failedAt: {
      type: Date,
      default: null,
    },
    lastError: {
      type: String,
      default: "",
      trim: true,
    },
    attemptsMade: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("ScanJob", scanJobSchema);
