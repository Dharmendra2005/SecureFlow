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
    status: {
      type: String,
      enum: ["queued", "running", "completed", "failed"],
      default: "queued",
    },
    triggeredBy: {
      type: String,
      default: "system",
      trim: true,
    },
    metadata: {
      type: Object,
      default: {},
    },
    completedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("ScanJob", scanJobSchema);
