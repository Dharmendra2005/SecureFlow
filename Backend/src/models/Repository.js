const mongoose = require("mongoose");

const repositorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    branch: {
      type: String,
      default: "main",
      trim: true,
    },
    provider: {
      type: String,
      default: "github",
      trim: true,
    },
    owner: {
      type: String,
      default: "",
      trim: true,
    },
    scanMode: {
      type: String,
      default: "Quick Scan",
      trim: true,
    },
    localPath: {
      type: String,
      default: "",
      trim: true,
    },
    cloneStatus: {
      type: String,
      enum: ["pending", "cloned", "failed"],
      default: "pending",
    },
    lastCloneError: {
      type: String,
      default: "",
      trim: true,
    },
    submittedAt: {
      type: Date,
      default: Date.now,
    },
    clonedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("Repository", repositorySchema);
