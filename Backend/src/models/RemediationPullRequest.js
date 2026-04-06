const mongoose = require("mongoose");

const remediationPullRequestSchema = new mongoose.Schema(
  {
    repository: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Repository",
      required: true,
    },
    scanJob: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ScanJob",
      required: true,
    },
    report: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "VulnerabilityReport",
      required: true,
    },
    findingId: {
      type: String,
      required: true,
      trim: true,
    },
    branchName: {
      type: String,
      default: "",
      trim: true,
    },
    baseBranch: {
      type: String,
      default: "main",
      trim: true,
    },
    title: {
      type: String,
      default: "",
      trim: true,
    },
    body: {
      type: String,
      default: "",
      trim: true,
    },
    commitMessage: {
      type: String,
      default: "",
      trim: true,
    },
    status: {
      type: String,
      enum: ["pending", "completed", "unsupported", "failed"],
      default: "pending",
    },
    provider: {
      type: String,
      default: "github",
      trim: true,
    },
    pullRequestNumber: {
      type: Number,
      default: null,
    },
    pullRequestUrl: {
      type: String,
      default: "",
      trim: true,
    },
    commitSha: {
      type: String,
      default: "",
      trim: true,
    },
    appliedFiles: {
      type: [String],
      default: [],
    },
    remediationSummary: {
      type: String,
      default: "",
      trim: true,
    },
    metadata: {
      type: Object,
      default: {},
    },
    failureReason: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true,
  },
);

remediationPullRequestSchema.index({ report: 1, findingId: 1, createdAt: -1 });
remediationPullRequestSchema.index({ repository: 1, createdAt: -1 });
remediationPullRequestSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model(
  "RemediationPullRequest",
  remediationPullRequestSchema,
);
