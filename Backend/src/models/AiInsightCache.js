const mongoose = require("mongoose");

const aiInsightCacheSchema = new mongoose.Schema(
  {
    cacheKey: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    provider: {
      type: String,
      default: "openai",
      trim: true,
    },
    model: {
      type: String,
      default: "",
      trim: true,
    },
    vulnerabilitySignature: {
      type: Object,
      default: {},
    },
    insight: {
      type: Object,
      required: true,
      default: {},
    },
    lastGeneratedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  },
);

aiInsightCacheSchema.index({ provider: 1, model: 1, updatedAt: -1 });

module.exports = mongoose.model("AiInsightCache", aiInsightCacheSchema);
