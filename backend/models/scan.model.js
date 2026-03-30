import mongoose from "mongoose";

const scanSchema = new mongoose.Schema(
  {
    target: {
      type: String,
      required: true,
      index: true,
    },
    type: {
      type: String,
      required: true,
      enum: ["url", "ip", "file"],
    },
    stats: {
      malicious: { type: Number, default: 0 },
      harmless: { type: Number, default: 0 },
      suspicious: { type: Number, default: 0 },
      undetected: { type: Number, default: 0 },
    },
    attributes: {
      statusCode: Number,
      contentType: String,
      lastAnalysisDate: Date,
      trackersCount: { type: Number, default: 0 },
      iframesCount: { type: Number, default: 0 },
    },
    aiAnalysis: {
      riskScore: Number,
      summary: String,
      threatCategory: {
        type: String,
        enum: ["safe", "suspicious", "malicious", "unknown"],
      },
      recommendations: [String],

      keyInsights: [String],
      confidence: {
        type: String,
        enum: ["low", "medium", "high"],
      },
    },
    vendors: {
      count: { type: Number, default: 0 },
      names: [{ type: String }],
    },

    geo: {
      country: { type: String, default: "Unknown" },
    },

    resolvedIP: {
      type: String,
      default: null,
    },

    vendorVerdict: {
      flagged: Number,
      total: Number,
      percentage: Number,
      label: String,
      color: String,
    },

    engineResults: [
      {
        engine: String,
        verdict: String,
      },
    ],

    rawReport: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true },
);

scanSchema.index({ target: 1, type: 1 });

export default mongoose.model("Scan", scanSchema);
