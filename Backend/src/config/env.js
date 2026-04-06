const path = require("path");
const dotenv = require("dotenv");

dotenv.config({
  path: path.resolve(__dirname, "../../.env"),
});

const toNumber = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const toStringWithDefault = (value, fallback) =>
  value === undefined ? fallback : value;

module.exports = {
  app: {
    name: process.env.APP_NAME || "SecureFlow API",
    env: process.env.NODE_ENV || "development",
    port: toNumber(process.env.PORT, 5000),
    clientUrl: process.env.CLIENT_URL || "http://localhost:5173",
    trustProxy: String(process.env.TRUST_PROXY || "false").toLowerCase() === "true",
  },
  mongodb: {
    uri:
      process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/secureflow",
  },
  redis: {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: toNumber(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || "",
    db: toNumber(process.env.REDIS_DB, 0),
  },
  queue: {
    name: process.env.SCAN_QUEUE_NAME || "security-scans",
  },
  repositoryWorkspace:
    process.env.REPOSITORY_WORKSPACE ||
    path.resolve(__dirname, "../../workspace/repos"),
  tools: {
    python: toStringWithDefault(process.env.PYTHON_PATH, "python"),
    semgrepCommand: toStringWithDefault(process.env.SEMGREP_COMMAND, ""),
    semgrepArgs: toStringWithDefault(process.env.SEMGREP_ARGS, "-m semgrep"),
    pipAuditCommand: toStringWithDefault(process.env.PIP_AUDIT_COMMAND, ""),
    pipAuditArgs: toStringWithDefault(process.env.PIP_AUDIT_ARGS, "-m pip_audit"),
    gitleaksPath: toStringWithDefault(process.env.GITLEAKS_PATH, "gitleaks"),
    trivyPath: toStringWithDefault(process.env.TRIVY_PATH, "trivy"),
    dockerPath: toStringWithDefault(process.env.DOCKER_PATH, "docker"),
  },
  ai: {
    enabled: String(process.env.AI_INSIGHTS_ENABLED || "true").toLowerCase() !== "false",
    provider: process.env.AI_PROVIDER || "openai",
    apiKey: process.env.OPENAI_API_KEY || "",
    model: process.env.OPENAI_MODEL || "gpt-4o-mini",
    baseUrl:
      process.env.OPENAI_CHAT_COMPLETIONS_URL ||
      "https://api.openai.com/v1/chat/completions",
  },
  github: {
    token: process.env.GITHUB_TOKEN || "",
    apiBaseUrl: process.env.GITHUB_API_BASE_URL || "https://api.github.com",
    branchPrefix: process.env.GITHUB_FIX_BRANCH_PREFIX || "secureflow/fix",
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || "",
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET || "change-me-in-production",
    jwtExpiresInHours: toNumber(process.env.JWT_EXPIRES_IN_HOURS, 12),
    bootstrapAdminName: process.env.BOOTSTRAP_ADMIN_NAME || "SecureFlow Admin",
    bootstrapAdminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL || "",
    bootstrapAdminPassword: process.env.BOOTSTRAP_ADMIN_PASSWORD || "",
  },
};
