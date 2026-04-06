const crypto = require("crypto");
const User = require("../models/User");
const config = require("../config/env");

const TOKEN_VERSION = "v1";

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

const encodeBase64Url = (value) =>
  Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const decodeBase64Url = (value) =>
  Buffer.from(
    String(value || "")
      .replace(/-/g, "+")
      .replace(/_/g, "/"),
    "base64",
  ).toString("utf8");

const createPasswordHash = (password) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${TOKEN_VERSION}:${salt}:${derived}`;
};

const verifyPassword = (password, passwordHash) => {
  const [, salt, expected] = String(passwordHash || "").split(":");

  if (!salt || !expected) {
    return false;
  }

  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(
    Buffer.from(derived, "hex"),
    Buffer.from(expected, "hex"),
  );
};

const signToken = (payload) => {
  const header = encodeBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = encodeBase64Url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", config.auth.jwtSecret)
    .update(`${header}.${body}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${header}.${body}.${signature}`;
};

const verifyToken = (token) => {
  const [header, body, signature] = String(token || "").split(".");

  if (!header || !body || !signature) {
    throw new Error("Malformed token.");
  }

  const expected = crypto
    .createHmac("sha256", config.auth.jwtSecret)
    .update(`${header}.${body}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  if (signature.length !== expected.length) {
    throw new Error("Invalid token signature.");
  }

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature, "utf8"),
      Buffer.from(expected, "utf8"),
    )
  ) {
    throw new Error("Invalid token signature.");
  }

  const payload = JSON.parse(decodeBase64Url(body));

  if (!payload.exp || Date.now() >= payload.exp * 1000) {
    throw new Error("Token has expired.");
  }

  return payload;
};

const issueAccessToken = (user) => {
  const expiresInSeconds = config.auth.jwtExpiresInHours * 60 * 60;
  const issuedAt = Math.floor(Date.now() / 1000);

  return signToken({
    sub: String(user._id),
    email: user.email,
    role: user.role,
    iat: issuedAt,
    exp: issuedAt + expiresInSeconds,
  });
};

const serializeUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  status: user.status,
  lastLoginAt: user.lastLoginAt,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

const ensureBootstrapAdmin = async () => {
  if (!config.auth.bootstrapAdminEmail || !config.auth.bootstrapAdminPassword) {
    return null;
  }

  const existingUsers = await User.countDocuments();

  if (existingUsers > 0) {
    return null;
  }

  const user = await User.create({
    name: config.auth.bootstrapAdminName,
    email: normalizeEmail(config.auth.bootstrapAdminEmail),
    passwordHash: createPasswordHash(config.auth.bootstrapAdminPassword),
    role: "admin",
  });

  return user;
};

module.exports = {
  normalizeEmail,
  createPasswordHash,
  verifyPassword,
  issueAccessToken,
  verifyToken,
  serializeUser,
  ensureBootstrapAdmin,
};
