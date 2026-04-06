const User = require("../models/User");
const { verifyToken, serializeUser } = require("../services/authService");

const readBearerToken = (authorizationHeader) => {
  const match = String(authorizationHeader || "").match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
};

const requireAuth = async (req, res, next) => {
  try {
    const token = readBearerToken(req.get("authorization"));

    if (!token) {
      return res.status(401).json({
        message: "Authentication is required.",
      });
    }

    const payload = verifyToken(token);
    const user = await User.findById(payload.sub);

    if (!user || user.status !== "active") {
      return res.status(401).json({
        message: "Your account is not available for access.",
      });
    }

    req.user = serializeUser(user);
    return next();
  } catch (error) {
    return res.status(401).json({
      message: error.message || "Invalid authentication token.",
    });
  }
};

const requireRole = (...allowedRoles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      message: "Authentication is required.",
    });
  }

  if (!allowedRoles.includes(req.user.role)) {
    return res.status(403).json({
      message: "You do not have permission to perform this action.",
    });
  }

  return next();
};

module.exports = {
  requireAuth,
  requireRole,
};
