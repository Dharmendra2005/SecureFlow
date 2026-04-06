const User = require("../models/User");
const {
  normalizeEmail,
  createPasswordHash,
  verifyPassword,
  issueAccessToken,
  serializeUser,
} = require("../services/authService");

const validatePassword = (password) =>
  typeof password === "string" && password.length >= 8;

const register = async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const role = "developer";

  if (!name || !email || !validatePassword(password)) {
    return res.status(400).json({
      message: "Name, email, and a password of at least 8 characters are required.",
    });
  }

  const existing = await User.findOne({ email });

  if (existing) {
    return res.status(409).json({
      message: "An account with this email already exists.",
    });
  }

  const user = await User.create({
    name,
    email,
    passwordHash: createPasswordHash(password),
    role,
  });

  const token = issueAccessToken(user);

  return res.status(201).json({
    message: "Account created successfully.",
    data: {
      token,
      user: serializeUser(user),
    },
  });
};

const login = async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required.",
    });
  }

  const user = await User.findOne({ email });

  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({
      message: "Invalid email or password.",
    });
  }

  if (user.status !== "active") {
    return res.status(403).json({
      message: "This account is disabled.",
    });
  }

  user.lastLoginAt = new Date();
  await user.save();

  return res.json({
    message: "Login successful.",
    data: {
      token: issueAccessToken(user),
      user: serializeUser(user),
    },
  });
};

const me = async (req, res) =>
  res.json({
    data: req.user,
  });

module.exports = {
  register,
  login,
  me,
};
