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

const toPositiveNumber = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) || parsed <= 0 ? fallback : parsed;
};

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

const listUsers = async (req, res) => {
  const page = toPositiveNumber(req.query.page, 1);
  const limit = Math.min(toPositiveNumber(req.query.limit, 10), 50);
  const skip = (page - 1) * limit;
  const role = String(req.query.role || "").trim().toLowerCase();
  const status = String(req.query.status || "").trim().toLowerCase();
  const search = String(req.query.search || "").trim();

  const query = {
    ...(role ? { role } : {}),
    ...(status ? { status } : {}),
    ...(search
      ? {
          $or: [
            { name: new RegExp(search, "i") },
            { email: new RegExp(search, "i") },
          ],
        }
      : {}),
  };

  const [totalItems, users] = await Promise.all([
    User.countDocuments(query),
    User.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
  ]);

  return res.json({
    data: users.map(serializeUser),
    pagination: {
      page,
      limit,
      totalItems,
      totalPages: Math.ceil(totalItems / limit),
    },
    filters: {
      role,
      status,
      search,
    },
  });
};

const updateUser = async (req, res) => {
  const user = await User.findById(req.params.userId);

  if (!user) {
    return res.status(404).json({
      message: "User not found.",
    });
  }

  const nextRole = req.body.role ? String(req.body.role).trim().toLowerCase() : user.role;
  const nextStatus = req.body.status
    ? String(req.body.status).trim().toLowerCase()
    : user.status;
  const allowedRoles = ["admin", "developer", "viewer"];
  const allowedStatuses = ["active", "disabled"];

  if (!allowedRoles.includes(nextRole)) {
    return res.status(400).json({
      message: "Role must be admin, developer, or viewer.",
    });
  }

  if (!allowedStatuses.includes(nextStatus)) {
    return res.status(400).json({
      message: "Status must be active or disabled.",
    });
  }

  const isSelf = String(req.user.id) === String(user._id);
  const adminCount = await User.countDocuments({ role: "admin", status: "active" });
  const removingActiveAdmin =
    user.role === "admin" &&
    user.status === "active" &&
    (nextRole !== "admin" || nextStatus !== "active");

  if (isSelf && nextStatus !== "active") {
    return res.status(400).json({
      message: "You cannot disable your own account.",
    });
  }

  if (removingActiveAdmin && adminCount <= 1) {
    return res.status(400).json({
      message: "SecureFlow must keep at least one active admin account.",
    });
  }

  user.role = nextRole;
  user.status = nextStatus;
  await user.save();

  return res.json({
    message: "User updated successfully.",
    data: serializeUser(user),
  });
};

module.exports = {
  register,
  login,
  me,
  listUsers,
  updateUser,
};
