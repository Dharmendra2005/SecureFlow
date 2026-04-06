const express = require("express");
const { register, login, me } = require("../controllers/authController");
const { requireAuth, requireRole } = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/auth/register", register);
router.post("/auth/login", login);
router.get("/auth/me", requireAuth, me);
router.get("/users/me", requireAuth, me);
router.get("/users/admin-check", requireAuth, requireRole("admin"), (req, res) =>
  res.json({ data: { ok: true } }),
);

module.exports = router;
