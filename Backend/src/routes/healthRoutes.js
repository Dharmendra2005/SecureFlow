const express = require("express");
const {
  getHealth,
  getDashboardSnapshot,
} = require("../controllers/healthController");

const router = express.Router();

router.get("/health", getHealth);
router.get("/dashboard", getDashboardSnapshot);

module.exports = router;
