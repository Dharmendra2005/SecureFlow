const express = require("express");
const { enqueueScan } = require("../controllers/scanController");
const { requireRole } = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/scans", requireRole("admin", "developer"), enqueueScan);

module.exports = router;
