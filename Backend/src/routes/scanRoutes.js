const express = require("express");
const { enqueueScan } = require("../controllers/scanController");

const router = express.Router();

router.post("/scans", enqueueScan);

module.exports = router;
