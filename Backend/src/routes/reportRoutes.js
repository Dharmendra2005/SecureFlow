const express = require("express");
const {
  listReports,
  getReportById,
  listScanJobs,
  getScanJobById,
} = require("../controllers/reportController");

const router = express.Router();

router.get("/reports", listReports);
router.get("/reports/:reportId", getReportById);
router.get("/scan-jobs", listScanJobs);
router.get("/scan-jobs/:scanJobId", getScanJobById);

module.exports = router;
