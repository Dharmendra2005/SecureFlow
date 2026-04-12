const express = require("express");
const { requireRole } = require("../middleware/authMiddleware");
const {
  listRepositories,
  listReports,
  getReportById,
  listScanJobs,
  getScanJobById,
  createRemediationPullRequest,
  getRepositoryAnalytics,
  downloadReportPdf,
  deleteReportById,
  deleteScanJobById,
} = require("../controllers/reportController");

const router = express.Router();

router.get("/repositories", listRepositories);
router.get("/reports", listReports);
router.get("/reports/:reportId", getReportById);
router.get("/reports/:reportId/download.pdf", downloadReportPdf);
router.delete("/reports/:reportId", requireRole("admin", "developer"), deleteReportById);
router.post(
  "/reports/:reportId/findings/:findingId/remediation-pr",
  requireRole("admin", "developer"),
  createRemediationPullRequest,
);
router.get("/repositories/:repositoryId/analytics", getRepositoryAnalytics);
router.get("/scan-jobs", listScanJobs);
router.get("/scan-jobs/:scanJobId", getScanJobById);
router.delete("/scan-jobs/:scanJobId", requireRole("admin", "developer"), deleteScanJobById);

module.exports = router;
