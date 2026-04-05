const Repository = require("../models/Repository");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");

const toPositiveNumber = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) || parsed <= 0 ? fallback : parsed;
};

const buildPagination = (query) => {
  const page = toPositiveNumber(query.page, 1);
  const limit = Math.min(toPositiveNumber(query.limit, 10), 50);

  return {
    page,
    limit,
    skip: (page - 1) * limit,
  };
};

const buildRepositoryMatch = async (repositoryQuery) => {
  if (!repositoryQuery) {
    return null;
  }

  const repositories = await Repository.find({
    $or: [
      { name: new RegExp(repositoryQuery, "i") },
      { owner: new RegExp(repositoryQuery, "i") },
      { url: new RegExp(repositoryQuery, "i") },
    ],
  }).select("_id");

  return repositories.map((repository) => repository._id);
};

const filterFindings = (findings, { severity, type }) =>
  findings.filter((finding) => {
    const severityMatches = severity
      ? String(finding.severity || "").toLowerCase() === severity
      : true;
    const typeMatches = type
      ? String(finding.type || "").toLowerCase() === type
      : true;

    return severityMatches && typeMatches;
  });

const serializeReport = (report, filters = {}) => {
  const filteredFindings = filterFindings(report.findings || [], filters);

  return {
    id: report._id,
    repository: report.repository
      ? {
          id: report.repository._id,
          name: report.repository.name,
          owner: report.repository.owner,
          url: report.repository.url,
          branch: report.repository.branch,
        }
      : null,
    scanJob: report.scanJob
      ? {
          id: report.scanJob._id,
          status: report.scanJob.status,
          scanType: report.scanJob.scanType,
          tool: report.scanJob.tool,
          queueJobId: report.scanJob.queueJobId,
          startedAt: report.scanJob.startedAt,
          completedAt: report.scanJob.completedAt,
          failedAt: report.scanJob.failedAt,
          lastError: report.scanJob.lastError,
        }
      : null,
    summary: report.summary,
    findingsCount: filteredFindings.length,
    findings: filteredFindings,
    toolRuns: report.toolRuns || [],
    createdAt: report.createdAt,
    updatedAt: report.updatedAt,
  };
};

const listReports = async (req, res) => {
  const pagination = buildPagination(req.query);
  const severity = req.query.severity?.trim().toLowerCase() || "";
  const type = req.query.type?.trim().toLowerCase() || "";
  const repositoryIds = await buildRepositoryMatch(req.query.repository?.trim());

  if (req.query.repository && repositoryIds && repositoryIds.length === 0) {
    return res.json({
      data: [],
      pagination: {
        page: pagination.page,
        limit: pagination.limit,
        totalItems: 0,
        totalPages: 0,
      },
      filters: {
        severity,
        type,
        repository: req.query.repository,
      },
    });
  }

  const reportQuery = {};

  if (repositoryIds) {
    reportQuery.repository = { $in: repositoryIds };
  }

  if (severity || type) {
    reportQuery.findings = {
      $elemMatch: {
        ...(severity ? { severity } : {}),
        ...(type ? { type: new RegExp(`^${type}$`, "i") } : {}),
      },
    };
  }

  const [totalItems, reports] = await Promise.all([
    VulnerabilityReport.countDocuments(reportQuery),
    VulnerabilityReport.find(reportQuery)
      .sort({ createdAt: -1 })
      .skip(pagination.skip)
      .limit(pagination.limit)
      .populate("repository", "name owner url branch")
      .populate(
        "scanJob",
        "status scanType tool queueJobId startedAt completedAt failedAt lastError",
      )
      .lean(),
  ]);

  res.json({
    data: reports.map((report) => serializeReport(report, { severity, type })),
    pagination: {
      page: pagination.page,
      limit: pagination.limit,
      totalItems,
      totalPages: Math.ceil(totalItems / pagination.limit),
    },
    filters: {
      severity,
      type,
      repository: req.query.repository || "",
    },
  });
};

const getReportById = async (req, res) => {
  const report = await VulnerabilityReport.findById(req.params.reportId)
    .populate("repository", "name owner url branch")
    .populate(
      "scanJob",
      "status scanType tool queueJobId startedAt completedAt failedAt lastError",
    )
    .lean();

  if (!report) {
    return res.status(404).json({
      message: "Vulnerability report not found.",
    });
  }

  const severity = req.query.severity?.trim().toLowerCase() || "";
  const type = req.query.type?.trim().toLowerCase() || "";

  return res.json({
    data: serializeReport(report, { severity, type }),
  });
};

const listScanJobs = async (req, res) => {
  const pagination = buildPagination(req.query);
  const repositoryIds = await buildRepositoryMatch(req.query.repository?.trim());
  const status = req.query.status?.trim().toLowerCase() || "";
  const scanType = req.query.scanType?.trim() || "";

  if (req.query.repository && repositoryIds && repositoryIds.length === 0) {
    return res.json({
      data: [],
      pagination: {
        page: pagination.page,
        limit: pagination.limit,
        totalItems: 0,
        totalPages: 0,
      },
      filters: {
        status,
        scanType,
        repository: req.query.repository,
      },
    });
  }

  const jobQuery = {
    ...(repositoryIds ? { repository: { $in: repositoryIds } } : {}),
    ...(status ? { status } : {}),
    ...(scanType ? { scanType } : {}),
  };

  const [totalItems, jobs] = await Promise.all([
    ScanJob.countDocuments(jobQuery),
    ScanJob.find(jobQuery)
      .sort({ createdAt: -1 })
      .skip(pagination.skip)
      .limit(pagination.limit)
      .populate("repository", "name owner url branch")
      .lean(),
  ]);

  res.json({
    data: jobs.map((job) => ({
      id: job._id,
      queueJobId: job.queueJobId,
      repository: job.repository
        ? {
            id: job.repository._id,
            name: job.repository.name,
            owner: job.repository.owner,
            url: job.repository.url,
            branch: job.repository.branch,
          }
        : null,
      tool: job.tool,
      scanType: job.scanType,
      status: job.status,
      triggeredBy: job.triggeredBy,
      repositoryPath: job.repositoryPath,
      userDetails: job.userDetails,
      metadata: job.metadata,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      failedAt: job.failedAt,
      lastError: job.lastError,
      attemptsMade: job.attemptsMade,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
    })),
    pagination: {
      page: pagination.page,
      limit: pagination.limit,
      totalItems,
      totalPages: Math.ceil(totalItems / pagination.limit),
    },
    filters: {
      status,
      scanType,
      repository: req.query.repository || "",
    },
  });
};

const getScanJobById = async (req, res) => {
  const jobId = req.params.scanJobId;
  const job = await ScanJob.findById(jobId).populate("repository", "name owner url branch").lean();

  if (!job) {
    return res.status(404).json({
      message: "Scan job not found.",
    });
  }

  const report = await VulnerabilityReport.findOne({ scanJob: jobId }).lean();

  return res.json({
    data: {
      id: job._id,
      queueJobId: job.queueJobId,
      repository: job.repository
        ? {
            id: job.repository._id,
            name: job.repository.name,
            owner: job.repository.owner,
            url: job.repository.url,
            branch: job.repository.branch,
          }
        : null,
      tool: job.tool,
      scanType: job.scanType,
      status: job.status,
      triggeredBy: job.triggeredBy,
      repositoryPath: job.repositoryPath,
      userDetails: job.userDetails,
      metadata: job.metadata,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      failedAt: job.failedAt,
      lastError: job.lastError,
      attemptsMade: job.attemptsMade,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
      report: report
        ? {
            id: report._id,
            summary: report.summary,
            findingsCount: report.findings?.length || 0,
            toolRuns: report.toolRuns || [],
            createdAt: report.createdAt,
          }
        : null,
    },
  });
};

module.exports = {
  listReports,
  getReportById,
  listScanJobs,
  getScanJobById,
};
