const Repository = require("../models/Repository");
const ScanJob = require("../models/ScanJob");
const VulnerabilityReport = require("../models/VulnerabilityReport");
const RemediationPullRequest = require("../models/RemediationPullRequest");
const { createGitHubPullRequest, pushBranchToRemote } = require("../services/githubPullRequestService");
const {
  generateAutomatedFix,
  applyFixAndCommit,
  buildPullRequestBody,
} = require("../services/vulnerabilityAutoFixService");
const { buildRepositoryAnalytics } = require("../services/securityScoreService");
const { buildReportPdf } = require("../services/pdfReportService");

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
    securityScore: report.securityScore || null,
    remediationPullRequests: report.remediationPullRequests || [],
    createdAt: report.createdAt,
    updatedAt: report.updatedAt,
  };
};

const serializeRemediationPullRequest = (item) => ({
  id: item._id,
  findingId: item.findingId,
  status: item.status,
  provider: item.provider,
  branchName: item.branchName,
  baseBranch: item.baseBranch,
  title: item.title,
  body: item.body,
  commitMessage: item.commitMessage,
  pullRequestNumber: item.pullRequestNumber,
  pullRequestUrl: item.pullRequestUrl,
  commitSha: item.commitSha,
  appliedFiles: item.appliedFiles || [],
  remediationSummary: item.remediationSummary,
  metadata: item.metadata || {},
  failureReason: item.failureReason,
  createdAt: item.createdAt,
  updatedAt: item.updatedAt,
});

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

  const reportIds = reports.map((report) => report._id);
  const remediationPullRequests = await RemediationPullRequest.find({
    report: { $in: reportIds },
  })
    .sort({ createdAt: -1 })
    .lean();

  const remediationByReportId = remediationPullRequests.reduce((accumulator, item) => {
    const key = item.report.toString();
    accumulator[key] = accumulator[key] || [];
    accumulator[key].push(serializeRemediationPullRequest(item));
    return accumulator;
  }, {});

  res.json({
    data: reports.map((report) =>
      serializeReport(
        {
          ...report,
          remediationPullRequests:
            remediationByReportId[report._id.toString()] || [],
        },
        { severity, type },
      ),
    ),
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
  const remediationPullRequests = await RemediationPullRequest.find({
    report: report._id,
  })
    .sort({ createdAt: -1 })
    .lean();

  return res.json({
    data: serializeReport(
      {
        ...report,
        remediationPullRequests: remediationPullRequests.map(
          serializeRemediationPullRequest,
        ),
      },
      { severity, type },
    ),
  });
};

const createRemediationPullRequest = async (req, res) => {
  const report = await VulnerabilityReport.findById(req.params.reportId)
    .populate("repository", "name owner url branch localPath")
    .populate("scanJob", "_id")
    .lean();

  if (!report) {
    return res.status(404).json({
      message: "Vulnerability report not found.",
    });
  }

  const finding = (report.findings || []).find(
    (item) => String(item.id) === String(req.params.findingId),
  );

  if (!finding) {
    return res.status(404).json({
      message: "Finding not found in this vulnerability report.",
    });
  }

  const repository = report.repository;

  if (!repository?.localPath) {
    return res.status(400).json({
      message: "The repository clone is not available for automated remediation.",
    });
  }

  try {
    const automatedFix = await generateAutomatedFix({
      repository,
      finding,
    });
    const previewRequested =
      String(req.query.preview || req.body?.preview || "").toLowerCase() === "true";

    if (previewRequested) {
      return res.json({
        message: "Automated remediation preview generated successfully.",
        data: {
          preview: true,
          findingId: finding.id,
          strategy: automatedFix.strategy,
          title: automatedFix.prTitle,
          commitMessage: automatedFix.commitMessage,
          remediationSummary: automatedFix.remediationSummary,
          remediationSteps: automatedFix.remediationSteps,
          appliedFiles: [automatedFix.relativePath],
        },
      });
    }

    const gitResult = await applyFixAndCommit({
      repository,
      finding,
      automatedFix,
    });

    await pushBranchToRemote({
      repoPath: repository.localPath,
      branchName: gitResult.branchName,
      repositoryUrl: repository.url,
    });

    const pullRequestBody = buildPullRequestBody({
      finding,
      remediationSummary: automatedFix.remediationSummary,
      remediationSteps: automatedFix.remediationSteps,
      baseBranch: gitResult.baseBranch,
    });

    const pullRequestPayload = await createGitHubPullRequest({
      owner: repository.owner,
      repo: repository.name,
      title: automatedFix.prTitle,
      head: gitResult.branchName,
      base: gitResult.baseBranch,
      body: pullRequestBody,
    });

    const record = await RemediationPullRequest.create({
      repository: repository._id,
      scanJob: report.scanJob?._id,
      report: report._id,
      findingId: finding.id,
      branchName: gitResult.branchName,
      baseBranch: gitResult.baseBranch,
      title: automatedFix.prTitle,
      body: pullRequestBody,
      commitMessage: automatedFix.commitMessage,
      status: "completed",
      provider: "github",
      pullRequestNumber: pullRequestPayload.number,
      pullRequestUrl: pullRequestPayload.html_url,
      commitSha: gitResult.commitSha,
      appliedFiles: gitResult.appliedFiles,
      remediationSummary: automatedFix.remediationSummary,
      metadata: {
        strategy: automatedFix.strategy,
        remediationSteps: automatedFix.remediationSteps,
        aiFix: automatedFix.aiFix || null,
      },
    });

    return res.status(201).json({
      message: "Automated remediation pull request created successfully.",
      data: serializeRemediationPullRequest(record),
    });
  } catch (error) {
    const statusCode = error.code === "UNSUPPORTED_FIX" ? 422 : 500;

    const failedRecord = await RemediationPullRequest.create({
      repository: repository._id,
      scanJob: report.scanJob?._id,
      report: report._id,
      findingId: finding.id,
      status: error.code === "UNSUPPORTED_FIX" ? "unsupported" : "failed",
      provider: "github",
      failureReason: error.message,
      remediationSummary: finding.ai?.summary || "",
      metadata: {
        ai: finding.ai || null,
      },
    });

    return res.status(statusCode).json({
      message: error.message,
      data: serializeRemediationPullRequest(failedRecord),
    });
  }
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

const getRepositoryAnalytics = async (req, res) => {
  const repositoryId = req.params.repositoryId;
  const reports = await VulnerabilityReport.find({ repository: repositoryId })
    .sort({ createdAt: 1 })
    .populate("repository", "name owner url branch")
    .lean();

  if (!reports.length) {
    return res.status(404).json({
      message: "No analytics data found for this repository.",
    });
  }

  const analytics = buildRepositoryAnalytics({ reports });
  const repository = reports[0].repository;

  return res.json({
    data: {
      repository: repository
        ? {
            id: repository._id,
            name: repository.name,
            owner: repository.owner,
            url: repository.url,
            branch: repository.branch,
          }
        : null,
      ...analytics,
    },
  });
};

const downloadReportPdf = async (req, res) => {
  const report = await VulnerabilityReport.findById(req.params.reportId)
    .populate("repository", "name owner url branch")
    .lean();

  if (!report) {
    return res.status(404).json({
      message: "Vulnerability report not found.",
    });
  }

  const pdfBuffer = buildReportPdf(report);

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="secureflow-report-${report._id}.pdf"`,
  );

  return res.send(pdfBuffer);
};

const deleteReportById = async (req, res) => {
  const report = await VulnerabilityReport.findById(req.params.reportId).lean();

  if (!report) {
    return res.status(404).json({
      message: "Vulnerability report not found.",
    });
  }

  await Promise.all([
    VulnerabilityReport.deleteOne({ _id: report._id }),
    RemediationPullRequest.deleteMany({ report: report._id }),
  ]);

  return res.json({
    message: "Report history deleted successfully.",
    data: {
      id: report._id,
    },
  });
};

const deleteScanJobById = async (req, res) => {
  const scanJob = await ScanJob.findById(req.params.scanJobId).lean();

  if (!scanJob) {
    return res.status(404).json({
      message: "Scan job not found.",
    });
  }

  const report = await VulnerabilityReport.findOne({ scanJob: scanJob._id }).lean();

  await Promise.all([
    ScanJob.deleteOne({ _id: scanJob._id }),
    report ? VulnerabilityReport.deleteOne({ _id: report._id }) : Promise.resolve(),
    report
      ? RemediationPullRequest.deleteMany({ report: report._id })
      : Promise.resolve(),
  ]);

  return res.json({
    message: "Scan history deleted successfully.",
    data: {
      id: scanJob._id,
      reportId: report?._id || null,
    },
  });
};

module.exports = {
  listReports,
  getReportById,
  listScanJobs,
  getScanJobById,
  createRemediationPullRequest,
  getRepositoryAnalytics,
  downloadReportPdf,
  deleteReportById,
  deleteScanJobById,
};
