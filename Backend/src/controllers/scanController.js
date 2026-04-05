const Repository = require("../models/Repository");
const ScanJob = require("../models/ScanJob");
const { cloneRepository } = require("../services/repositoryCloneService");

const enqueueScan = async (req, res) => {
  const { queue } = req.app.locals;
  const repositoryUrl = req.body.repositoryUrl?.trim();
  const branch = req.body.branch?.trim() || "main";
  const scanMode = req.body.scanMode?.trim() || "Quick Scan";
  const submittedBy = req.body.submittedBy?.trim() || "developer";
  const targetUrl = req.body.targetUrl?.trim() || "";

  if (!repositoryUrl) {
    return res.status(400).json({
      message: "Repository URL is required.",
    });
  }

  let cloneResult;

  try {
    cloneResult = await cloneRepository({
      repositoryUrl,
      branch,
      baseDirectory: req.app.locals.config.repositoryWorkspace,
    });
  } catch (error) {
    return res.status(400).json({
      message: error.message,
    });
  }

  const repository = await Repository.create({
    name: cloneResult.name,
    owner: cloneResult.owner,
    url: repositoryUrl,
    branch,
    provider: "github",
    scanMode,
    localPath: cloneResult.clonePath,
    cloneStatus: "cloned",
    submittedAt: new Date(),
    clonedAt: new Date(),
  });

  const scanJob = await ScanJob.create({
    repository: repository._id,
    tool: "scanner-engine",
    scanType: scanMode,
    status: "pending",
    triggeredBy: req.body.triggeredBy || "api",
    queueJobId: "",
    repositoryPath: repository.localPath,
    userDetails: {
      submittedBy,
    },
    metadata: {
      initiatedFrom: "manual-dashboard",
      scanMode,
      branch,
      repositoryUrl,
      repositoryPath: repository.localPath,
      targetUrl,
    },
  });

  const queuedJob = await queue.add("scan-job", {
    scanJobId: scanJob._id.toString(),
    repositoryId: repository._id.toString(),
    tool: scanJob.tool,
    branch,
    scanMode,
    repositoryUrl,
    repoPath: repository.localPath,
    targetUrl,
    userDetails: {
      submittedBy,
    },
  });

  scanJob.queueJobId = queuedJob.id?.toString() || "";
  await scanJob.save();

  return res.status(202).json({
    message: "Security scan queued successfully.",
    scanJob: {
      id: scanJob._id,
      queueJobId: scanJob.queueJobId,
      status: scanJob.status,
      tool: scanJob.tool,
      scanType: scanJob.scanType,
    },
    repository: {
      id: repository._id,
      name: repository.name,
      url: repository.url,
      branch: repository.branch,
      localPath: repository.localPath,
    },
  });
};

module.exports = {
  enqueueScan,
};
