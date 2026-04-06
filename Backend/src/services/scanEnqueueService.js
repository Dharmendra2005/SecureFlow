const Repository = require("../models/Repository");
const ScanJob = require("../models/ScanJob");
const { cloneRepository } = require("./repositoryCloneService");

const enqueueRepositoryScan = async ({
  queue,
  config,
  repositoryUrl,
  branch = "main",
  scanMode = "Quick Scan",
  submittedBy = "developer",
  triggeredBy = "api",
  targetUrl = "",
  tool = "scanner-engine",
  provider = "github",
  repositoryMetadata = {},
  scanMetadata = {},
}) => {
  const cloneResult = await cloneRepository({
    repositoryUrl,
    branch,
    baseDirectory: config.repositoryWorkspace,
  });

  const repository = await Repository.create({
    name: cloneResult.name,
    owner: cloneResult.owner,
    url: repositoryUrl,
    branch,
    provider,
    scanMode,
    localPath: cloneResult.clonePath,
    cloneStatus: "cloned",
    submittedAt: new Date(),
    clonedAt: new Date(),
    ...repositoryMetadata,
  });

  const scanJob = await ScanJob.create({
    repository: repository._id,
    tool,
    scanType: scanMode,
    status: "pending",
    triggeredBy,
    queueJobId: "",
    repositoryPath: repository.localPath,
    userDetails: {
      submittedBy,
    },
    metadata: {
      initiatedFrom: triggeredBy,
      scanMode,
      branch,
      repositoryUrl,
      repositoryPath: repository.localPath,
      targetUrl,
      ...scanMetadata,
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

  return {
    repository,
    scanJob,
  };
};

module.exports = {
  enqueueRepositoryScan,
};
