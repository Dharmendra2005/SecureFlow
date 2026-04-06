const { enqueueRepositoryScan } = require("../services/scanEnqueueService");

const enqueueScan = async (req, res) => {
  const { queue, config } = req.app.locals;
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

  try {
    const { repository, scanJob } = await enqueueRepositoryScan({
      queue,
      config,
      repositoryUrl,
      branch,
      scanMode,
      submittedBy,
      triggeredBy: req.body.triggeredBy || "api",
      targetUrl,
      tool: "scanner-engine",
    });

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
  } catch (error) {
    return res.status(400).json({
      message: error.message,
    });
  }
};

module.exports = {
  enqueueScan,
};
