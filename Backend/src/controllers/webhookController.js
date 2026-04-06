const crypto = require("crypto");
const { enqueueRepositoryScan } = require("../services/scanEnqueueService");

const getRawBodyString = (body) =>
  Buffer.isBuffer(body) ? body.toString("utf8") : JSON.stringify(body || {});

const verifyGitHubSignature = ({ rawBody, signatureHeader, secret }) => {
  if (!secret) {
    throw new Error("GITHUB_WEBHOOK_SECRET is required to validate GitHub webhooks.");
  }

  if (!signatureHeader?.startsWith("sha256=")) {
    return false;
  }

  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  const expected = Buffer.from(`sha256=${digest}`, "utf8");
  const provided = Buffer.from(signatureHeader, "utf8");

  if (expected.length !== provided.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, provided);
};

const getPushEventData = (payload) => {
  const branch = String(payload.ref || "").replace("refs/heads/", "").trim();

  if (!branch || payload.deleted) {
    return null;
  }

  return {
    repositoryUrl: payload.repository?.clone_url,
    branch,
    submittedBy: payload.sender?.login || "github-webhook",
    triggeredBy: "github-webhook-push",
    scanMode: "Quick Scan",
    targetUrl: "",
    scanMetadata: {
      github: {
        event: "push",
        owner: payload.repository?.owner?.login || payload.repository?.owner?.name || "",
        repo: payload.repository?.name || "",
        commitSha: payload.after || "",
        compareUrl: payload.compare || "",
        pullRequestNumber: null,
        installationId: payload.installation?.id || null,
      },
      webhookDeliveryId: payload.head_commit?.id || payload.after || "",
    },
  };
};

const getPullRequestEventData = (payload) => {
  const action = String(payload.action || "").toLowerCase();

  if (!["opened", "synchronize", "reopened"].includes(action)) {
    return null;
  }

  return {
    repositoryUrl: payload.pull_request?.head?.repo?.clone_url || payload.repository?.clone_url,
    branch: payload.pull_request?.head?.ref || payload.repository?.default_branch || "main",
    submittedBy: payload.sender?.login || "github-webhook",
    triggeredBy: "github-webhook-pull-request",
    scanMode: "Full Scan",
    targetUrl: "",
    scanMetadata: {
      github: {
        event: "pull_request",
        action,
        owner: payload.repository?.owner?.login || payload.repository?.owner?.name || "",
        repo: payload.repository?.name || "",
        commitSha: payload.pull_request?.head?.sha || "",
        baseBranch: payload.pull_request?.base?.ref || payload.repository?.default_branch || "main",
        pullRequestNumber: payload.pull_request?.number || null,
        pullRequestUrl: payload.pull_request?.html_url || "",
        installationId: payload.installation?.id || null,
      },
      webhookDeliveryId: payload.pull_request?.node_id || "",
    },
  };
};

const handleGitHubWebhook = async (req, res) => {
  const eventName = req.get("x-github-event");
  const deliveryId = req.get("x-github-delivery") || "";
  const signature = req.get("x-hub-signature-256");
  const rawBody = getRawBodyString(req.body);
  const { queue, config } = req.app.locals;

  if (
    !verifyGitHubSignature({
      rawBody,
      signatureHeader: signature,
      secret: config.github.webhookSecret,
    })
  ) {
    return res.status(401).json({
      message: "Invalid GitHub webhook signature.",
    });
  }

  const payload = JSON.parse(rawBody || "{}");

  if (eventName === "ping") {
    return res.json({
      message: "GitHub webhook received.",
      deliveryId,
      hookId: payload.hook_id || null,
    });
  }

  const eventData =
    eventName === "push"
      ? getPushEventData(payload)
      : eventName === "pull_request"
        ? getPullRequestEventData(payload)
        : null;

  if (!eventData) {
    return res.status(202).json({
      message: `Ignored GitHub event "${eventName}".`,
      deliveryId,
    });
  }

  if (!eventData.repositoryUrl || !eventData.branch) {
    return res.status(400).json({
      message: "Webhook payload is missing repository clone details.",
      deliveryId,
    });
  }

  try {
    const { repository, scanJob } = await enqueueRepositoryScan({
      queue,
      config,
      ...eventData,
      tool: "scanner-engine",
      provider: "github",
      repositoryMetadata: {},
      scanMetadata: {
        ...eventData.scanMetadata,
        initiatedFrom: "github-webhook",
        deliveryId,
      },
    });

    return res.status(202).json({
      message: "GitHub webhook accepted and scan queued.",
      deliveryId,
      event: eventName,
      scanJob: {
        id: scanJob._id,
        queueJobId: scanJob.queueJobId,
        status: scanJob.status,
        scanType: scanJob.scanType,
      },
      repository: {
        id: repository._id,
        name: repository.name,
        url: repository.url,
        branch: repository.branch,
      },
    });
  } catch (error) {
    return res.status(400).json({
      message: error.message,
      deliveryId,
    });
  }
};

module.exports = {
  handleGitHubWebhook,
};
