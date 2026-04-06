const config = require("../config/env");

const createGitHubHeaders = () => {
  if (!config.github.token) {
    throw new Error("GITHUB_TOKEN is required for GitHub feedback updates.");
  }

  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${config.github.token}`,
    "Content-Type": "application/json",
    "User-Agent": "SecureFlow-GitHub-Integration",
    "X-GitHub-Api-Version": "2022-11-28",
  };
};

const canSendGitHubFeedback = (metadata = {}) =>
  Boolean(
    config.github.token &&
      metadata.github?.owner &&
      metadata.github?.repo &&
      metadata.github?.commitSha,
  );

const createCommitStatus = async ({
  owner,
  repo,
  sha,
  state,
  description,
  targetUrl,
  context = "secureflow/security-scan",
}) => {
  const response = await fetch(
    `${config.github.apiBaseUrl}/repos/${owner}/${repo}/statuses/${sha}`,
    {
      method: "POST",
      headers: createGitHubHeaders(),
      body: JSON.stringify({
        state,
        description,
        target_url: targetUrl || undefined,
        context,
      }),
    },
  );

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || `Failed to create GitHub commit status (${response.status}).`);
  }

  return response.json();
};

const createPullRequestComment = async ({
  owner,
  repo,
  issueNumber,
  body,
}) => {
  const response = await fetch(
    `${config.github.apiBaseUrl}/repos/${owner}/${repo}/issues/${issueNumber}/comments`,
    {
      method: "POST",
      headers: createGitHubHeaders(),
      body: JSON.stringify({ body }),
    },
  );

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || `Failed to create pull request comment (${response.status}).`);
  }

  return response.json();
};

module.exports = {
  canSendGitHubFeedback,
  createCommitStatus,
  createPullRequestComment,
};
