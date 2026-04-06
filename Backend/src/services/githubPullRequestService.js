const { simpleGit } = require("simple-git");
const config = require("../config/env");

const normalizeGitHubRepoUrl = (repositoryUrl) => {
  const trimmed = String(repositoryUrl || "").trim();

  if (!trimmed) {
    throw new Error("Repository URL is required to create a GitHub pull request.");
  }

  return trimmed.endsWith(".git") ? trimmed : `${trimmed}.git`;
};

const createAuthenticatedRemoteUrl = (repositoryUrl) => {
  const normalizedUrl = normalizeGitHubRepoUrl(repositoryUrl);

  if (!config.github.token) {
    throw new Error("GITHUB_TOKEN is required for automated pull request creation.");
  }

  return normalizedUrl.replace(
    /^https:\/\//i,
    `https://x-access-token:${encodeURIComponent(config.github.token)}@`,
  );
};

const pushBranchToRemote = async ({ repoPath, branchName, repositoryUrl }) => {
  const git = simpleGit(repoPath);
  const authenticatedUrl = createAuthenticatedRemoteUrl(repositoryUrl);

  await git.push(authenticatedUrl, branchName, ["--set-upstream"]);
};

const createGitHubPullRequest = async ({
  owner,
  repo,
  title,
  head,
  base,
  body,
}) => {
  if (!config.github.token) {
    throw new Error("GITHUB_TOKEN is required for GitHub API access.");
  }

  const response = await fetch(
    `${config.github.apiBaseUrl}/repos/${owner}/${repo}/pulls`,
    {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${config.github.token}`,
        "Content-Type": "application/json",
        "User-Agent": "SecureFlow-Remediation-Bot",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({
        title,
        head,
        base,
        body,
      }),
    },
  );

  const payload = await response.json();

  if (!response.ok) {
    throw new Error(
      payload.message || `GitHub pull request creation failed with ${response.status}.`,
    );
  }

  return payload;
};

module.exports = {
  pushBranchToRemote,
  createGitHubPullRequest,
};
