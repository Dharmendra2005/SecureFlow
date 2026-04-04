const fs = require("fs/promises");
const path = require("path");
const { simpleGit } = require("simple-git");

const git = simpleGit();

const parseGitHubUrl = (repositoryUrl) => {
  const match = repositoryUrl.match(
    /^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/i,
  );

  if (!match) {
    throw new Error("Enter a valid GitHub repository URL.");
  }

  return {
    owner: match[1],
    name: match[2],
  };
};

const sanitizeSegment = (value) =>
  value.replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-");

const createClonePath = ({ baseDirectory, owner, repositoryName, branch }) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return path.join(
    baseDirectory,
    "github",
    sanitizeSegment(owner),
    sanitizeSegment(repositoryName),
    `${sanitizeSegment(branch)}-${timestamp}`,
  );
};

const cloneRepository = async ({
  repositoryUrl,
  branch,
  baseDirectory,
}) => {
  const parsed = parseGitHubUrl(repositoryUrl);
  const clonePath = createClonePath({
    baseDirectory,
    owner: parsed.owner,
    repositoryName: parsed.name,
    branch,
  });

  await fs.mkdir(path.dirname(clonePath), { recursive: true });

  try {
    await git.clone(repositoryUrl, clonePath, [
      "--branch",
      branch,
      "--single-branch",
    ]);
  } catch (error) {
    if (/repository .* not found/i.test(error.message)) {
      throw new Error(
        "GitHub repository not found or access denied. Private repositories are not supported yet.",
      );
    }

    if (/remote branch .* not found/i.test(error.message)) {
      throw new Error(`The branch "${branch}" does not exist on this repository.`);
    }

    if (/authentication failed/i.test(error.message)) {
      throw new Error(
        "Authentication failed while cloning the repository. Private repositories are not supported yet.",
      );
    }

    throw new Error(`Failed to clone repository: ${error.message}`);
  }

  return {
    ...parsed,
    clonePath,
  };
};

module.exports = {
  cloneRepository,
  parseGitHubUrl,
};
