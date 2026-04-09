const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const { executeCommand } = require("./processExecutionService");
const config = require("../config/env");

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const TOOL_MESSAGE_MAX_LENGTH = 320;
const ANSI_ESCAPE_PATTERN =
  // Remove terminal color/control sequences before showing tool output in the UI.
  /\u001b\[[0-9;?]*[ -/]*[@-~]/g;

const normalizeSeverity = (severity) => {
  const normalized = String(severity || "medium").toLowerCase();

  if (["error", "critical"].includes(normalized)) {
    return "critical";
  }

  if (["warning", "high"].includes(normalized)) {
    return "high";
  }

  if (["medium", "moderate"].includes(normalized)) {
    return "medium";
  }

  if (["low", "info", "note"].includes(normalized)) {
    return "low";
  }

  return "medium";
};

const summarizeFindings = (findings) =>
  findings.reduce(
    (summary, finding) => {
      const severity = normalizeSeverity(finding.severity);
      summary.total += 1;
      summary[severity] += 1;
      return summary;
    },
    {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  );

const createFindingId = (prefix, source) =>
  `${prefix}-${crypto.createHash("md5").update(source).digest("hex").slice(0, 8)}`;

const summarizeCommandOutput = (value, fallback) => {
  const normalized = String(value || "")
    .replace(ANSI_ESCAPE_PATTERN, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!normalized) {
    return fallback;
  }

  if (normalized.length <= TOOL_MESSAGE_MAX_LENGTH) {
    return normalized;
  }

  return `${normalized.slice(0, TOOL_MESSAGE_MAX_LENGTH - 3)}...`;
};

const summarizeTrivyError = (result) => {
  if (result.error?.killed) {
    return "Trivy did not finish before the scan timeout. Run a Full Scan later after Trivy has initialized its vulnerability database.";
  }

  const combinedOutput = `${result.stderr || ""} ${result.stdout || ""}`;

  if (/Need to update DB|Downloading vulnerability DB|mirror\.gcr\.io/i.test(combinedOutput)) {
    return "Trivy could not finish downloading or updating its vulnerability database during this scan.";
  }

  return summarizeCommandOutput(
    result.stderr || result.error?.message,
    "Trivy execution failed.",
  );
};

const parseJsonArrayOutput = (...values) => {
  for (const value of values) {
    const parsed = parseJson(value);

    if (Array.isArray(parsed)) {
      return parsed;
    }
  }

  return [];
};

const makeToolRun = ({
  tool,
  status,
  command,
  message,
  findings = [],
}) => ({
  tool,
  status,
  command,
  message,
  findingsCount: findings.length,
  completedAt: new Date().toISOString(),
});

const parseJson = (payload) => {
  try {
    return JSON.parse(payload);
  } catch (error) {
    return null;
  }
};

const fileExists = async (targetPath) => {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
};

const splitArgs = (value) =>
  String(value || "")
    .split(" ")
    .map((item) => item.trim())
    .filter(Boolean);

const buildPythonModuleCommand = ({ command, args, fallbackModule }) => {
  if (command) {
    return {
      command,
      args: splitArgs(args),
    };
  }

  return {
    command: config.tools.python,
    args: ["-m", fallbackModule],
  };
};

const detectDependencyManifest = async (repoPath) => {
  const packageJsonPath = path.join(repoPath, "package.json");
  const requirementsPath = path.join(repoPath, "requirements.txt");
  const pyprojectPath = path.join(repoPath, "pyproject.toml");

  if (await fileExists(packageJsonPath)) {
    return {
      ecosystem: "node",
      cwd: repoPath,
    };
  }

  if ((await fileExists(requirementsPath)) || (await fileExists(pyprojectPath))) {
    return {
      ecosystem: "python",
      cwd: repoPath,
    };
  }

  return null;
};

const runSemgrepScan = async ({ repoPath }) => {
  const semgrepCommand = buildPythonModuleCommand({
    command: config.tools.semgrepCommand,
    args: config.tools.semgrepArgs,
    fallbackModule: "semgrep",
  });
  const command = `${semgrepCommand.command} ${[...semgrepCommand.args, "scan", "--config", "auto", "--json", "."].join(" ")}`;
  const result = await executeCommand({
    command: semgrepCommand.command,
    args: [...semgrepCommand.args, "scan", "--config", "auto", "--json", "."],
    cwd: repoPath,
    timeoutMs: 300000,
  });

  if (result.error?.code === "ENOENT") {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Semgrep",
        status: "skipped",
        command,
        message: "Semgrep is not installed on this machine.",
      }),
    };
  }

  if (!result.ok) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Semgrep",
        status: "error",
        command,
        message: summarizeCommandOutput(
          result.stderr || result.error?.message,
          "Semgrep execution failed.",
        ),
      }),
    };
  }

  const payload = parseJson(result.stdout) || {};
  const findings = (payload.results || []).map((item) => ({
    id: createFindingId("SG", `${item.check_id}-${item.path}-${item.start?.line}`),
    tool: "Semgrep",
    category: item.check_id || "SAST Rule",
    type: "SAST",
    location: `${item.path}:${item.start?.line || 1}`,
    severity: normalizeSeverity(item.extra?.severity),
    description: item.extra?.message || "Semgrep finding detected.",
    raw: item,
  }));

  return {
    findings,
    toolRun: makeToolRun({
      tool: "Semgrep",
      status: "completed",
      command,
      message: `Completed SAST scan with ${findings.length} findings.`,
      findings,
    }),
  };
};

const runGitleaksScan = async ({ repoPath }) => {
  const command = `${config.tools.gitleaksPath} detect --source . --report-format json --report-path -`;
  const result = await executeCommand({
    command: config.tools.gitleaksPath,
    args: ["detect", "--source", ".", "--report-format", "json", "--report-path", "-"],
    cwd: repoPath,
    timeoutMs: 300000,
  });

  if (result.error?.code === "ENOENT") {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Gitleaks",
        status: "skipped",
        command,
        message: "Gitleaks is not installed on this machine.",
      }),
    };
  }

  const payload = parseJsonArrayOutput(result.stdout, result.stderr);
  const findings = payload.map((item) => ({
    id: createFindingId("GL", `${item.RuleID}-${item.File}-${item.StartLine}`),
    tool: "Gitleaks",
    category: item.RuleID || "Secret Detection",
    type: "Secrets",
    location: `${item.File}:${item.StartLine || 1}`,
    severity: "high",
    description: item.Description || "Potential secret detected.",
    raw: item,
  }));

  if (!result.ok && !findings.length) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Gitleaks",
        status: "error",
        command,
        message: summarizeCommandOutput(
          result.stderr || result.error?.message,
          "Gitleaks execution failed.",
        ),
      }),
    };
  }

  return {
    findings,
    toolRun: makeToolRun({
      tool: "Gitleaks",
      status: "completed",
      command,
      message: `Completed secret scan with ${findings.length} findings.`,
      findings,
    }),
  };
};

const runDependencyScan = async ({ repoPath }) => {
  const manifest = await detectDependencyManifest(repoPath);

  if (!manifest) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Dependency Audit",
        status: "skipped",
        command: "npm audit --json | pip-audit -f json",
        message: "No supported Node.js or Python dependency manifest found.",
      }),
    };
  }

  if (manifest.ecosystem === "node") {
    const command = "npm audit --json";
    const result = await executeCommand({
      command: "npm",
      args: ["audit", "--json"],
      cwd: repoPath,
      timeoutMs: 300000,
    });

    if (!result.ok && result.error?.code === "ENOENT") {
      return {
        findings: [],
        toolRun: makeToolRun({
          tool: "npm audit",
          status: "skipped",
          command,
          message: "npm is not installed on this machine.",
        }),
      };
    }

    const payload = parseJson(result.stdout || result.stderr) || {};
    const vulnerabilities = Object.entries(payload.vulnerabilities || {}).flatMap(
      ([packageName, item]) =>
        (item.via || [])
          .filter((via) => typeof via === "object")
          .map((via) => ({
            id: createFindingId(
              "NPM",
              `${packageName}-${via.source || via.title}-${via.severity}`,
            ),
            tool: "npm audit",
            category: packageName,
            type: "Dependency",
            location: "package-lock.json:1",
            severity: normalizeSeverity(via.severity),
            description: via.title || "Dependency vulnerability detected.",
            raw: via,
          })),
    );

    return {
      findings: vulnerabilities,
        toolRun: makeToolRun({
          tool: "npm audit",
          status: result.ok ? "completed" : "error",
          command,
          message: result.ok
            ? `Completed dependency scan with ${vulnerabilities.length} findings.`
            : summarizeCommandOutput(
                result.stderr || result.error?.message,
                "npm audit returned errors.",
              ),
          findings: vulnerabilities,
        }),
      };
  }

  const pipAuditCommand = buildPythonModuleCommand({
    command: config.tools.pipAuditCommand,
    args: config.tools.pipAuditArgs,
    fallbackModule: "pip_audit",
  });
  const command = `${pipAuditCommand.command} ${[...pipAuditCommand.args, "-f", "json"].join(" ")}`;
  const result = await executeCommand({
    command: pipAuditCommand.command,
    args: [...pipAuditCommand.args, "-f", "json"],
    cwd: repoPath,
    timeoutMs: 300000,
  });

  if (result.error?.code === "ENOENT") {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "pip-audit",
        status: "skipped",
        command,
        message: "pip-audit is not installed on this machine.",
      }),
    };
  }

  const payload = parseJson(result.stdout) || [];
  const findings = payload.flatMap((dependency) =>
    (dependency.vulns || []).map((vulnerability) => ({
      id: createFindingId(
        "PIP",
        `${dependency.name}-${vulnerability.id}-${vulnerability.fix_versions?.join(",")}`,
      ),
      tool: "pip-audit",
      category: dependency.name,
      type: "Dependency",
      location: "requirements.txt:1",
      severity: "medium",
      description:
        vulnerability.description || `Python dependency vulnerability ${vulnerability.id}.`,
      raw: vulnerability,
    })),
  );

  return {
    findings,
    toolRun: makeToolRun({
      tool: "pip-audit",
      status: result.ok ? "completed" : "error",
      command,
      message: result.ok
        ? `Completed dependency scan with ${findings.length} findings.`
        : summarizeCommandOutput(
            result.stderr || result.error?.message,
            "pip-audit returned errors.",
          ),
      findings,
    }),
  };
};

const runTrivyScan = async ({ repoPath }) => {
  const command = `${config.tools.trivyPath} fs --format json .`;
  const result = await executeCommand({
    command: config.tools.trivyPath,
    args: ["fs", "--format", "json", "."],
    cwd: repoPath,
    timeoutMs: 300000,
  });

  if (result.error?.code === "ENOENT") {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Trivy",
        status: "skipped",
        command,
        message: "Trivy is not installed on this machine.",
      }),
    };
  }

  if (!result.ok) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "Trivy",
        status: "error",
        command,
        message: summarizeTrivyError(result),
      }),
    };
  }

  const payload = parseJson(result.stdout) || {};
  const findings = (payload.Results || []).flatMap((resultItem) =>
    (resultItem.Vulnerabilities || []).map((vulnerability) => ({
      id: createFindingId(
        "TV",
        `${vulnerability.VulnerabilityID}-${vulnerability.PkgName}-${vulnerability.Severity}`,
      ),
      tool: "Trivy",
      category: vulnerability.PkgName || resultItem.Target || "Container Scan",
      type: "Container",
      location: resultItem.Target || repoPath,
      severity: normalizeSeverity(vulnerability.Severity),
      description: vulnerability.Title || vulnerability.Description || "Trivy finding detected.",
      raw: vulnerability,
    })),
  );

  return {
    findings,
    toolRun: makeToolRun({
      tool: "Trivy",
      status: "completed",
      command,
      message: `Completed container scan with ${findings.length} findings.`,
      findings,
    }),
  };
};

const runZapScan = async ({ targetUrl }) => {
  const command = targetUrl
    ? `${config.tools.dockerPath} run --rm owasp/zap2docker-stable zap-baseline.py -t ${targetUrl}`
    : `${config.tools.dockerPath} run --rm owasp/zap2docker-stable zap-baseline.py -t <targetUrl>`;

  if (!targetUrl) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "OWASP ZAP",
        status: "skipped",
        command,
        message: "No target URL was provided for DAST.",
      }),
    };
  }

  const result = await executeCommand({
    command: config.tools.dockerPath,
    args: [
      "run",
      "--rm",
      "owasp/zap2docker-stable",
      "zap-baseline.py",
      "-t",
      targetUrl,
      "-J",
      "-",
    ],
    timeoutMs: 600000,
  });

  if (result.error?.code === "ENOENT") {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "OWASP ZAP",
        status: "skipped",
        command,
        message: "Docker is not installed on this machine.",
      }),
    };
  }

  if (!result.ok) {
    return {
      findings: [],
      toolRun: makeToolRun({
        tool: "OWASP ZAP",
        status: "error",
        command,
        message: summarizeCommandOutput(
          result.stderr || result.error?.message,
          "OWASP ZAP execution failed.",
        ),
      }),
    };
  }

  const payload = parseJson(result.stdout) || {};
  const findings = (payload.site || []).flatMap((site) =>
    (site.alerts || []).map((alert) => ({
      id: createFindingId("ZAP", `${alert.pluginid}-${alert.name}-${site["@name"]}`),
      tool: "OWASP ZAP",
      category: alert.name || "DAST Finding",
      type: "DAST",
      location: targetUrl,
      severity: normalizeSeverity(alert.riskcode),
      description: alert.desc || "OWASP ZAP finding detected.",
      raw: alert,
    })),
  );

  return {
    findings,
    toolRun: makeToolRun({
      tool: "OWASP ZAP",
      status: "completed",
      command,
      message: `Completed DAST scan with ${findings.length} findings.`,
      findings,
    }),
  };
};

const sortFindings = (findings) =>
  [...findings].sort(
    (left, right) => severityRank[normalizeSeverity(right.severity)] - severityRank[normalizeSeverity(left.severity)],
  );

const buildScannerPlan = (scanType) => {
  const quickScanPlan = [
    runSemgrepScan,
    runGitleaksScan,
    runDependencyScan,
  ];

  if (scanType === "Full Scan") {
    return [...quickScanPlan, runTrivyScan, runZapScan];
  }

  return quickScanPlan;
};

const runRepositoryScans = async ({
  repoPath,
  scanType,
  targetUrl,
}) => {
  const runners = buildScannerPlan(scanType);
  const results = [];

  for (const runner of runners) {
    // Keep the pipeline moving even when one tool errors out.
    // Each runner normalizes its own execution status.
    results.push(
      await runner({
        repoPath,
        scanType,
        targetUrl,
      }),
    );
  }

  const findings = sortFindings(results.flatMap((result) => result.findings));
  const toolRuns = results.map((result) => result.toolRun);

  return {
    findings,
    toolRuns,
    summary: summarizeFindings(findings),
  };
};

module.exports = {
  runRepositoryScans,
};
