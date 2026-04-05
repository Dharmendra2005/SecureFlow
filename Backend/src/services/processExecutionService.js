const { execFile } = require("child_process");

const executeCommand = ({
  command,
  args = [],
  cwd,
  env = {},
  timeoutMs = 300000,
}) =>
  new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        cwd,
        env: {
          ...process.env,
          PYTHONUTF8: "1",
          PYTHONIOENCODING: "utf-8",
          ...env,
        },
        timeout: timeoutMs,
        maxBuffer: 20 * 1024 * 1024,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        resolve({
          ok: !error,
          error,
          stdout,
          stderr,
        });
      },
    );
  });

module.exports = {
  executeCommand,
};
