const { execFile } = require("child_process");

const executeCommand = ({
  command,
  args = [],
  cwd,
  timeoutMs = 300000,
}) =>
  new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        cwd,
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
