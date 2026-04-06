const escapePdfText = (value) =>
  String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");

const buildMinimalPdf = (lines) => {
  const content = [
    "BT",
    "/F1 12 Tf",
    "50 780 Td",
    "16 TL",
    ...lines.map((line, index) =>
      index === 0
        ? `(${escapePdfText(line)}) Tj`
        : `T* (${escapePdfText(line)}) Tj`,
    ),
    "ET",
  ].join("\n");

  const objects = [
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
    "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
    "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    `5 0 obj << /Length ${Buffer.byteLength(content, "utf8")} >> stream\n${content}\nendstream endobj`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets = [0];

  for (const object of objects) {
    offsets.push(Buffer.byteLength(pdf, "utf8"));
    pdf += `${object}\n`;
  }

  const xrefOffset = Buffer.byteLength(pdf, "utf8");
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += "0000000000 65535 f \n";

  for (let index = 1; index < offsets.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, "0")} 00000 n \n`;
  }

  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdf, "utf8");
};

const buildReportPdf = (report) => {
  const lines = [
    "SecureFlow Vulnerability Report",
    `Repository: ${report.repository?.name || "Unknown repository"}`,
    `Branch: ${report.repository?.branch || "main"}`,
    `Created: ${new Date(report.createdAt).toLocaleString()}`,
    `Security Score: ${report.securityScore?.score ?? 100}`,
    `Risk Level: ${report.securityScore?.riskLevel || "secure"}`,
    `Critical: ${report.summary?.critical || 0}`,
    `High: ${report.summary?.high || 0}`,
    `Medium: ${report.summary?.medium || 0}`,
    `Low: ${report.summary?.low || 0}`,
    `Total Findings: ${report.summary?.total || 0}`,
    "Top Findings:",
    ...(report.findings || [])
      .slice(0, 10)
      .map(
        (finding, index) =>
          `${index + 1}. [${finding.severity}] ${finding.category} @ ${finding.location}`,
      ),
  ];

  return buildMinimalPdf(lines);
};

module.exports = {
  buildReportPdf,
};
