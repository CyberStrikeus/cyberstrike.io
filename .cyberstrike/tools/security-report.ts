import { tool } from "@cyberstrike-io/plugin"
import * as fs from "fs"
import * as path from "path"

/**
 * Security Report Generator - Create professional pentest reports
 */
export default tool({
  description: `Generate a security assessment report in various formats.
Creates professional penetration testing reports from findings data.`,
  args: {
    title: tool.schema.string().describe("Report title"),
    target: tool.schema.string().describe("Target system/application name"),
    findings: tool.schema
      .array(
        tool.schema.object({
          title: tool.schema.string(),
          severity: tool.schema.enum(["critical", "high", "medium", "low", "info"]),
          description: tool.schema.string(),
          impact: tool.schema.string().optional(),
          remediation: tool.schema.string().optional(),
          references: tool.schema.array(tool.schema.string()).optional(),
          cvss: tool.schema.string().optional(),
          cve: tool.schema.string().optional(),
        })
      )
      .describe("Array of security findings"),
    output_format: tool.schema
      .enum(["markdown", "json", "html"])
      .default("markdown")
      .describe("Output format for the report"),
    output_file: tool.schema
      .string()
      .optional()
      .describe("File path to save the report (optional)"),
    include_executive_summary: tool.schema
      .boolean()
      .default(true)
      .describe("Include executive summary section"),
  },
  async execute(args, ctx) {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    const sortedFindings = [...args.findings].sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    )

    const severityCounts = {
      critical: args.findings.filter((f) => f.severity === "critical").length,
      high: args.findings.filter((f) => f.severity === "high").length,
      medium: args.findings.filter((f) => f.severity === "medium").length,
      low: args.findings.filter((f) => f.severity === "low").length,
      info: args.findings.filter((f) => f.severity === "info").length,
    }

    const timestamp = new Date().toISOString().split("T")[0]

    ctx.metadata({ title: `Security Report: ${args.title}` })

    let report: string

    if (args.output_format === "json") {
      report = JSON.stringify(
        {
          title: args.title,
          target: args.target,
          date: timestamp,
          summary: {
            total: args.findings.length,
            ...severityCounts,
          },
          findings: sortedFindings,
        },
        null,
        2
      )
    } else if (args.output_format === "html") {
      report = generateHtmlReport(args.title, args.target, timestamp, severityCounts, sortedFindings, args.include_executive_summary)
    } else {
      report = generateMarkdownReport(args.title, args.target, timestamp, severityCounts, sortedFindings, args.include_executive_summary)
    }

    if (args.output_file) {
      const outputPath = path.resolve(ctx.directory, args.output_file)
      await fs.promises.writeFile(outputPath, report)
      return `Report saved to: ${outputPath}\n\n${report}`
    }

    return report
  },
})

function generateMarkdownReport(
  title: string,
  target: string,
  date: string,
  counts: Record<string, number>,
  findings: Array<any>,
  includeExecSummary: boolean
): string {
  let md = `# ${title}

**Target:** ${target}
**Date:** ${date}
**Total Findings:** ${findings.length}

## Summary

| Severity | Count |
|----------|-------|
| Critical | ${counts.critical} |
| High     | ${counts.high} |
| Medium   | ${counts.medium} |
| Low      | ${counts.low} |
| Info     | ${counts.info} |

`

  if (includeExecSummary) {
    md += `## Executive Summary

This security assessment identified **${findings.length}** findings across the target system.
${counts.critical > 0 ? `**${counts.critical} critical** vulnerabilities require immediate attention. ` : ""}
${counts.high > 0 ? `**${counts.high} high** severity issues should be addressed promptly. ` : ""}
${counts.critical === 0 && counts.high === 0 ? "No critical or high severity vulnerabilities were identified. " : ""}

`
  }

  md += `## Findings\n\n`

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]
    const severityBadge = {
      critical: "**[CRITICAL]**",
      high: "**[HIGH]**",
      medium: "**[MEDIUM]**",
      low: "[LOW]",
      info: "[INFO]",
    }[f.severity]

    md += `### ${i + 1}. ${severityBadge} ${f.title}

${f.description}

`
    if (f.cvss) md += `**CVSS:** ${f.cvss}\n`
    if (f.cve) md += `**CVE:** ${f.cve}\n`
    if (f.impact) md += `\n**Impact:** ${f.impact}\n`
    if (f.remediation) md += `\n**Remediation:** ${f.remediation}\n`
    if (f.references && f.references.length > 0) {
      md += `\n**References:**\n${f.references.map((r: string) => `- ${r}`).join("\n")}\n`
    }
    md += "\n---\n\n"
  }

  return md
}

function generateHtmlReport(
  title: string,
  target: string,
  date: string,
  counts: Record<string, number>,
  findings: Array<any>,
  includeExecSummary: boolean
): string {
  const severityColors = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#ffc107",
    low: "#17a2b8",
    info: "#6c757d",
  }

  let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
    .meta { color: #666; margin-bottom: 20px; }
    .summary { display: flex; gap: 10px; margin: 20px 0; }
    .severity-badge { padding: 5px 15px; border-radius: 4px; color: white; font-weight: bold; }
    .finding { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
    .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
    .critical { background: ${severityColors.critical}; }
    .high { background: ${severityColors.high}; }
    .medium { background: ${severityColors.medium}; color: #333; }
    .low { background: ${severityColors.low}; }
    .info { background: ${severityColors.info}; }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">
    <p><strong>Target:</strong> ${target}</p>
    <p><strong>Date:</strong> ${date}</p>
  </div>

  <h2>Summary</h2>
  <div class="summary">
    <span class="severity-badge critical">Critical: ${counts.critical}</span>
    <span class="severity-badge high">High: ${counts.high}</span>
    <span class="severity-badge medium">Medium: ${counts.medium}</span>
    <span class="severity-badge low">Low: ${counts.low}</span>
    <span class="severity-badge info">Info: ${counts.info}</span>
  </div>
`

  if (includeExecSummary) {
    html += `
  <h2>Executive Summary</h2>
  <p>This security assessment identified <strong>${findings.length}</strong> findings across the target system.
  ${counts.critical > 0 ? `<strong>${counts.critical} critical</strong> vulnerabilities require immediate attention.` : ""}
  ${counts.high > 0 ? `<strong>${counts.high} high</strong> severity issues should be addressed promptly.` : ""}
  </p>
`
  }

  html += `<h2>Findings</h2>\n`

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]
    html += `
  <div class="finding">
    <div class="finding-header">
      <span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
      <h3 style="margin: 0;">${i + 1}. ${f.title}</h3>
    </div>
    <p>${f.description}</p>
    ${f.cvss ? `<p><strong>CVSS:</strong> ${f.cvss}</p>` : ""}
    ${f.cve ? `<p><strong>CVE:</strong> ${f.cve}</p>` : ""}
    ${f.impact ? `<p><strong>Impact:</strong> ${f.impact}</p>` : ""}
    ${f.remediation ? `<p><strong>Remediation:</strong> ${f.remediation}</p>` : ""}
    ${f.references && f.references.length > 0 ? `<p><strong>References:</strong><ul>${f.references.map((r: string) => `<li>${r}</li>`).join("")}</ul></p>` : ""}
  </div>
`
  }

  html += `</body></html>`
  return html
}
