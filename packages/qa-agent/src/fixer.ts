import fs from "fs/promises"
import path from "path"
import { askClaude, parseJSON } from "./claude.js"
import type { QAAgentConfig, TestReport, FixAttempt, FileFix } from "./types.js"

const PROCESSED_FILE = "processed-fixes.json"

export async function getFailedReports(reportsDir: string): Promise<TestReport[]> {
  try {
    const files = await fs.readdir(reportsDir)
    const reports: TestReport[] = []
    for (const file of files.filter((f) => f.endsWith(".json"))) {
      try {
        const raw = await fs.readFile(path.join(reportsDir, file), "utf-8")
        const report: TestReport = JSON.parse(raw)
        if (report.verdict === "FAILED") reports.push(report)
      } catch {}
    }
    return reports.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
  } catch {
    return []
  }
}

export async function loadProcessed(reportsDir: string): Promise<Set<string>> {
  try {
    const raw = await fs.readFile(path.join(path.dirname(reportsDir), PROCESSED_FILE), "utf-8")
    return new Set(JSON.parse(raw))
  } catch {
    return new Set()
  }
}

export async function saveProcessed(reportsDir: string, processed: Set<string>): Promise<void> {
  await fs.writeFile(
    path.join(path.dirname(reportsDir), PROCESSED_FILE),
    JSON.stringify([...processed], null, 2),
  )
}

export async function attemptFix(
  report: TestReport,
  projectRoot: string,
  config: QAAgentConfig,
  attemptNum: number,
): Promise<FixAttempt> {
  const start = Date.now()
  const branch = report.commitInfo.branch
  const fixBranch = `fix/${report.commitInfo.shortHash}-attempt-${attemptNum}`

  const attempt: FixAttempt = {
    reportId: report.id,
    commitHash: report.commitHash,
    branch,
    fixBranch,
    attempt: attemptNum,
    analysis: "",
    fixes: [],
    status: "analyzing",
    createdAt: new Date().toISOString(),
    duration: 0,
  }

  try {
    // Build context from failed report
    const failedSteps = report.results
      .filter((r) => r.status === "FAILED" || r.status === "ERROR")
      .map((r) => `Step: ${r.description}\nExit: ${r.exitCode}\nStdout: ${r.stdout.slice(0, 2000)}\nStderr: ${r.stderr.slice(0, 2000)}`)
      .join("\n---\n")

    // Read source files mentioned in report
    const fileSources: string[] = []
    for (const file of report.diff.filesChanged.slice(0, 10)) {
      try {
        const content = await fs.readFile(path.join(projectRoot, file), "utf-8")
        fileSources.push(`=== ${file} ===\n${content.slice(0, 5000)}`)
      } catch {}
    }

    // Ask Claude for fix
    const response = await askClaude({
      systemPrompt: `You are a code fixer. Analyze test failures and produce targeted fixes.
Return valid JSON only, no markdown. Format:
{
  "analysis": "Brief explanation of what went wrong",
  "fixes": [{"file": "path/to/file", "search": "exact text to find", "replace": "replacement text"}],
  "commitMessage": "fix: description"
}
Keep fixes minimal and targeted. Only fix what's broken.`,
      prompt: `Project: ${config.project}
Commit: ${report.commitHash} on ${branch}
Verdict: ${report.verdict}
Reasoning: ${report.verdictReasoning}

Failed steps:
${failedSteps}

Source files:
${fileSources.join("\n\n")}

Provide fixes as search/replace pairs.`,
      timeout: 120_000,
    })

    const parsed = parseJSON<{
      analysis: string
      fixes: FileFix[]
      commitMessage: string
    }>(response.text)

    if (!parsed || !parsed.fixes?.length) {
      attempt.status = "failed"
      attempt.error = "No fixes generated"
      attempt.duration = Date.now() - start
      return attempt
    }

    attempt.analysis = parsed.analysis
    attempt.fixes = parsed.fixes
    attempt.status = "fixing"

    // Checkout the branch and create fix branch
    const exec = async (cmd: string) => {
      const proc = Bun.spawn(["sh", "-c", cmd], { cwd: projectRoot, stdout: "pipe", stderr: "pipe" })
      await proc.exited
      return proc
    }

    await exec(`git checkout ${branch} 2>/dev/null || git checkout -b ${branch} origin/${branch}`)
    await exec(`git pull origin ${branch} 2>/dev/null`)
    await exec(`git checkout -b ${fixBranch} 2>/dev/null || git checkout ${fixBranch}`)

    // Apply fixes
    let appliedCount = 0
    for (const fix of parsed.fixes) {
      try {
        const filePath = path.join(projectRoot, fix.file)
        const content = await fs.readFile(filePath, "utf-8")
        if (content.includes(fix.search)) {
          await fs.writeFile(filePath, content.replace(fix.search, fix.replace))
          appliedCount++
        }
      } catch {}
    }

    if (appliedCount === 0) {
      attempt.status = "failed"
      attempt.error = "No fixes could be applied (search strings not found)"
      attempt.duration = Date.now() - start
      await exec(`git checkout ${branch}`)
      await exec(`git branch -D ${fixBranch} 2>/dev/null`)
      return attempt
    }

    // Commit and push
    if (config.fixer.autoCommit) {
      await exec(`git add -A`)
      const commitMsg = parsed.commitMessage || `fix: auto-fix for ${report.commitInfo.shortHash}`
      await exec(`git commit -m "${commitMsg}"`)

      const logProc = Bun.spawn(["git", "rev-parse", "HEAD"], { cwd: projectRoot, stdout: "pipe" })
      attempt.fixCommitHash = (await new Response(logProc.stdout).text()).trim()

      if (config.fixer.autoPush) {
        await exec(`git push origin ${fixBranch}`)
      }

      attempt.status = "committed"
    }

    // Return to original branch
    await exec(`git checkout ${branch}`)
    attempt.duration = Date.now() - start
    return attempt
  } catch (err) {
    attempt.status = "failed"
    attempt.error = err instanceof Error ? err.message : String(err)
    attempt.duration = Date.now() - start
    return attempt
  }
}

export async function saveFixAttempt(attempt: FixAttempt, reportsDir: string): Promise<void> {
  const fixDir = path.join(path.dirname(reportsDir), "fixes")
  await fs.mkdir(fixDir, { recursive: true })
  const filename = `${attempt.commitHash.slice(0, 7)}-attempt-${attempt.attempt}.json`
  await fs.writeFile(path.join(fixDir, filename), JSON.stringify(attempt, null, 2))
}
