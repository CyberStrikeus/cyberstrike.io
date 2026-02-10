import fs from "fs/promises"
import path from "path"
import type { Subprocess } from "bun"

export interface ProjectConfig {
  id: string
  name: string
  repoUrl: string
  branches?: string[]
  build?: string
  test?: string
  model: string
  status: "running" | "stopped" | "error"
  createdAt: string
}

interface RunningProject extends ProjectConfig {
  watchProc?: Subprocess
  fixProc?: Subprocess
  logs: string[]
}

const DATA_DIR = process.env.DATA_DIR || "/data"
const CONFIG_PATH = path.join(DATA_DIR, "config", "projects.json")
const MAX_LOGS = 200

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6)
}

export class ProjectManager {
  private projects: Map<string, RunningProject> = new Map()
  private qaAgentPath: string

  constructor(qaAgentPath: string) {
    this.qaAgentPath = qaAgentPath
  }

  async init(): Promise<void> {
    await fs.mkdir(path.join(DATA_DIR, "config"), { recursive: true })
    await fs.mkdir(path.join(DATA_DIR, "repos"), { recursive: true })
    await fs.mkdir(path.join(DATA_DIR, "reports"), { recursive: true })

    const configs = await this.loadConfigs()
    for (const config of configs) {
      this.projects.set(config.id, { ...config, logs: [] })
      if (config.status === "running") {
        await this.startAgents(config.id).catch((err) => {
          this.appendLog(config.id, `[orchestrator] Failed to auto-start: ${err.message}`)
        })
      }
    }
  }

  private async loadConfigs(): Promise<ProjectConfig[]> {
    try {
      const raw = await fs.readFile(CONFIG_PATH, "utf-8")
      return JSON.parse(raw)
    } catch {
      return []
    }
  }

  private async saveConfigs(): Promise<void> {
    const configs = [...this.projects.values()].map(({ watchProc, fixProc, logs, ...config }) => config)
    await fs.writeFile(CONFIG_PATH, JSON.stringify(configs, null, 2))
  }

  private appendLog(id: string, line: string): void {
    const project = this.projects.get(id)
    if (!project) return
    const ts = new Date().toISOString().slice(11, 19)
    project.logs.push(`[${ts}] ${line}`)
    if (project.logs.length > MAX_LOGS) {
      project.logs = project.logs.slice(-MAX_LOGS)
    }
  }

  private repoPath(id: string): string {
    return path.join(DATA_DIR, "repos", id)
  }

  private reportsPath(id: string): string {
    return path.join(DATA_DIR, "reports", id)
  }

  private async writeAgentConfig(id: string): Promise<void> {
    const project = this.projects.get(id)
    if (!project) return

    const config: Record<string, any> = {
      project: project.name,
      type: "auto",
      reportsDir: this.reportsPath(id) + "/reports",
      maxReports: 50,
      model: project.model || "claude-opus-4-6",
      timeout: { build: 120000, test: 300000, command: 60000 },
      fixer: { maxAttempts: 3, pollInterval: 10000, autoCommit: true, autoPush: true },
    }
    if (project.build) config.build = project.build
    if (project.test) config.test = project.test
    if (project.branches?.length) config.branches = project.branches

    const configPath = path.join(this.repoPath(id), ".qa-agent.jsonc")
    await fs.writeFile(configPath, JSON.stringify(config, null, 2))
  }

  async addProject(input: {
    name: string
    repoUrl: string
    branches?: string[]
    build?: string
    test?: string
    model?: string
  }): Promise<ProjectConfig> {
    const id = generateId()
    const config: ProjectConfig = {
      id,
      name: input.name,
      repoUrl: input.repoUrl,
      branches: input.branches,
      build: input.build,
      test: input.test,
      model: input.model || "claude-opus-4-6",
      status: "stopped",
      createdAt: new Date().toISOString(),
    }

    this.projects.set(id, { ...config, logs: [] })
    this.appendLog(id, `Project created: ${input.name}`)

    // Clone repo
    this.appendLog(id, `Cloning ${input.repoUrl}...`)
    const repoDir = this.repoPath(id)
    await fs.mkdir(repoDir, { recursive: true })

    const cloneProc = Bun.spawn(["git", "clone", input.repoUrl, repoDir], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const stderr = await new Response(cloneProc.stderr).text()
    const exitCode = await cloneProc.exited

    if (exitCode !== 0) {
      this.appendLog(id, `Clone failed: ${stderr}`)
      config.status = "error"
    } else {
      this.appendLog(id, "Clone complete")
    }

    // Write agent config
    await this.writeAgentConfig(id)
    await fs.mkdir(this.reportsPath(id) + "/reports", { recursive: true })
    await this.saveConfigs()

    return config
  }

  async removeProject(id: string): Promise<void> {
    await this.stopAgents(id)
    this.projects.delete(id)
    await this.saveConfigs()
    await fs.rm(this.repoPath(id), { recursive: true, force: true }).catch(() => {})
    await fs.rm(this.reportsPath(id), { recursive: true, force: true }).catch(() => {})
  }

  async startAgents(id: string): Promise<void> {
    const project = this.projects.get(id)
    if (!project) throw new Error(`Project ${id} not found`)

    await this.stopAgents(id)

    const cwd = this.repoPath(id)
    const env = { ...process.env }

    this.appendLog(id, "Starting watch agent...")
    project.watchProc = Bun.spawn([this.qaAgentPath, "watch"], {
      cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    })
    this.pipeOutput(id, project.watchProc, "watch")

    this.appendLog(id, "Starting fix agent...")
    project.fixProc = Bun.spawn([this.qaAgentPath, "fix"], {
      cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    })
    this.pipeOutput(id, project.fixProc, "fix")

    project.status = "running"
    await this.saveConfigs()
    this.appendLog(id, "Agents started")
  }

  private pipeOutput(id: string, proc: Subprocess, label: string): void {
    const read = async (stream: ReadableStream<Uint8Array> | null, prefix: string) => {
      if (!stream) return
      const reader = stream.getReader()
      const decoder = new TextDecoder()
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          const text = decoder.decode(value)
          for (const line of text.split("\n").filter(Boolean)) {
            this.appendLog(id, `[${prefix}] ${line}`)
          }
        }
      } catch {}
    }

    read(proc.stdout as ReadableStream<Uint8Array>, label)
    read(proc.stderr as ReadableStream<Uint8Array>, label)

    proc.exited.then((code) => {
      this.appendLog(id, `[${label}] Process exited with code ${code}`)
      const project = this.projects.get(id)
      if (project) {
        if (label === "watch") project.watchProc = undefined
        if (label === "fix") project.fixProc = undefined
        if (!project.watchProc && !project.fixProc) {
          project.status = "stopped"
          this.saveConfigs()
        }
      }
    })
  }

  async stopAgents(id: string): Promise<void> {
    const project = this.projects.get(id)
    if (!project) return

    if (project.watchProc) {
      try { project.watchProc.kill("SIGTERM") } catch {}
      project.watchProc = undefined
    }
    if (project.fixProc) {
      try { project.fixProc.kill("SIGTERM") } catch {}
      project.fixProc = undefined
    }

    project.status = "stopped"
    await this.saveConfigs()
    this.appendLog(id, "Agents stopped")
  }

  getProject(id: string): (ProjectConfig & { logs: string[] }) | null {
    const p = this.projects.get(id)
    if (!p) return null
    const { watchProc, fixProc, ...rest } = p
    return rest
  }

  listProjects(): (ProjectConfig & { logs: string[] })[] {
    return [...this.projects.values()].map(({ watchProc, fixProc, ...rest }) => rest)
  }

  getLogs(id: string, limit = 50): string[] {
    const project = this.projects.get(id)
    if (!project) return []
    return project.logs.slice(-limit)
  }

  async getReports(id: string, limit = 20): Promise<any[]> {
    const reportsDir = this.reportsPath(id) + "/reports"
    try {
      const files = await fs.readdir(reportsDir)
      const jsonFiles = files.filter((f) => f.endsWith(".json")).sort().reverse().slice(0, limit)
      const reports = []
      for (const file of jsonFiles) {
        try {
          const raw = await fs.readFile(path.join(reportsDir, file), "utf-8")
          reports.push(JSON.parse(raw))
        } catch {}
      }
      return reports
    } catch {
      return []
    }
  }

  async getFixes(id: string, limit = 20): Promise<any[]> {
    const fixDir = this.reportsPath(id) + "/fixes"
    try {
      const files = await fs.readdir(fixDir)
      const jsonFiles = files.filter((f) => f.endsWith(".json")).sort().reverse().slice(0, limit)
      const fixes = []
      for (const file of jsonFiles) {
        try {
          const raw = await fs.readFile(path.join(fixDir, file), "utf-8")
          fixes.push(JSON.parse(raw))
        } catch {}
      }
      return fixes
    } catch {
      return []
    }
  }

  async shutdown(): Promise<void> {
    for (const [id] of this.projects) {
      await this.stopAgents(id)
    }
  }
}
