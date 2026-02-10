const BASE = "/api"

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `Request failed: ${res.status}`)
  }
  return res.json()
}

export interface Project {
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

export interface Report {
  id: string
  commitHash: string
  commitInfo: { shortHash: string; branch: string; message: string }
  verdict: string
  duration: number
  createdAt: string
}

export interface FixAttempt {
  reportId: string
  commitHash: string
  branch: string
  fixBranch: string
  attempt: number
  analysis: string
  fixCommitHash?: string
  status: string
  error?: string
  duration: number
  createdAt: string
}

export interface AuthStatus {
  authenticated: boolean
  expiresAt?: string
}

export const api = {
  // Auth
  getAuthStatus: () => request<AuthStatus>("/auth/status"),
  relayCallback: (callbackUrl: string) =>
    request<{ success: boolean; error?: string }>("/auth/callback-relay", {
      method: "POST",
      body: JSON.stringify({ callbackUrl }),
    }),
  logout: () => request<{ success: boolean }>("/auth/logout", { method: "POST" }),

  // Projects
  listProjects: () => request<Project[]>("/projects"),
  getProject: (id: string) => request<Project>(`/projects/${id}`),
  addProject: (data: Partial<Project>) =>
    request<Project>("/projects", { method: "POST", body: JSON.stringify(data) }),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: "DELETE" }),
  startAgents: (id: string) => request<void>(`/projects/${id}/start`, { method: "POST" }),
  stopAgents: (id: string) => request<void>(`/projects/${id}/stop`, { method: "POST" }),
  getReports: (id: string) => request<Report[]>(`/projects/${id}/reports`),
  getFixes: (id: string) => request<FixAttempt[]>(`/projects/${id}/fixes`),
  getLogs: (id: string) => request<string[]>(`/projects/${id}/logs`),
}
