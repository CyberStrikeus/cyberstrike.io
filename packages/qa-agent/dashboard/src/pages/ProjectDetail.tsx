import { useEffect, useState } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { api, type Project, type Report, type FixAttempt } from "../api"
import { StatusBadge } from "../components/StatusBadge"
import { ReportList } from "../components/ReportList"

export function ProjectDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [project, setProject] = useState<Project | null>(null)
  const [reports, setReports] = useState<Report[]>([])
  const [fixes, setFixes] = useState<FixAttempt[]>([])
  const [logs, setLogs] = useState<string[]>([])
  const [tab, setTab] = useState<"reports" | "fixes" | "logs">("reports")

  useEffect(() => {
    if (!id) return
    const load = () => {
      api.getProject(id).then(setProject).catch(console.error)
      api.getReports(id).then(setReports).catch(console.error)
      api.getFixes(id).then(setFixes).catch(console.error)
      api.getLogs(id).then(setLogs).catch(console.error)
    }
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [id])

  if (!project) return <p className="text-gray-500">Loading...</p>

  const handleStart = async () => {
    await api.startAgents(project.id)
    setProject({ ...project, status: "running" })
  }

  const handleStop = async () => {
    await api.stopAgents(project.id)
    setProject({ ...project, status: "stopped" })
  }

  const handleDelete = async () => {
    if (!confirm(`Delete "${project.name}" and all its data?`)) return
    await api.deleteProject(project.id)
    navigate("/")
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">{project.name}</h1>
          <p className="text-sm text-gray-500">{project.repoUrl}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={project.status} />
          {project.status === "running" ? (
            <button onClick={handleStop} className="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded text-sm">
              Stop
            </button>
          ) : (
            <button onClick={handleStart} className="bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5 rounded text-sm">
              Start
            </button>
          )}
          <button onClick={handleDelete} className="bg-red-600/20 hover:bg-red-600/40 text-red-400 px-3 py-1.5 rounded text-sm">
            Delete
          </button>
        </div>
      </div>

      <div className="flex gap-1 mb-4 border-b border-gray-800">
        {(["reports", "fixes", "logs"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize ${tab === t ? "text-emerald-400 border-b-2 border-emerald-400" : "text-gray-500 hover:text-gray-300"}`}
          >
            {t} {t === "reports" ? `(${reports.length})` : t === "fixes" ? `(${fixes.length})` : ""}
          </button>
        ))}
      </div>

      {tab === "reports" && <ReportList reports={reports} />}

      {tab === "fixes" && (
        <div className="space-y-3">
          {fixes.length === 0 && <p className="text-gray-500 text-sm">No fix attempts yet.</p>}
          {fixes.map((f, i) => (
            <div key={i} className="bg-gray-900 border border-gray-800 rounded p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-xs text-gray-400">
                  {f.commitHash.slice(0, 7)} - Attempt #{f.attempt}
                </span>
                <StatusBadge status={f.status} />
              </div>
              <p className="text-sm text-gray-300">{f.analysis}</p>
              {f.error && <p className="text-sm text-red-400 mt-1">{f.error}</p>}
              <p className="text-xs text-gray-600 mt-1">{(f.duration / 1000).toFixed(1)}s - {new Date(f.createdAt).toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      {tab === "logs" && (
        <div className="bg-gray-900 border border-gray-800 rounded p-3 font-mono text-xs max-h-96 overflow-y-auto">
          {logs.length === 0 && <p className="text-gray-500">No logs yet.</p>}
          {logs.map((line, i) => (
            <div key={i} className="text-gray-400 py-0.5">{line}</div>
          ))}
        </div>
      )}
    </div>
  )
}
