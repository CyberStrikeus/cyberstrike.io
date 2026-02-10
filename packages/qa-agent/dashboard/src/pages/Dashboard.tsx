import { useEffect, useState } from "react"
import { api, type Project } from "../api"
import { ProjectCard } from "../components/ProjectCard"

export function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = () => api.listProjects().then(setProjects).catch(console.error).finally(() => setLoading(false))
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return <p className="text-gray-500">Loading...</p>
  }

  if (projects.length === 0) {
    return (
      <div className="text-center py-20">
        <h2 className="text-xl font-semibold text-gray-300 mb-2">No projects yet</h2>
        <p className="text-gray-500 mb-6">Add a git repository to start monitoring.</p>
        <a href="/add" className="bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded text-sm">
          + Add Project
        </a>
      </div>
    )
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Projects</h1>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {projects.map((p) => (
          <ProjectCard key={p.id} project={p} />
        ))}
      </div>
    </div>
  )
}
