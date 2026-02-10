import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { api } from "../api"

export function AddProject() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    name: "",
    repoUrl: "",
    build: "",
    test: "",
    branches: "",
  })
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const project = await api.addProject({
        name: form.name,
        repoUrl: form.repoUrl,
        build: form.build || undefined,
        test: form.test || undefined,
        branches: form.branches ? form.branches.split(",").map((b) => b.trim()) : undefined,
      })
      await api.startAgents(project.id)
      navigate("/")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add project")
    } finally {
      setLoading(false)
    }
  }

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }))

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-6">Add Project</h1>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Project Name *</label>
          <input
            type="text"
            value={form.name}
            onChange={set("name")}
            required
            placeholder="my-project"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Repository URL *</label>
          <input
            type="text"
            value={form.repoUrl}
            onChange={set("repoUrl")}
            required
            placeholder="https://github.com/user/repo.git"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Build Command</label>
          <input
            type="text"
            value={form.build}
            onChange={set("build")}
            placeholder="npm run build"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Test Command</label>
          <input
            type="text"
            value={form.test}
            onChange={set("test")}
            placeholder="npm test"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Branches (comma-separated, empty = all)</label>
          <input
            type="text"
            value={form.branches}
            onChange={set("branches")}
            placeholder="main, dev"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>

        {error && <p className="text-red-400 text-sm">{error}</p>}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 rounded font-medium"
        >
          {loading ? "Cloning & Starting..." : "Add & Start Agents"}
        </button>
      </form>
    </div>
  )
}
