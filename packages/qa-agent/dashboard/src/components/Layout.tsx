import { Link, Outlet, useNavigate } from "react-router-dom"
import { useEffect, useState } from "react"
import { api } from "../api"

export function Layout() {
  const navigate = useNavigate()
  const [authenticated, setAuthenticated] = useState(true)

  useEffect(() => {
    const check = () =>
      api.getAuthStatus().then((s) => setAuthenticated(s.authenticated)).catch(() => setAuthenticated(false))
    check()
    const interval = setInterval(check, 30_000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <nav className="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <Link to="/" className="text-lg font-bold text-emerald-400">
            QA Agent
          </Link>
          <Link to="/" className="text-sm text-gray-400 hover:text-white">
            Projects
          </Link>
          <Link to="/add" className="text-sm text-gray-400 hover:text-white">
            + Add
          </Link>
        </div>
        <button
          onClick={() => navigate("/login")}
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-white"
        >
          <span
            className={`w-2 h-2 rounded-full ${authenticated ? "bg-emerald-400" : "bg-red-400"}`}
          />
          {authenticated ? "Claude Connected" : "Not Authenticated"}
        </button>
      </nav>
      <main className="max-w-6xl mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
