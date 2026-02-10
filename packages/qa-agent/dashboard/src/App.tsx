import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { useEffect, useState } from "react"
import { api } from "./api"
import { Layout } from "./components/Layout"
import { Dashboard } from "./pages/Dashboard"
import { AddProject } from "./pages/AddProject"
import { ProjectDetail } from "./pages/ProjectDetail"
import { Login } from "./pages/Login"

export function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null)

  useEffect(() => {
    api.getAuthStatus().then((s) => setAuthenticated(s.authenticated)).catch(() => setAuthenticated(false))
  }, [])

  if (authenticated === null) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <p className="text-gray-500">Loading...</p>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login onAuth={() => setAuthenticated(true)} />} />
        <Route element={authenticated ? <Layout /> : <Navigate to="/login" replace />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/add" element={<AddProject />} />
          <Route path="/project/:id" element={<ProjectDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
