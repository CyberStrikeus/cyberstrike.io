import { Link } from "react-router-dom"
import { StatusBadge } from "./StatusBadge"
import type { Project } from "../api"

export function ProjectCard({ project }: { project: Project }) {
  return (
    <Link
      to={`/project/${project.id}`}
      className="block bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-600 transition-colors"
    >
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-white">{project.name}</h3>
        <StatusBadge status={project.status} />
      </div>
      <p className="text-sm text-gray-500 truncate mb-3">{project.repoUrl}</p>
      <div className="flex gap-2 text-xs text-gray-600">
        {project.build && <span>build: {project.build}</span>}
        {project.test && <span>test: {project.test}</span>}
      </div>
    </Link>
  )
}
