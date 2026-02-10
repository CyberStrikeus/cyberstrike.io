import { StatusBadge } from "./StatusBadge"
import type { Report } from "../api"

export function ReportList({ reports }: { reports: Report[] }) {
  if (reports.length === 0) {
    return <p className="text-gray-500 text-sm">No reports yet.</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-gray-500 border-b border-gray-800">
            <th className="pb-2 pr-4">Commit</th>
            <th className="pb-2 pr-4">Branch</th>
            <th className="pb-2 pr-4">Message</th>
            <th className="pb-2 pr-4">Verdict</th>
            <th className="pb-2 pr-4">Duration</th>
            <th className="pb-2">Time</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
              <td className="py-2 pr-4 font-mono text-xs">{r.commitInfo.shortHash}</td>
              <td className="py-2 pr-4 text-gray-400">{r.commitInfo.branch}</td>
              <td className="py-2 pr-4 text-gray-300 max-w-xs truncate">{r.commitInfo.message}</td>
              <td className="py-2 pr-4"><StatusBadge status={r.verdict} /></td>
              <td className="py-2 pr-4 text-gray-500">{(r.duration / 1000).toFixed(1)}s</td>
              <td className="py-2 text-gray-500">{new Date(r.createdAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
