const COLORS: Record<string, string> = {
  running: "bg-emerald-500/20 text-emerald-400",
  stopped: "bg-gray-500/20 text-gray-400",
  error: "bg-red-500/20 text-red-400",
  PASSED: "bg-emerald-500/20 text-emerald-400",
  FAILED: "bg-red-500/20 text-red-400",
  WARNING: "bg-yellow-500/20 text-yellow-400",
  committed: "bg-emerald-500/20 text-emerald-400",
  analyzing: "bg-blue-500/20 text-blue-400",
  fixing: "bg-yellow-500/20 text-yellow-400",
  failed: "bg-red-500/20 text-red-400",
}

export function StatusBadge({ status }: { status: string }) {
  const color = COLORS[status] || "bg-gray-500/20 text-gray-400"
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded ${color}`}>
      {status}
    </span>
  )
}
