import { RGBA } from "@cyberstrike/tui-core"
import { createSignal, onMount, onCleanup } from "solid-js"
import { useTheme } from "@tui/context/theme"

interface StatusBarProps {
  target?: string
  sessionCount?: number
  activeTools?: number
}

export function StatusBar(props: StatusBarProps) {
  const { theme } = useTheme()
  const [time, setTime] = createSignal(new Date())
  const [memoryUsage, setMemoryUsage] = createSignal(0)

  onMount(() => {
    // Update time every second
    const timeInterval = setInterval(() => {
      setTime(new Date())
    }, 1000)

    // Update memory usage every 5 seconds
    const memInterval = setInterval(() => {
      if (typeof process !== 'undefined' && process.memoryUsage) {
        const used = process.memoryUsage().heapUsed / 1024 / 1024
        setMemoryUsage(Math.round(used))
      }
    }, 5000)

    onCleanup(() => {
      clearInterval(timeInterval)
      clearInterval(memInterval)
    })
  })

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { hour12: false })
  }

  const StatusItem = (itemProps: { icon: string; label: string; value: string; color: RGBA }) => (
    <box flexDirection="row">
      <text fg={itemProps.color} selectable={false}>{itemProps.icon} </text>
      <text fg={theme.textMuted} selectable={false}>{itemProps.label}: </text>
      <text fg={itemProps.color} selectable={false}>{itemProps.value}</text>
    </box>
  )

  const Separator = () => (
    <text fg={theme.border} selectable={false}> │ </text>
  )

  return (
    <box
      flexDirection="row"
      paddingX={2}
      paddingY={0}
      borderStyle="single"
      borderColor={theme.border}
      justifyContent="space-between"
    >
      {/* Left section */}
      <box flexDirection="row">
        <StatusItem
          icon="⎯"
          label="TARGET"
          value={props.target || "none"}
          color={props.target ? theme.warning : theme.textMuted}
        />
        <Separator />
        <StatusItem
          icon="◉"
          label="SESSIONS"
          value={String(props.sessionCount || 0)}
          color={theme.info}
        />
        <Separator />
        <StatusItem
          icon="⚙"
          label="TOOLS"
          value={String(props.activeTools || 0)}
          color={props.activeTools ? theme.success : theme.textMuted}
        />
      </box>

      {/* Right section */}
      <box flexDirection="row">
        <StatusItem
          icon="◈"
          label="MEM"
          value={`${memoryUsage()}MB`}
          color={memoryUsage() > 500 ? theme.warning : theme.textMuted}
        />
        <Separator />
        <text fg={theme.primary} selectable={false}>⏱ {formatTime(time())}</text>
      </box>
    </box>
  )
}

// Minimal status indicator for inline use
export function StatusIndicator(props: { status: "idle" | "scanning" | "exploiting" | "error" }) {
  const { theme } = useTheme()

  const statusConfig = {
    idle: { icon: "●", color: theme.textMuted, label: "IDLE" },
    scanning: { icon: "◌", color: theme.info, label: "SCANNING" },
    exploiting: { icon: "◉", color: theme.warning, label: "EXPLOITING" },
    error: { icon: "✖", color: theme.error, label: "ERROR" },
  }

  const config = statusConfig[props.status]

  return (
    <box flexDirection="row">
      <text fg={config.color} selectable={false}>{config.icon} </text>
      <text fg={config.color} selectable={false}>{config.label}</text>
    </box>
  )
}
