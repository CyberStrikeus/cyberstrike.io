import z from "zod"
import { Tool } from "./tool"
import { Todo } from "../session/todo"
import { ulid } from "ulid"

/**
 * These tools mirror Claude Code's Task* tools but also sync to the sidebar's Todo list.
 * This ensures that when the AI uses TaskCreate/TaskUpdate, the progress is visible in the sidebar.
 */

const TaskStatus = z.enum(["pending", "in_progress", "completed", "deleted"])
const TaskPriority = z.enum(["high", "medium", "low"])

// In-memory task storage (per session)
const taskStorage = new Map<string, Map<string, TaskInfo>>()

interface TaskInfo {
  id: string
  subject: string
  description: string
  status: z.infer<typeof TaskStatus>
  priority: z.infer<typeof TaskPriority>
  activeForm?: string
  owner?: string
  blockedBy?: string[]
  blocks?: string[]
}

function getSessionTasks(sessionID: string): Map<string, TaskInfo> {
  if (!taskStorage.has(sessionID)) {
    taskStorage.set(sessionID, new Map())
  }
  return taskStorage.get(sessionID)!
}

async function syncToSidebar(sessionID: string) {
  const tasks = getSessionTasks(sessionID)
  const todos: Todo.Info[] = []

  for (const task of tasks.values()) {
    if (task.status !== "deleted") {
      todos.push({
        id: task.id,
        content: task.subject,
        status: task.status === "completed" ? "completed" : task.status === "in_progress" ? "in_progress" : "pending",
        priority: task.priority,
      })
    }
  }

  await Todo.update({ sessionID, todos })
}

export const TaskCreateTool = Tool.define("task_create", {
  description: "Create a new task to track progress. Tasks appear in the sidebar's Todo list.",
  parameters: z.object({
    subject: z.string().describe("Brief title for the task"),
    description: z.string().describe("Detailed description of what needs to be done"),
    activeForm: z.string().optional().describe("Present continuous form shown when in_progress (e.g., 'Running tests')"),
    priority: TaskPriority.optional().default("medium").describe("Task priority"),
  }),
  async execute(params, ctx) {
    const tasks = getSessionTasks(ctx.sessionID)
    const id = ulid()

    const task: TaskInfo = {
      id,
      subject: params.subject,
      description: params.description,
      status: "pending",
      priority: params.priority ?? "medium",
      activeForm: params.activeForm,
    }

    tasks.set(id, task)
    await syncToSidebar(ctx.sessionID)

    return {
      title: `Created task: ${params.subject}`,
      output: `Task #${id.slice(-4)} created: ${params.subject}`,
      metadata: { taskId: id },
    }
  },
})

export const TaskUpdateTool = Tool.define("task_update", {
  description: "Update a task's status or details. Changes appear in the sidebar's Todo list.",
  parameters: z.object({
    taskId: z.string().describe("The task ID to update"),
    status: TaskStatus.optional().describe("New status: pending, in_progress, completed, or deleted"),
    subject: z.string().optional().describe("New subject"),
    description: z.string().optional().describe("New description"),
    activeForm: z.string().optional().describe("New activeForm"),
    priority: TaskPriority.optional().describe("New priority"),
  }),
  async execute(params, ctx) {
    const tasks = getSessionTasks(ctx.sessionID)

    // Find task by ID (could be full ID or last 4 chars)
    let task: TaskInfo | undefined
    for (const [id, t] of tasks) {
      if (id === params.taskId || id.endsWith(params.taskId)) {
        task = t
        break
      }
    }

    if (!task) {
      return {
        title: "Task not found",
        output: `Task ${params.taskId} not found`,
        metadata: { error: true },
      }
    }

    if (params.status) task.status = params.status
    if (params.subject) task.subject = params.subject
    if (params.description) task.description = params.description
    if (params.activeForm) task.activeForm = params.activeForm
    if (params.priority) task.priority = params.priority

    await syncToSidebar(ctx.sessionID)

    return {
      title: `Updated task: ${task.subject}`,
      output: `Task #${task.id.slice(-4)} updated: ${task.status}`,
      metadata: { taskId: task.id, status: task.status },
    }
  },
})

export const TaskListTool = Tool.define("task_list", {
  description: "List all tasks in the current session.",
  parameters: z.object({}),
  async execute(_params, ctx) {
    const tasks = getSessionTasks(ctx.sessionID)
    const taskList = Array.from(tasks.values())
      .filter(t => t.status !== "deleted")
      .map(t => `#${t.id.slice(-4)} [${t.status}] ${t.subject}`)
      .join("\n")

    return {
      title: `${tasks.size} tasks`,
      output: taskList || "No tasks found",
      metadata: { count: tasks.size },
    }
  },
})

export const TaskGetTool = Tool.define("task_get", {
  description: "Get details of a specific task.",
  parameters: z.object({
    taskId: z.string().describe("The task ID to retrieve"),
  }),
  async execute(params, ctx) {
    const tasks = getSessionTasks(ctx.sessionID)

    let task: TaskInfo | undefined
    for (const [id, t] of tasks) {
      if (id === params.taskId || id.endsWith(params.taskId)) {
        task = t
        break
      }
    }

    if (!task) {
      return {
        title: "Task not found",
        output: `Task ${params.taskId} not found`,
        metadata: { error: true },
      }
    }

    return {
      title: task.subject,
      output: JSON.stringify(task, null, 2),
      metadata: task,
    }
  },
})
