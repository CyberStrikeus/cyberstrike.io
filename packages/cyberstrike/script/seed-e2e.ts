const dir = process.env.CYBERSTRIKE_E2E_PROJECT_DIR ?? process.cwd()
const title = process.env.CYBERSTRIKE_E2E_SESSION_TITLE ?? "E2E Session"
const text = process.env.CYBERSTRIKE_E2E_MESSAGE ?? "Seeded for UI e2e"
const model = process.env.CYBERSTRIKE_E2E_MODEL ?? "cyberstrike/gpt-5-nano"
const parts = model.split("/")
const providerID = parts[0] ?? "cyberstrike"
const modelID = parts[1] ?? "gpt-5-nano"
const now = Date.now()

const seed = async () => {
  const { Instance } = await import("../src/project/instance")
  const { InstanceBootstrap } = await import("../src/project/bootstrap")
  const { Session } = await import("../src/session")
  const { Identifier } = await import("../src/id/id")
  const { Project } = await import("../src/project/project")

  await Instance.provide({
    directory: dir,
    init: InstanceBootstrap,
    fn: async () => {
      const session = await Session.create({ title })
      const messageID = Identifier.descending("message")
      const partID = Identifier.descending("part")
      const message = {
        id: messageID,
        sessionID: session.id,
        role: "user" as const,
        time: { created: now },
        agent: "build",
        model: {
          providerID,
          modelID,
        },
      }
      const part = {
        id: partID,
        sessionID: session.id,
        messageID,
        type: "text" as const,
        text,
        time: { start: now },
      }
      await Session.updateMessage(message)
      await Session.updatePart(part)

      // Seed an assistant message with token usage for context panel tests
      const assistantMessageID = Identifier.descending("message")
      const assistantPartID = Identifier.descending("part")
      const stepFinishPartID = Identifier.descending("part")
      const assistantMessage = {
        id: assistantMessageID,
        sessionID: session.id,
        role: "assistant" as const,
        time: { created: now + 1 },
        parentID: messageID,
        modelID,
        providerID,
        mode: "chat",
        agent: "build",
        path: { cwd: dir, root: dir },
        cost: 0.0003,
        tokens: {
          input: 150,
          output: 50,
          reasoning: 0,
          cache: { read: 0, write: 0 },
        },
      }
      const assistantPart = {
        id: assistantPartID,
        sessionID: session.id,
        messageID: assistantMessageID,
        type: "text" as const,
        text: "Seeded assistant response for E2E testing.",
        time: { start: now + 1 },
      }
      const stepFinishPart = {
        id: stepFinishPartID,
        sessionID: session.id,
        messageID: assistantMessageID,
        type: "step-finish" as const,
        reason: "stop",
        cost: 0.0003,
        tokens: {
          input: 150,
          output: 50,
          reasoning: 0,
          cache: { read: 0, write: 0 },
        },
        time: { start: now + 2 },
      }
      await Session.updateMessage(assistantMessage)
      await Session.updatePart(assistantPart)
      await Session.updatePart(stepFinishPart)

      await Project.update({ projectID: Instance.project.id, name: "E2E Project" })
    },
  })
}

await seed()
