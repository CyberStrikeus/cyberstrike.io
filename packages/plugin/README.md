# @cyberstrike/plugin

Plugin API for extending Cyberstrike with custom functionality.

## Overview

This package provides the API for creating Cyberstrike plugins. Plugins can add new tools, modify behavior, and integrate with external services.

## Installation

```bash
npm install @cyberstrike/plugin
```

## Usage

```typescript
import { definePlugin } from "@cyberstrike/plugin"
import { defineTool } from "@cyberstrike/plugin/tool"

export default definePlugin({
  name: "my-plugin",
  tools: [
    defineTool({
      name: "my-tool",
      description: "A custom tool",
      parameters: z.object({
        input: z.string()
      }),
      execute: async ({ input }) => {
        return { result: `Processed: ${input}` }
      }
    })
  ]
})
```

## API

### `definePlugin(options)`

Creates a plugin definition with the following options:

- `name` - Plugin identifier
- `tools` - Array of tool definitions
- `hooks` - Lifecycle hooks (optional)

### `defineTool(options)`

Creates a tool definition with:

- `name` - Tool name
- `description` - Tool description for the AI
- `parameters` - Zod schema for input validation
- `execute` - Async function that performs the tool action

## License

MIT
