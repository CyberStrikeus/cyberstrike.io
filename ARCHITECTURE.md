# Cyberstrike Architecture Documentation

## Overview

Cyberstrike is an AI-powered penetration testing framework that integrates multiple AI providers (Anthropic, OpenAI, OpenRouter, etc.) with specialized security testing agents. It's built as a monorepo with a CLI tool, web console, and documentation website.

---

## Project Structure

```
cyberstrike/
├── packages/
│   ├── cyberstrike/          # Main CLI application
│   │   ├── src/
│   │   │   ├── agent/        # Agent definitions and prompts
│   │   │   ├── auth/         # Authentication handling
│   │   │   ├── cli/          # CLI commands
│   │   │   ├── config/       # Configuration management
│   │   │   ├── provider/     # AI provider integrations
│   │   │   ├── session/      # Session management
│   │   │   ├── tool/         # Tool implementations
│   │   │   └── util/         # Utilities
│   │   └── test/             # Test files
│   ├── console/              # Web console application
│   └── ui/                   # Shared UI components
│       └── src/assets/       # Icons, favicons
├── website/
│   ├── landing/              # Astro-based landing page
│   │   ├── public/           # Static assets (logo, favicons)
│   │   └── src/
│   │       ├── components/   # Astro components
│   │       ├── data/         # Content data (codeToggles, etc.)
│   │       └── layouts/      # Page layouts
│   └── docs/                 # Documentation site
├── .cyberstrike/             # Project-level configuration
│   └── agents/               # Custom agent definitions (markdown)
└── specs/                    # Specifications
```

---

## Agent System

### Native Agents (Built-in)

Located in `packages/cyberstrike/src/agent/agent.ts`:

| Agent | Mode | Description |
|-------|------|-------------|
| `build` | primary | Default agent with full tool access |
| `plan` | primary | Planning mode, restricted edit tools |
| `explore` | subagent | Fast codebase exploration |
| `general` | subagent | General-purpose research tasks |
| `web-application` | primary | OWASP Top 10, WSTG methodology |
| `cloud-security` | primary | AWS, Azure, GCP security testing |
| `internal-network` | primary | AD, Kerberos, lateral movement |
| `bug-hunter` | primary | Bug bounty, recon automation |

### Agent Prompts

Located in `packages/cyberstrike/src/agent/prompt/`:

- `web-application.txt` - WSTG checklist, OWASP methodology
- `cloud-security.txt` - CIS benchmarks, IAM analysis
- `internal-network.txt` - AD attacks, privilege escalation
- `bug-hunter.txt` - Recon, subdomain enum, JS analysis
- `explore.txt` - Codebase exploration
- `compaction.txt` - Context compaction
- `summary.txt` - Session summarization
- `title.txt` - Title generation

### Custom Agents (Markdown)

Users can define custom agents in `.cyberstrike/agents/*.md`:

```markdown
---
name: my-agent
description: Description for agent selection
model: anthropic/claude-sonnet-4-5-20250514  # Optional - uses default if omitted
temperature: 0.7
color: "#FF5733"
---

# Agent System Prompt

Your custom instructions here...
```

**Fields:**
- `name` - Agent identifier
- `description` - Shown in agent picker
- `model` - Optional, format: `provider/model-id`
- `temperature` - Optional, 0-1
- `top_p` - Optional
- `color` - Hex color for UI
- `mode` - `primary`, `subagent`, or `all`
- `permission` - Permission overrides

---

## Provider System

### Supported Providers

Located in `packages/cyberstrike/src/provider/provider.ts`:

| Provider | SDK Package | Notes |
|----------|-------------|-------|
| Anthropic | `@ai-sdk/anthropic` | Claude models |
| OpenAI | `@ai-sdk/openai` | GPT models |
| OpenRouter | `@openrouter/ai-sdk-provider` | Multi-model gateway |
| Amazon Bedrock | `@ai-sdk/amazon-bedrock` | AWS hosted models |
| Azure | `@ai-sdk/azure` | Azure OpenAI |
| Google Vertex | `@ai-sdk/google-vertex` | Gemini models |
| GitHub Copilot | Custom | Copilot integration |
| Claude CLI | `@cyberstrike/claude-cli` | Local Claude Code subprocess |

### Model Configuration

In `cyberstrike.json`:

```json
{
  "model": "anthropic/claude-sonnet-4-5-20250514",
  "small_model": "anthropic/claude-haiku-4-5-20250514",
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "${env:ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

### Model ID Format

```
provider/model-id

Examples:
- anthropic/claude-sonnet-4-5-20250514
- openai/gpt-5
- openrouter/meta-llama/llama-4-scout
```

---

## Configuration System

### Configuration Hierarchy (Low to High Priority)

1. Remote/Well-known config
2. Global config (`~/.cyberstrike/cyberstrike.json`)
3. Custom config (`CYBERSTRIKE_CONFIG` env var)
4. Project config (`./cyberstrike.json`)
5. Inline config (`CYBERSTRIKE_CONFIG_CONTENT` env var)

### Config Directories Scanned

- `~/.config/cyberstrike/` - Global config
- `~/.cyberstrike/` - User home config
- `./.cyberstrike/` - Project config

### Configuration Schema

```typescript
interface Config {
  $schema?: string;
  model?: string;                    // Default model (provider/model-id)
  small_model?: string;              // Small model for titles, etc.
  default_agent?: string;            // Default agent name
  theme?: string;                    // UI theme

  agent?: Record<string, AgentConfig>;
  provider?: Record<string, ProviderConfig>;
  mcp?: Record<string, McpConfig>;
  permission?: PermissionConfig;
  keybinds?: KeybindsConfig;

  disabled_providers?: string[];
  enabled_providers?: string[];

  compaction?: {
    auto?: boolean;
    prune?: boolean;
  };
}
```

### Agent Config Schema

```typescript
interface AgentConfig {
  model?: string;           // provider/model-id
  temperature?: number;     // 0-1
  top_p?: number;          // 0-1
  prompt?: string;         // System prompt
  description?: string;    // When to use
  mode?: 'subagent' | 'primary' | 'all';
  hidden?: boolean;        // Hide from picker
  color?: string;          // Hex color
  steps?: number;          // Max iterations
  disable?: boolean;       // Disable agent
  permission?: Permission; // Permission overrides
}
```

---

## Permission System

### Permission Actions

- `allow` - Always allow
- `deny` - Always deny
- `ask` - Ask user for permission

### Permission Categories

```typescript
interface Permission {
  read?: PermissionRule;      // File reading
  edit?: PermissionRule;      // File editing
  bash?: PermissionRule;      // Shell commands
  glob?: PermissionRule;      // File globbing
  grep?: PermissionRule;      // Content search
  webfetch?: PermissionRule;  // Web fetching
  websearch?: PermissionRule; // Web search
  task?: PermissionRule;      // Subagent tasks
  external_directory?: PermissionRule;
  // ... more
}

type PermissionRule = PermissionAction | Record<string, PermissionAction>;
```

### Pattern-Based Permissions

```json
{
  "permission": {
    "read": {
      "*": "allow",
      "*.env": "ask",
      "*.env.*": "ask"
    },
    "bash": {
      "*": "allow",
      "rm -rf *": "deny"
    }
  }
}
```

---

## Website Architecture

### Landing Page (Astro)

Location: `website/landing/`

**Key Components:**
- `src/components/Feature/FeatureCodeToggle.astro` - Installation tabs with copy button
- `src/components/SiteLogo/SiteLogo.astro` - Logo component
- `src/layouts/BaseHead.astro` - HTML head with favicons

**Code Toggles Data:**
- `src/data/codeToggles/cli/index.mdx` - One-liner tab
- `src/data/codeToggles/config/index.mdx` - npm tab
- `src/data/codeToggles/sdk/index.mdx` - Homebrew tab

**Static Assets:**
- `public/logo.svg` - Lightning bolt logo
- `public/favicons/` - Favicon files

### Docs Site

Location: `website/docs/`

- `public/logo.svg` - Lightning bolt logo
- `public/images/logo.svg` - Logo for docs

---

## Branding

### Logo

The project uses the Amplify template's lightning bolt logo:

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 16 16">
  <path fill="#3b82f6"
    d="M11.251.068a.5.5 0 0 1 .227.58L9.677 6.5H13a.5.5 0 0 1 .364.843l-8 8.5a.5.5 0 0 1-.842-.49L6.323 9.5H3a.5.5 0 0 1-.364-.843l8-8.5a.5.5 0 0 1 .615-.09zM4.157 8.5H7a.5.5 0 0 1 .478.647L6.11 13.59l5.732-6.09H9a.5.5 0 0 1-.478-.647L9.89 2.41z" />
</svg>
```

### Primary Color

`#3b82f6` (Blue-500)

### Logo Locations

- `/website/landing/public/logo.svg`
- `/website/landing/public/favicons/favicon.svg`
- `/website/docs/public/logo.svg`
- `/website/docs/public/images/logo.svg`
- `/packages/ui/src/assets/favicon/favicon.svg`

---

## Icons

### Tabler Icons

Located in `website/landing/src/icons/tabler/`:

Custom icons added:
- `brand-npm.svg` - npm package manager
- `brand-apple.svg` - Apple/Homebrew
- `copy.svg` - Copy to clipboard

Usage in Astro:
```astro
import { Icon } from "astro-icon/components";
<Icon name="tabler/terminal-2" class="size-4" />
```

---

## Development

### Running the CLI

```bash
cd packages/cyberstrike
bun run dev                    # Development mode
bun run dev --agent web-application  # Specific agent
bun run build                  # Build for production
```

### Running the Website

```bash
cd website/landing
npm run dev                    # Start dev server (port 4321+)
npm run build                  # Build for production
```

### Environment Variables

```bash
# API Keys
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
OPENROUTER_API_KEY=...

# Config overrides
CYBERSTRIKE_CONFIG=/path/to/config.json
CYBERSTRIKE_CONFIG_CONTENT='{"model":"..."}'
CYBERSTRIKE_DISABLE_PROJECT_CONFIG=true
```

---

## Persistent Memory System

Cyberstrike includes a Moltbot-inspired persistent memory system that maintains context across sessions.

### File Structure

```
.cyberstrike/
├── MEMORY.md              # Long-term memory (decisions, preferences, facts)
└── memory/
    ├── 2026-01-28.md     # Daily notes
    ├── 2026-01-27.md
    └── ...
```

### Memory Types

| Type | File | Purpose |
|------|------|---------|
| Long-term | `MEMORY.md` | Decisions, preferences, important facts |
| Daily | `memory/YYYY-MM-DD.md` | Session notes, temporary context |

### Memory Tools

| Tool | Description |
|------|-------------|
| `memory_write` | Save to long-term memory or daily notes |
| `memory_read` | Read specific memory files |
| `memory_search` | Search through all memory |
| `memory_context` | Get full memory context |

### Usage Examples

```
# Save user preference to long-term memory
> Remember that I prefer Python over JavaScript

# Search memory
> What do you remember about my preferences?

# Read specific memory
> Show me yesterday's notes
```

### Auto-Loading

At session start, memory context is automatically loaded into the system prompt:
- Long-term memory (MEMORY.md)
- Today's daily notes
- Yesterday's daily notes

---

## Skills Preload System

Skills are domain knowledge packages that are preloaded into an agent's context at startup.

### Skill File Structure

```
.cyberstrike/skills/           # Project-level skills
~/.config/cyberstrike/skills/  # User-level skills
```

### Skill File Format

```markdown
---
name: owasp-wstg
description: OWASP Web Security Testing Guide v4.2 Checklist
tags: [web, owasp, security, testing]
version: "4.2"
---

# OWASP Web Security Testing Guide

## Information Gathering (WSTG-INFO)
...
```

### Adding Skills to Agents

In agent definitions:

```typescript
"web-application": {
  name: "web-application",
  skills: ["owasp-wstg", "sql-injection"], // Preloaded at startup
  // ...
}
```

Or in custom agent markdown:

```yaml
---
name: my-agent
skills:
  - owasp-wstg
  - recon-methodology
---
```

### Available Skills

| Skill | Description |
|-------|-------------|
| `owasp-wstg` | OWASP Web Security Testing Guide checklist |
| `sql-injection` | SQL injection techniques and payloads |
| `recon-methodology` | Bug bounty reconnaissance methodology |

### Skill Priority

1. Project-level (`.cyberstrike/skills/`) - Highest
2. User-level (`~/.config/cyberstrike/skills/`)
3. Plugin skills - Lowest

### Creating Custom Skills

```bash
mkdir -p .cyberstrike/skills
cat > .cyberstrike/skills/my-skill.md << 'EOF'
---
name: my-skill
description: My custom security skill
tags: [custom, security]
---

# My Skill Content

Your domain knowledge here...
EOF
```

---

## Model Recommendations

| Use Case | Recommended Model | Notes |
|----------|-------------------|-------|
| Pentest Agents | `claude-cli/opus` | Most capable, follows complex instructions |
| General coding | `claude-cli/sonnet` | Good balance of speed and capability |
| Quick tasks | `claude-cli/haiku` | Fast but conservative, may refuse some actions |

**Important:** Haiku models may refuse to execute commands like opening browsers or running security tools. For penetration testing, use **Opus** or **Sonnet**.

---

## Recent Changes (This Session)

1. **Logo/Favicon Update** - Replaced skull logos with Amplify template lightning bolt
2. **Code Toggle Tabs** - Changed from CLI/Config/SDK to One-liner/npm/Homebrew
3. **Copy Button** - Added copy-to-clipboard functionality
4. **Agent Model Config** - Made model field optional (inherits default)
5. **Environment Capabilities** - Added browser opening instructions to agent prompts
6. **New Icons** - Added brand-npm.svg, brand-apple.svg, copy.svg
7. **Claude CLI System Prompt** - Fixed to allow browser opening via `--system-prompt`
8. **Default Model** - Set to `claude-cli/opus` for better capability
9. **Persistent Memory System** - Added Moltbot-inspired memory with:
   - `memory/index.ts` - Core memory management
   - `tool/memory.ts` - Memory tools (search, write, read, context)
   - Auto-loading at session start
   - Daily notes and long-term memory support

10. **Skills Preload System** - Added Claude Code-inspired skills with:
    - `skill/index.ts` - Skill loading and formatting
    - Agent `skills` field for preloading domain knowledge
    - Example skills: `owasp-wstg`, `sql-injection`, `recon-methodology`
    - Automatic injection into system prompt

11. **Dynamic Tool Loading (ToolSearch Pattern)** - Scale to 100+ MCP tools:
    - `tool/lazy-registry.ts` - Lazy tool metadata storage
    - `tool/tool-search.ts` - Meta-tools for dynamic loading
    - Tools: `tool_search`, `load_tools`, `unload_tools`, `list_loaded_tools`
    - Context savings: ~48K tokens freed for conversation

---

## Dynamic Tool Loading

### The Problem

Each tool definition consumes ~500 tokens in the context window:
- Description: 100-300 tokens
- Parameter schema: 200-400 tokens
- Examples: 50-100 tokens

With 100 MCP tools: `100 × 500 = 50,000 tokens` just for tool definitions!

### The Solution: ToolSearch Pattern

Instead of loading all tool definitions, use meta-tools for dynamic discovery:

```
┌─────────────────────────────────────────────────────────────┐
│ Traditional Approach                                         │
├─────────────────────────────────────────────────────────────┤
│ System Prompt: [Tool1][Tool2][Tool3]...[Tool100]            │
│ Context used: ~50,000 tokens                                 │
│ Remaining for conversation: ~150,000 tokens                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ ToolSearch Pattern                                           │
├─────────────────────────────────────────────────────────────┤
│ System Prompt: [tool_search][load_tools][core_tools...]     │
│ Context used: ~5,000 tokens                                  │
│ Remaining for conversation: ~195,000 tokens                  │
│                                                              │
│ Dynamic loading:                                             │
│ 1. tool_search("sql injection") → returns tool IDs          │
│ 2. load_tools(["sqlmap_scan"]) → loads full definition      │
│ 3. Tool available for next turn                              │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

**LazyToolRegistry** (`src/tool/lazy-registry.ts`):
```typescript
interface LazyTool {
  id: string
  name: string
  summary: string      // Max 100 chars
  keywords: string[]   // For search
  category: string     // For grouping
  source: "mcp" | "plugin" | "builtin"
}

// Only metadata stored (~50 tokens each)
// Full definitions loaded on-demand
```

**Meta-Tools** (`src/tool/tool-search.ts`):

| Tool | Purpose |
|------|---------|
| `tool_search` | Find tools by capability description |
| `load_tools` | Load selected tools into context |
| `unload_tools` | Free context budget |
| `list_loaded_tools` | Show current tool status |

### Usage Example

```
User: "I need to scan the target for SQL injection vulnerabilities"

Agent: Let me find the right tools for SQL injection testing.
       [Calls tool_search({ query: "sql injection scanner" })]

System: Found 3 matching tools:
        1. sqlmap_scan - Automated SQL injection testing
        2. burp_sqlmap - Burp Suite SQL injection scanner
        3. custom_sqli - Custom SQL injection payloads

Agent: I'll load the sqlmap tool.
       [Calls load_tools({ tool_ids: ["sqlmap_scan"] })]

System: Loaded 1 tool. Now available for use.

Agent: Now I can use sqlmap to test for SQL injection.
       [Calls sqlmap_scan({ target: "...", ... })]
```

### Token Budget

```typescript
const TOOL_CONTEXT_BUDGET = 30000  // ~30K tokens for tools
const AVG_TOKENS_PER_TOOL = 500

// Budget check before loading
function canLoad(newTools: number): boolean {
  const current = loadedTools.size * AVG_TOKENS_PER_TOOL
  const needed = newTools * AVG_TOKENS_PER_TOOL
  return (current + needed) < TOOL_CONTEXT_BUDGET
}
```

---

## File Quick Reference

| Purpose | Location |
|---------|----------|
| CLI Entry | `packages/cyberstrike/src/cli/index.ts` |
| Agent Definitions | `packages/cyberstrike/src/agent/agent.ts` |
| Agent Prompts | `packages/cyberstrike/src/agent/prompt/*.txt` |
| Provider System | `packages/cyberstrike/src/provider/provider.ts` |
| Config Schema | `packages/cyberstrike/src/config/config.ts` |
| Custom Agents | `.cyberstrike/agents/*.md` |
| Skills System | `packages/cyberstrike/src/skill/index.ts` |
| Memory System | `packages/cyberstrike/src/memory/index.ts` |
| Lazy Tool Registry | `packages/cyberstrike/src/tool/lazy-registry.ts` |
| ToolSearch Tools | `packages/cyberstrike/src/tool/tool-search.ts` |
| MCP Integration | `packages/cyberstrike/src/mcp/index.ts` |
| Landing Page | `website/landing/src/pages/index.astro` |
| Installation Tabs | `website/landing/src/components/Feature/FeatureCodeToggle.astro` |
| Tab Content | `website/landing/src/data/codeToggles/*/index.mdx` |
