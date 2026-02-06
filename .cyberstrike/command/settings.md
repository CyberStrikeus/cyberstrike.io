---
description: View or modify Cyberstrike settings (timeout, etc.)
---

# Settings Command

The user wants to view or modify settings. Parse the command arguments and take appropriate action.

## Command Format

```
/settings                           # Show all settings
/settings timeout                   # Show all timeout settings
/settings timeout <key> <value>     # Set a specific timeout
/settings timeout reset             # Reset timeouts to defaults
```

## Available Timeout Keys

| Key | Description | Default |
|-----|-------------|---------|
| mcp | MCP server connection timeout (ms) | 30000 |
| provider | Provider API request timeout (ms) | 300000 |
| bash | Bash command execution timeout (ms) | 120000 |
| websearch | Web search request timeout (ms) | 25000 |
| codesearch | Code search request timeout (ms) | 30000 |
| webfetch | Web fetch request timeout (ms) | 30000 |
| instruction | Instruction URL fetch timeout (ms) | 15000 |

## Instructions

1. **If no arguments** or just `/settings`:
   - Read the current config file
   - Display all settings in a formatted table

2. **If `/settings timeout`** (no value):
   - Read the current config and show only timeout settings
   - Show current values vs defaults

3. **If `/settings timeout <key> <value>`**:
   - Validate the key is one of the allowed timeout keys
   - Validate the value is a positive integer (milliseconds)
   - Update the config file using the Config.updateGlobal() function
   - Confirm the change

4. **If `/settings timeout reset`**:
   - Remove the timeout section from config
   - Confirm reset to defaults

## Current Config

!`cat ~/.config/cyberstrike/cyberstrike.json 2>/dev/null || echo "{}"`

## User Input

$ARGUMENTS
