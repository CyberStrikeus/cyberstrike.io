# @cyberstrike/enterprise

Enterprise features and team management for Cyberstrike.

## Overview

This package provides enterprise-grade features including:

- Team workspaces and collaboration
- User management and access control
- Usage analytics and reporting
- SSO integration

## Development

```bash
# Install dependencies (from repo root)
bun install

# Start dev server
bun run dev

# Type check
bun run typecheck

# Build for production
bun run build

# Build for Cloudflare
bun run build:cloudflare
```

## Tech Stack

- **Framework**: SolidStart
- **Backend**: Hono on Cloudflare Workers
- **Styling**: TailwindCSS
- **Infrastructure**: SST

## License

MIT
