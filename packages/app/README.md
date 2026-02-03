# @cyberstrike/app

Web application UI for Cyberstrike, built with SolidJS and Vite.

## Overview

This package contains the shared web UI components and application logic used by both the web interface and desktop application.

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
```

## E2E Testing

Playwright tests require a running Cyberstrike backend.

```bash
# Install Playwright browsers
bunx playwright install

# Run tests with local sandbox
bun run test:e2e:local

# Run specific tests
bun run test:e2e:local -- --grep "settings"
```

### Environment Variables

- `PLAYWRIGHT_SERVER_HOST` / `PLAYWRIGHT_SERVER_PORT` - Backend address (default: `localhost:4096`)
- `PLAYWRIGHT_PORT` - Vite dev server port (default: `3000`)
- `PLAYWRIGHT_BASE_URL` - Override base URL

## Tech Stack

- **Framework**: SolidJS
- **Build**: Vite
- **Styling**: TailwindCSS
- **Testing**: Playwright

## License

MIT
