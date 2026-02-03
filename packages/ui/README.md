# @cyberstrike/ui

Shared UI components and design system for Cyberstrike applications.

## Overview

This package contains reusable SolidJS components, styling utilities, and design tokens used across Cyberstrike web applications.

## Features

- **Components** - Reusable UI components built with SolidJS and Kobalte
- **Theme** - Dark/light theme support with CSS variables
- **Icons** - Provider icons and file type icons
- **Markdown** - Markdown rendering with syntax highlighting (Shiki) and math support (KaTeX)
- **Pierre** - Diff visualization components
- **i18n** - Internationalization utilities

## Usage

```typescript
// Import components
import Button from "@cyberstrike/ui/button"
import Dialog from "@cyberstrike/ui/dialog"

// Import styles
import "@cyberstrike/ui/styles"

// Import theme utilities
import { useTheme } from "@cyberstrike/ui/theme/context"
```

## Development

```bash
cd packages/ui

# Run development server
bun run dev

# Generate Tailwind config
bun run generate:tailwind

# Type check
bun run typecheck
```

## Tech Stack

- **SolidJS** - Reactive UI framework
- **Kobalte** - Accessible component primitives
- **TailwindCSS** - Utility-first CSS
- **Shiki** - Syntax highlighting
- **KaTeX** - Math rendering
- **Luxon** - Date/time formatting

## License

MIT
