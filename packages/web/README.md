# @cyberstrike/web

Documentation and marketing website for Cyberstrike, built with Astro and Starlight.

## Overview

This package contains:

- Documentation pages (`/docs`)
- Marketing landing pages
- Blog posts
- API reference

## Development

```bash
# Install dependencies (from repo root)
bun install

# Start dev server
bun run dev

# Start with remote API
bun run dev:remote

# Build for production
bun run build

# Preview production build
bun run preview
```

## Project Structure

```
src/
  content/
    docs/       # Documentation pages (MDX)
  pages/        # Marketing pages (Astro)
  components/   # Shared components
public/         # Static assets
```

## Tech Stack

- **Framework**: Astro
- **Docs**: Starlight
- **Styling**: TailwindCSS
- **Deployment**: Cloudflare Pages

## License

MIT
