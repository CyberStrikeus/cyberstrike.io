# Cyberstrike Website

Landing page and documentation for Cyberstrike.

## Structure

```
website/
├── landing/          # Main website (cyberstrike.io)
│   ├── src/
│   ├── Dockerfile
│   └── nginx.conf
│
├── docs/             # Documentation (docs.cyberstrike.io)
│   ├── src/
│   ├── Dockerfile
│   └── nginx.conf
│
└── docker-compose.yml
```

## Local Development

### Landing Page
```bash
cd landing
pnpm install
pnpm dev
# Open http://localhost:4321
```

### Documentation
```bash
cd docs
pnpm install
pnpm dev
# Open http://localhost:4321
```

## Docker Build

```bash
# Build both
docker-compose build

# Run both
docker-compose up -d

# Landing: http://localhost:3000
# Docs: http://localhost:3001
```

## Coolify Deployment

### Landing Page (cyberstrike.io)
1. Create new project in Coolify
2. Source: Git repository → `website/landing`
3. Build Pack: Dockerfile
4. Domain: `cyberstrike.io`

### Documentation (docs.cyberstrike.io)
1. Create new project in Coolify
2. Source: Git repository → `website/docs`
3. Build Pack: Dockerfile
4. Domain: `docs.cyberstrike.io`

## Configuration

### Landing Page
- Site config: `landing/src/config/en/siteData.json.ts`
- Navigation: `landing/src/config/en/navData.json.ts`
- FAQ: `landing/src/config/en/faqData.json.ts`

### Documentation
- Site config: `docs/src/docs/config/en/siteData.json.ts`
- Sidebar: `docs/src/docs/config/en/sidebarNavData.json.ts`
- Content: `docs/src/content/docs/`

## Backend Integration

API endpoints are hosted on Cloudflare Workers:
- Console: `https://console.cyberstrike.io`
- API: `https://api.cyberstrike.io`
