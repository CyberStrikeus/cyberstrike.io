/**
 * Cloudflare Worker for bolt.cyberstrike.io
 * Uses assets from cyberstrike.io
 */

const INSTALL_SCRIPT = `#!/bin/bash
set -e

echo ""
echo "  ____        _ _   "
echo " | __ )  ___ | | |_ "
echo " |  _ \\\\ / _ \\\\| | __|"
echo " | |_) | (_) | | |_ "
echo " |____/ \\\\___/|_|\\\\__|"
echo ""
echo "Installing Bolt - Kali Linux tools via MCP"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Docker not found."
    echo ""
    echo "Install Docker first:"
    echo "  https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if bolt already exists
if docker ps -a --format '{{.Names}}' | grep -q '^bolt$'; then
    echo "Container 'bolt' already exists."
    echo ""
    read -p "Remove and reinstall? [y/N] " -n 1 -r
    echo
    if [[ \\$REPLY =~ ^[Yy]$ ]]; then
        docker rm -f bolt 2>/dev/null || true
    else
        echo "Aborted."
        exit 0
    fi
fi

# Generate secure token
TOKEN=\\$(openssl rand -hex 32)

echo "Pulling Bolt image..."
docker pull ghcr.io/cyberstrikeus/bolt:latest

echo "Starting Bolt container..."
docker run -d \\
  --name bolt \\
  --restart unless-stopped \\
  -p 3001:3001 \\
  -v bolt-data:/data \\
  -e MCP_ADMIN_TOKEN=\\$TOKEN \\
  --cap-add NET_RAW \\
  --cap-add NET_ADMIN \\
  ghcr.io/cyberstrikeus/bolt:latest

# Wait for container to be ready
echo "Waiting for Bolt to start..."
sleep 3

# Check health
if curl -s http://localhost:3001/health > /dev/null 2>&1; then
    echo ""
    echo "Bolt installed successfully!"
    echo ""
    echo "Admin Token (save this!):"
    echo ""
    echo "   \\$TOKEN"
    echo ""
    echo ""
    echo "Add to Cyberstrike:"
    echo ""
    echo "   1. Run: cyberstrike"
    echo "   2. Type: /bolt"
    echo "   3. Press 'a' to add server"
    echo "   4. URL: http://localhost:3001"
    echo "   5. Paste your token"
    echo ""
    echo "Docs: https://docs.cyberstrike.io/docs/mcp/bolt"
    echo ""
else
    echo ""
    echo "Container started but health check failed."
    echo "Check logs with: docker logs bolt"
fi
`;

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bolt - Kali Linux Tools via MCP | Cyberstrike</title>
  <meta name="description" content="Access 100+ Kali Linux security tools through Cyberstrike's MCP interface. Docker-based, secure, and AI-powered.">

  <!-- Favicons from cyberstrike.io -->
  <link rel="icon" type="image/svg+xml" href="https://cyberstrike.io/favicons/favicon.svg">
  <link rel="apple-touch-icon" sizes="180x180" href="https://cyberstrike.io/favicons/apple-touch-icon.png">
  <meta name="theme-color" content="#000000">

  <!-- Space Grotesk font -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">

  <style>
    :root {
      /* Neutral (base) colors - same as landing */
      --base-50: #fafafa;
      --base-100: #f5f5f5;
      --base-200: #e5e5e5;
      --base-300: #d4d4d4;
      --base-400: #a3a3a3;
      --base-500: #737373;
      --base-600: #525252;
      --base-700: #404040;
      --base-800: #262626;
      --base-900: #171717;
      --base-950: #0a0a0a;

      /* Blue (primary) colors */
      --primary-300: #93c5fd;
      --primary-400: #60a5fa;
      --primary-500: #3b82f6;
      --primary-600: #2563eb;
      --primary-700: #1d4ed8;

      /* Dark background - same as landing */
      --dark-bg: hsl(0, 0%, 1%);
    }

    * { margin: 0; padding: 0; box-sizing: border-box; border-color: var(--base-800); }

    html {
      scroll-behavior: smooth;
      color-scheme: dark;
    }

    body {
      font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--dark-bg);
      color: var(--base-200);
      min-height: 100vh;
      line-height: 1.6;
    }

    /* Neon arc background - same as landing HeroCentered */
    .neon-arc {
      position: absolute;
      top: 80px;
      left: -40px;
      right: -40px;
      height: 400px;
      pointer-events: none;
      overflow: hidden;
      opacity: 0.7;
    }

    .neon-arc svg {
      width: 100%;
      height: 100%;
      color: var(--primary-500);
    }

    /* Container - same as landing site-container */
    .site-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1rem;
    }

    /* Navigation - same as landing Nav */
    .nav-container {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 30;
      transition: all 0.3s;
      border-bottom: 1px solid transparent;
    }

    .nav-container.scrolled {
      background: rgba(3, 3, 3, 0.7);
      backdrop-filter: blur(8px);
      border-bottom-color: rgba(255, 255, 255, 0.1);
    }

    .nav-inner {
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Logo - same as landing SiteLogo */
    .logo {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      text-decoration: none;
      color: var(--base-200);
      font-weight: 500;
      font-size: 1.25rem;
    }

    .logo img {
      height: 3.5rem;
      width: 3.5rem;
      filter: brightness(0) invert(1);
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .nav-links a {
      color: var(--base-400);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      transition: color 0.2s;
      padding: 0 1rem;
    }

    .nav-links a:hover {
      color: var(--base-200);
    }

    /* Primary button - same as landing button--primary */
    .button--primary {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.375rem 1rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      text-decoration: none;
      transition: box-shadow 0.3s, color 0.3s, background-color 0.3s, border-color 0.3s;
      position: relative;
      border: 1px solid var(--primary-600);
      background: linear-gradient(to top, var(--primary-700), var(--primary-700));
      color: white;
    }

    .button--primary::before {
      content: '';
      position: absolute;
      inset: -2px;
      z-index: -1;
      border-radius: 9999px;
      background: var(--primary-500);
      opacity: 0;
      filter: blur(4px);
      transition: opacity 0.3s;
    }

    .button--primary:hover {
      border-color: var(--primary-300);
    }

    .button--primary:hover::before {
      opacity: 1;
    }

    @media (max-width: 768px) {
      .nav-links { display: none; }
      .nav-btn { display: none !important; }
    }

    /* Hero - same as landing HeroCentered */
    .hero {
      position: relative;
      padding: 7rem 0 3rem;
      text-align: center;
      overflow: hidden;
    }

    .hero-content {
      position: relative;
      z-index: 1;
      max-width: 750px;
      margin: 0 auto;
      padding: 0 1rem;
    }

    /* Notification badge - same as landing */
    .notification {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.25rem 1rem;
      margin-bottom: 1rem;
      border-radius: 9999px;
      border: 1px solid var(--base-800);
      background: var(--base-950);
      color: var(--base-300);
      font-size: 0.875rem;
      text-decoration: none;
      transition: all 0.3s;
    }

    .notification:hover {
      border-color: var(--primary-300);
    }

    .notification svg {
      width: 1rem;
      height: 1rem;
      color: var(--primary-500);
    }

    /* h1 - same as landing .h1 class */
    .h1 {
      font-size: 3rem;
      font-weight: 500;
      line-height: 1.1;
      letter-spacing: -0.02em;
      margin-bottom: 1.5rem;
      background: linear-gradient(to bottom right, var(--base-200), rgba(229, 229, 229, 0.6));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    @media (min-width: 768px) {
      .h1 { font-size: 3.75rem; }
    }

    .hero-description {
      font-size: 1.125rem;
      color: var(--base-100);
      max-width: 48rem;
      margin: 0 auto 2.5rem;
    }

    /* Buttons group */
    .btn-group {
      display: flex;
      gap: 1rem;
      justify-content: center;
      flex-wrap: wrap;
    }

    .button {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.625rem 1.25rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      text-decoration: none;
      transition: box-shadow 0.3s, color 0.3s, background-color 0.3s, border-color 0.3s;
      cursor: pointer;
      font-family: inherit;
    }

    .button--outline {
      border: 1px solid var(--base-600);
      background: transparent;
      color: var(--base-100);
    }

    .button--outline:hover {
      border-color: var(--base-100);
      background: var(--base-100);
      color: var(--base-900);
    }

    /* GitHub badge - same as landing */
    .github-badge {
      display: inline-flex;
      align-items: center;
      gap: 1rem;
      margin-top: 2rem;
      padding: 0.5rem 1.25rem;
      border-radius: 9999px;
      border: 1px solid var(--base-700);
      background: rgba(10, 10, 10, 0.5);
      text-decoration: none;
      transition: all 0.3s;
    }

    .github-badge:hover {
      border-color: var(--primary-300);
    }

    .github-badge-left {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--base-200);
      font-weight: 500;
      font-size: 0.875rem;
    }

    .github-badge-left svg {
      width: 1.25rem;
      height: 1.25rem;
      color: var(--base-300);
    }

    .github-badge-right {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      color: var(--base-400);
      font-size: 0.875rem;
    }

    .github-badge-right svg {
      width: 1rem;
      height: 1rem;
      color: #facc15;
    }

    /* Install Section */
    .install-section {
      padding: 3rem 0;
    }

    .install-box {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.75rem;
      padding: 1.5rem;
      max-width: 700px;
      margin: 0 auto;
    }

    .install-label {
      font-size: 0.875rem;
      color: var(--base-400);
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .install-code {
      background: var(--dark-bg);
      border: 1px solid var(--base-800);
      border-radius: 0.5rem;
      padding: 0.875rem 1rem;
      font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
      font-size: 0.875rem;
      color: var(--primary-400);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .install-code code {
      overflow-x: auto;
    }

    .copy-btn {
      background: transparent;
      border: 1px solid var(--base-700);
      color: var(--base-400);
      padding: 0.375rem 0.75rem;
      border-radius: 0.375rem;
      cursor: pointer;
      font-size: 0.75rem;
      font-family: inherit;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .copy-btn:hover {
      background: var(--base-800);
      color: var(--base-200);
    }

    /* Features - same as landing FeatureCardsSmall style */
    .features {
      padding: 4rem 0;
    }

    .h2 {
      text-align: center;
      font-size: 2rem;
      font-weight: 500;
      letter-spacing: -0.02em;
      margin-bottom: 2.5rem;
      background: linear-gradient(to bottom right, var(--base-200), rgba(229, 229, 229, 0.6));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    @media (min-width: 768px) {
      .h2 { font-size: 2.5rem; }
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(1, 1fr);
      gap: 1rem;
    }

    @media (min-width: 640px) {
      .features-grid { grid-template-columns: repeat(2, 1fr); }
    }

    @media (min-width: 1024px) {
      .features-grid { grid-template-columns: repeat(4, 1fr); }
    }

    .feature-card {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.75rem;
      padding: 1.25rem;
      transition: border-color 0.2s;
    }

    .feature-card:hover {
      border-color: var(--primary-300);
    }

    .feature-icon {
      width: 2.5rem;
      height: 2.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 0.75rem;
      border-radius: 0.5rem;
      background: var(--base-900);
      color: var(--primary-400);
    }

    .feature-icon svg {
      width: 1.25rem;
      height: 1.25rem;
    }

    .feature-title {
      font-size: 1rem;
      font-weight: 500;
      color: var(--base-100);
      margin-bottom: 0.375rem;
      letter-spacing: -0.01em;
    }

    .feature-desc {
      color: var(--base-400);
      font-size: 0.875rem;
      line-height: 1.5;
    }

    /* Tools */
    .tools {
      padding: 4rem 0;
    }

    .tools-subtitle {
      text-align: center;
      color: var(--base-400);
      margin-top: -1.5rem;
      margin-bottom: 2.5rem;
      font-size: 1rem;
    }

    .tools-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      justify-content: center;
      max-width: 900px;
      margin: 0 auto;
    }

    .tool-tag {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.5rem;
      padding: 0.5rem 1rem;
      font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      color: var(--base-300);
      transition: all 0.2s;
    }

    .tool-tag:hover {
      border-color: var(--primary-400);
      color: var(--primary-300);
    }

    /* Footer */
    footer {
      padding: 3rem 0;
      text-align: center;
      border-top: 1px solid var(--base-800);
    }

    .footer-links {
      display: flex;
      gap: 2rem;
      justify-content: center;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }

    .footer-links a {
      color: var(--base-400);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      transition: color 0.2s;
    }

    .footer-links a:hover {
      color: var(--base-200);
    }

    .footer-text {
      color: var(--base-500);
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="nav-container" id="nav">
    <div class="site-container">
      <div class="nav-inner">
        <a href="https://cyberstrike.io" class="logo">
          <img src="https://cyberstrike.io/logo.svg" alt="Cyberstrike">
          <span>Cyberstrike</span>
        </a>
        <div class="nav-links">
          <a href="https://docs.cyberstrike.io/docs/mcp/bolt">Docs</a>
          <a href="https://github.com/CyberStrikeus/cyberstrike.io">GitHub</a>
          <a href="https://discord.gg/NpjPCbQVHe">Discord</a>
        </div>
        <a href="https://github.com/CyberStrikeus/cyberstrike.io" class="button--primary nav-btn" target="_blank">
          Get Started
        </a>
      </div>
    </div>
  </div>

  <main>
    <section class="hero">
      <div class="neon-arc">
        <svg viewBox="0 0 1800 400" preserveAspectRatio="xMidYMax slice">
          <defs>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" result="blur"/>
              <feMerge>
                <feMergeNode in="blur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          <path d="M 0 400 Q 900 -100 1800 400" stroke="currentColor" stroke-width="2" fill="none" filter="url(#glow)" opacity="0.6"/>
          <path d="M 0 400 Q 900 -100 1800 400" stroke="white" stroke-width="0.5" fill="none" opacity="0.3"/>
        </svg>
      </div>

      <div class="hero-content">
        <a href="https://docs.cyberstrike.io/changelog" class="notification" target="_blank">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 3l1.912 5.813a2 2 0 0 0 1.275 1.275L21 12l-5.813 1.912a2 2 0 0 0-1.275 1.275L12 21l-1.912-5.813a2 2 0 0 0-1.275-1.275L3 12l5.813-1.912a2 2 0 0 0 1.275-1.275z"/>
          </svg>
          <span>100+ Kali Linux tools available</span>
        </a>

        <h1 class="h1">Bolt<br>Kali Linux Tools via MCP</h1>

        <p class="hero-description">
          Access professional security tools through a Docker container.
          Connect to Cyberstrike and let AI orchestrate your penetration tests.
        </p>

        <div class="btn-group">
          <a href="https://docs.cyberstrike.io/docs/mcp/bolt" class="button button--primary" target="_blank">
            Read the Docs
          </a>
          <a href="https://github.com/CyberStrikeus/cyberstrike.io/tree/main/packages/mcp-kali" class="button button--outline" target="_blank">
            View Source
          </a>
        </div>

        <a href="https://github.com/CyberStrikeus/cyberstrike.io" class="github-badge" target="_blank">
          <div class="github-badge-left">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/>
              <path d="M9 18c-4.51 2-5-2-7-2"/>
            </svg>
            <span>CyberStrikeus/cyberstrike.io</span>
          </div>
          <div class="github-badge-right">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
            </svg>
            <span id="stars">-</span>
          </div>
        </a>
      </div>
    </section>

    <section class="install-section">
      <div class="site-container">
        <div class="install-box">
          <div class="install-label">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
              <line x1="12" y1="22.08" x2="12" y2="12"/>
            </svg>
            Quick Install
          </div>
          <div class="install-code">
            <code>curl -sSL https://bolt.cyberstrike.io/install.sh | bash</code>
            <button class="copy-btn" onclick="copyInstall()">Copy</button>
          </div>
        </div>
      </div>
    </section>

    <section class="features">
      <div class="site-container">
        <h2 class="h2">Why Bolt?</h2>
        <div class="features-grid">
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              </svg>
            </div>
            <div class="feature-title">Docker-based</div>
            <div class="feature-desc">
              All tools pre-installed in an isolated container. No manual setup required.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div class="feature-title">Secure by Design</div>
            <div class="feature-desc">
              Token authentication for secure remote deployments.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2a4 4 0 0 0-4 4v2H6a2 2 0 0 0-2 2v10c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4Z"/>
                <circle cx="12" cy="14" r="2"/>
                <path d="M12 16v2"/>
              </svg>
            </div>
            <div class="feature-title">AI-Powered</div>
            <div class="feature-desc">
              Let Claude orchestrate complex security assessments.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="2" y1="12" x2="22" y2="12"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
              </svg>
            </div>
            <div class="feature-title">Cross-Platform</div>
            <div class="feature-desc">
              Works on macOS, Windows, and Linux. Anywhere Docker runs.
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="tools">
      <div class="site-container">
        <h2 class="h2">100+ Tools Included</h2>
        <p class="tools-subtitle">Reconnaissance, web testing, Active Directory, password attacks, and more.</p>
        <div class="tools-grid">
          <div class="tool-tag">nmap</div>
          <div class="tool-tag">sqlmap</div>
          <div class="tool-tag">nuclei</div>
          <div class="tool-tag">ffuf</div>
          <div class="tool-tag">gobuster</div>
          <div class="tool-tag">nikto</div>
          <div class="tool-tag">netexec</div>
          <div class="tool-tag">bloodhound</div>
          <div class="tool-tag">hydra</div>
          <div class="tool-tag">john</div>
          <div class="tool-tag">hashcat</div>
          <div class="tool-tag">responder</div>
          <div class="tool-tag">subfinder</div>
          <div class="tool-tag">amass</div>
          <div class="tool-tag">wpscan</div>
          <div class="tool-tag">metasploit</div>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="site-container">
      <div class="footer-links">
        <a href="https://cyberstrike.io">Cyberstrike</a>
        <a href="https://docs.cyberstrike.io">Documentation</a>
        <a href="https://github.com/CyberStrikeus/cyberstrike.io">GitHub</a>
        <a href="https://discord.gg/NpjPCbQVHe">Discord</a>
      </div>
      <p class="footer-text">Built by the Cyberstrike team. Open source under MIT license.</p>
    </div>
  </footer>

  <script>
    // Navbar scroll effect
    const nav = document.getElementById('nav');
    window.addEventListener('scroll', () => {
      if (window.scrollY > 50) {
        nav.classList.add('scrolled');
      } else {
        nav.classList.remove('scrolled');
      }
    }, { passive: true });

    // Copy install command
    function copyInstall() {
      navigator.clipboard.writeText('curl -sSL https://bolt.cyberstrike.io/install.sh | bash');
      const btn = document.querySelector('.copy-btn');
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 2000);
    }

    // Fetch GitHub stars
    async function fetchStars() {
      try {
        const res = await fetch('https://api.github.com/repos/CyberStrikeus/cyberstrike.io');
        const data = await res.json();
        if (data.stargazers_count !== undefined) {
          document.getElementById('stars').textContent = data.stargazers_count.toLocaleString();
        }
      } catch (e) {
        console.error('Failed to fetch stars:', e);
      }
    }
    fetchStars();
  </script>
</body>
</html>
`;

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Serve install script
    if (url.pathname === '/install.sh' || url.pathname === '/install') {
      return new Response(INSTALL_SCRIPT, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'public, max-age=300',
        }
      });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Landing page
    return new Response(LANDING_HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      }
    });
  }
}
