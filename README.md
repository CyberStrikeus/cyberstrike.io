[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/CyberStrikeus/cyberstrike.io)](https://github.com/CyberStrikeus/cyberstrike.io/stargazers)
[![Release](https://img.shields.io/github/v/release/CyberStrikeus/cyberstrike.io)](https://github.com/CyberStrikeus/cyberstrike.io/releases)

# Cyberstrike

AI-powered autonomous penetration testing agent.

Cyberstrike combines multiple AI models (Claude, GPT, Gemini) with specialized security tools to perform assessments, identify vulnerabilities, and generate detailed reports.

## Features

- **Multi-Model AI** - Access Claude, GPT-4, Gemini, Ollama, and more
- **Automated Scanning** - Comprehensive vulnerability scanning for web apps, APIs, and infrastructure
- **BYOK Model** - Bring your own API keys, full control over costs and data privacy
- **CLI & TUI** - Powerful terminal interface for scripting and interactive sessions
- **Detailed Reports** - Generate professional pentest reports in PDF, Markdown, or HTML

## Installation

```bash
# Using npm
npm install -g cyberstrike

# Using bun
bun install -g cyberstrike
```

## Quick Start

```bash
# Configure your API key
export ANTHROPIC_API_KEY=your_key_here

# Start Cyberstrike
cyberstrike

# Or run with a specific agent
cyberstrike --agent web-application
```

## Available Agents

- `web-application` - OWASP Web Security Testing Guide
- `internal-network` - Internal network penetration testing
- `cloud-security` - AWS/Azure/GCP security assessment
- `bug-hunter` - Bug bounty hunting automation

## Documentation

Visit [docs.cyberstrike.io](https://docs.cyberstrike.io) for full documentation.

## License

Cyberstrike is open source under the [AGPL-3.0 license](LICENSE).

For commercial use without AGPL obligations, contact: license@cyberstrike.io

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Community

- [GitHub Discussions](https://github.com/CyberStrikeus/cyberstrike.io/discussions)
- [Discord](https://discord.gg/cyberstrike)
- [Twitter](https://twitter.com/cyberstrike_io)
