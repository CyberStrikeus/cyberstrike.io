# Cyberstrike

AI-powered penetration testing agent framework.

```
█▀▀ █░░█ █▀▀▄ █▀▀ █▀▀▄ █▀▀ ▀▀█▀▀ █▀▀▄ ▀█▀ █░█ █▀▀
█░░ █▄▄█ █▀▀▄ █▀▀ █▄▄▀ ▀▀█ ░░█░░ █▄▄▀ ░█░ █▀▄ █▀▀
▀▀▀ ░░░█ ▀▀▀░ ▀▀▀ ▀░▀▀ ▀▀▀ ░░▀░░ ▀░▀▀ ▀▀▀ ▀░▀ ▀▀▀
```

---

## Quick Start

```bash
# Install dependencies
cd packages/cyberstrike
bun install

# Run cyberstrike
bun run dev

# Or with a specific agent
bun run dev --agent web-application
bun run dev --agent cloud-security
bun run dev --agent internal-network
bun run dev --agent bug-hunter
```

## Pentest Agents

### web-application
Web application security specialist following OWASP/WSTG methodology:
- OWASP Top 10 (A01-A10)
- WSTG 120+ test cases
- SQL Injection, XSS, CSRF, XXE, SSTI
- API Security testing (REST, GraphQL)
- Authentication/Authorization bypass
- Business logic vulnerabilities

### cloud-security
Cloud infrastructure security testing:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS Benchmark compliance
- Privilege escalation in cloud

### internal-network
Internal network and Active Directory specialist:
- Network enumeration and service discovery
- AD attacks (Kerberoasting, AS-REP Roasting)
- Credential attacks (Password Spraying, PtH)
- Lateral movement (DCOM, WMI, PSExec)
- Privilege escalation (Windows, Linux, Domain)

### bug-hunter
Bug bounty hunting methodology:
- Asset discovery and subdomain enumeration
- Historical data analysis (Wayback, GAU)
- JavaScript analysis (endpoints, secrets)
- Vulnerability chaining for impact
- Platform strategies (HackerOne, Bugcrowd)

## Knowledge Base

WSTG checklists are in `knowledge/web-application/`:

| Category | Tests | Description |
|----------|-------|-------------|
| WSTG-INFO | 10 | Information Gathering |
| WSTG-CONF | 13 | Configuration Testing |
| WSTG-IDNT | 5 | Identity Management |
| WSTG-ATHN | 11 | Authentication Testing |
| WSTG-AUTHZ | 7 | Authorization Testing |
| WSTG-SESS | 11 | Session Management |
| WSTG-INPV | 29 | Input Validation |
| WSTG-ERRH | 2 | Error Handling |
| WSTG-CRYP | 4 | Cryptography |
| WSTG-BUSL | 10 | Business Logic |
| WSTG-CLNT | 14 | Client-side Testing |
| WSTG-APIT | 4 | API Testing |

**Total: 120+ test cases**

## Usage Examples

```bash
# Start web application pentest
bun run dev --agent web-application
> "Test https://target.com for SQL injection following WSTG-INPV-05"

# Run a reconnaissance scan
bun run dev --agent bug-hunter
> "Enumerate subdomains for target.com"

# Cloud security audit
bun run dev --agent cloud-security
> "Audit my AWS account for S3 bucket misconfigurations"

# Internal network pentest
bun run dev --agent internal-network
> "Perform Kerberoasting attack on the domain"
```

## Architecture

Based on OpenCode CLI:
- **Bun** runtime for fast execution
- **TypeScript** for type safety
- **Solid.js + OpenTUI** for terminal UI
- **Vercel AI SDK** for multi-provider LLM support
- **MCP integration** for tool extensions

## Tools Integration

The agents can use various security tools via Bash:
- **Network**: nmap, masscan, netcat
- **Web**: nuclei, sqlmap, ffuf, nikto
- **Cloud**: prowler, scoutsuite, pacu
- **AD**: bloodhound, netexec, kerbrute
- **Recon**: subfinder, amass, httpx, gau

## Project Structure

```
cyberstrike.io/
├── packages/cyberstrike/          # Main CLI package
│   ├── src/
│   │   ├── agent/              # Agent definitions
│   │   │   └── prompt/         # Agent prompts (pentest agents)
│   │   ├── session/prompt/     # System prompts
│   │   └── tool/               # Tool implementations
│   └── bin/cyberstrike             # CLI entry point
├── knowledge/                  # Security knowledge base
│   ├── web-application/        # WSTG checklists
│   │   ├── WSTG-INFO/
│   │   ├── WSTG-INPV/
│   │   └── ...
│   └── rehber/                 # Master checklist
└── README.md
```

## License

MIT

---

Based on [OpenCode](https://github.com/anomalyco/opencode) - The open source AI coding agent.
