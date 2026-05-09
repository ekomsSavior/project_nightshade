"""
Nightshade Ngrok Integration.
Manages ngrok tunnel lifecycle for TCP reverse shells and HTTP C2.
"""
import subprocess
import time
import json
import os
import shutil
from typing import Optional
import requests


class NgrokManager:
    """Manage ngrok tunnels for Nightshade operations."""

    NGROK_API = "http://127.0.0.1:4040/api/tunnels"

    def __init__(self, auth_token: str = "", region: str = "us"):
        self._auth_token = auth_token
        self._region = region
        self._process: Optional[subprocess.Popen] = None

    @staticmethod
    def is_installed() -> bool:
        return shutil.which("ngrok") is not None

    def get_tunnels(self) -> list[dict]:
        """Fetch active ngrok tunnels from the local API."""
        try:
            r = requests.get(self.NGROK_API, timeout=3)
            return r.json().get("tunnels", [])
        except Exception:
            return []

    def get_http_url(self) -> Optional[str]:
        for t in self.get_tunnels():
            if t["proto"] in ("https", "http"):
                return t["public_url"]
        return None

    def get_tcp_address(self) -> Optional[str]:
        for t in self.get_tunnels():
            if t["proto"] == "tcp":
                return t["public_url"]
        return None

    def authenticate(self):
        if self._auth_token:
            subprocess.run(
                ["ngrok", "config", "add-authtoken", self._auth_token],
                capture_output=True, timeout=10,
            )

    def start_tcp_tunnel(self, port: int) -> Optional[str]:
        """Start an ngrok TCP tunnel and return the public address."""
        if not self.is_installed():
            print("[-] ngrok not found on PATH")
            return None

        self.authenticate()
        cmd = ["ngrok", "tcp", str(port), "--region", self._region, "--log=stdout"]
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        addr = self.get_tcp_address()
        if addr:
            print(f"[+] ngrok TCP tunnel: {addr}")
            return addr

        # Fallback: prompt user
        print("[!] Could not auto-detect ngrok TCP tunnel.")
        manual = input("[?] Enter ngrok TCP address manually (e.g., 1.tcp.ngrok.io:12345): ").strip()
        return manual if manual else None

    def start_http_tunnel(self, port: int) -> Optional[str]:
        """Start an ngrok HTTP tunnel and return the public URL."""
        if not self.is_installed():
            print("[-] ngrok not found on PATH")
            return None

        self.authenticate()
        cmd = ["ngrok", "http", str(port), "--region", self._region, "--log=stdout"]
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        url = self.get_http_url()
        if url:
            print(f"[+] ngrok HTTP tunnel: {url}")
        else:
            print("[!] Could not auto-detect ngrok HTTP tunnel.")
        return url

    def stop(self):
        if self._process:
            self._process.terminate()
            self._process = None
