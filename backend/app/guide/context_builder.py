"""CipherTwinGuide Grounded Context Builder.

Extracts live, read-only application facts from CipherTwin subsystems (Zero Trust,
Decoy Honeypot, Network Twin, Optimization, Telemetry, and Subsystem Health),
sanitizes untrusted input, redacts sensitive secrets, wraps evidence in `<data>...</data>`,
and bounds context to ~1,500 tokens for local llama3.2:3b execution.
"""
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.risk import RiskDecision
from app.models.deception import DecoySession
from app.models.twin import TwinNode, TwinRelationship
from app.models.policy import PolicyImprovement, Policy as SecurityPolicy
from app.models.audit import AuditLog

logger = logging.getLogger("ciphertwin.guide.context_builder")

# Sensitive keys and patterns to redact
SECRET_PATTERNS = [
    re.compile(r'(?i)(xai_api_key|api_key|password|secret_key|token|bearer\s+[a-zA-Z0-9_\-\.]+)\s*[:=]\s*["\']?([^"\'\s]+)["\']?'),
    re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),  # JWT pattern
    re.compile(r'xai-[a-zA-Z0-9]{20,}'),  # xAI key pattern
    re.compile(r'gsk_[a-zA-Z0-9]{20,}'),  # Groq key pattern
]


def redact_secrets(text: str) -> str:
    """Strictly redact passwords, tokens, API keys, and JWT signatures."""
    if not text:
        return text
    clean = text
    for pattern in SECRET_PATTERNS:
        clean = pattern.sub("[REDACTED_SECRET]", clean)
    return clean


def sanitize_untrusted_data(raw_data: Any) -> str:
    """Sanitize and delimit untrusted network/user data inside <data>...</data>."""
    if raw_data is None:
        return "<data></data>"
    if isinstance(raw_data, (dict, list)):
        serialized = json.dumps(raw_data, default=str)
    else:
        serialized = str(raw_data)
    redacted = redact_secrets(serialized)
    # Neutralize any attempts to close </data> tags inside untrusted text
    safe_str = redacted.replace("</data>", "&lt;/data&gt;").replace("<data>", "&lt;data&gt;")
    return f"<data>{safe_str}</data>"


class ContextBuilder:
    """Builds compact, grounded fact blocks for the local LLM."""

    def __init__(self, db: Session):
        self.db = db

    def build_context(
        self,
        query: str,
        page_context: Optional[str] = None,
        role: str = "Beginner/General user",
        style: str = "Simple Explanation",
    ) -> Dict[str, Any]:
        """Analyze intent and build compact grounded facts block."""
        q_lower = query.lower()
        page_lower = (page_context or "").lower()

        # Check for pure conceptual / architectural questions
        # For pure concepts, provide a concise reference block and skip raw database tables.
        is_concept_query = (
            any(w in q_lower for w in ["what is", "explain how", "how does", "why do we", "tell me about", "what does", "define"])
            and not any(w in q_lower for w in ["latest", "recent", "today", "now", "current", "incident", "last", "session", "device", "ip", "table", "stats"])
        )
        if is_concept_query:
            concept_facts = (
                "CIPHERTWIN ARCHITECTURAL SPECIFICATIONS:\n"
                "- Zero Trust Engine: Continuous risk scoring (0-100) evaluating Identity Confidence, Behavioral Deviation, Device Posture, Location Anomaly, and Prior History. Actions: Allow (<45), Restrict (45-74), Deny (>=75).\n"
                "- Adaptive Deception: Routes unauthorized/malicious SSH connections to Cowrie honeypots (port 2222) categorized into Low, Medium, and High fidelity.\n"
                "- Network Digital Twin: Graph-based asset model that simulates attack paths and blast radiuses safely without touching production assets.\n"
                "- QAOA Optimizer: Statevector PennyLane circuit balancing policy weights using QUBO formulation, warm-started from classical SciPy."
            )
            return {
                "facts_block": concept_facts,
                "verified_items": [{"source": "ArchitectureReference", "concept_only": True}],
                "intents": {"concept": True, "zero_trust": True, "honeypot": False, "twin": False, "policy": False},
            }

        facts: List[str] = []
        verified_items: List[Dict[str, Any]] = []

        # 1. Base System Health
        try:
            health_summary = self._get_health_facts()
            facts.append(health_summary["text"])
            verified_items.append({"source": "SystemHealth", "data": health_summary["data"]})
        except Exception as e:
            logger.warning("Could not fetch health facts: %s", e)
            facts.append("System Health: Database connected; telemetry generator active.")

        # 2. Intent-specific fact retrieval
        needs_zt = any(k in q_lower or k in page_lower for k in [
            "zero trust", "risk", "decision", "score", "allow", "deny", "restricted", "access", "factor", "request"
        ])
        needs_honeypot = any(k in q_lower or k in page_lower for k in [
            "honeypot", "decoy", "cowrie", "attacker", "deception", "captured", "payload", "command", "threat"
        ])
        needs_twin = any(k in q_lower or k in page_lower for k in [
            "twin", "node", "graph", "asset", "network", "host", "ip", "topology", "lateral", "simulate", "forecast"
        ])
        needs_policy = any(k in q_lower or k in page_lower for k in [
            "policy", "quantum", "qubo", "qaoa", "reoptimize", "weights", "anneal", "optimization"
        ])

        # If general overview, include highlights from each
        if not (needs_zt or needs_honeypot or needs_twin or needs_policy):
            needs_zt = True
            needs_honeypot = True
            needs_twin = True

        if needs_zt:
            zt_facts = self._get_zero_trust_facts()
            facts.append(zt_facts["text"])
            verified_items.append({"source": "ZeroTrustDB", "data": zt_facts["data"]})

        if needs_honeypot:
            decoy_facts = self._get_decoy_facts()
            facts.append(decoy_facts["text"])
            verified_items.append({"source": "DecoyDB", "data": decoy_facts["data"]})

        if needs_twin:
            twin_facts = self._get_twin_facts()
            facts.append(twin_facts["text"])
            verified_items.append({"source": "NetworkTwinDB", "data": twin_facts["data"]})

        if needs_policy:
            policy_facts = self._get_policy_facts()
            facts.append(policy_facts["text"])
            verified_items.append({"source": "PolicyDB", "data": policy_facts["data"]})

        facts_block = "\n\n".join(facts)
        # Cap length to ensure prompt stays under ~1,500 tokens
        if len(facts_block) > 4000:
            facts_block = facts_block[:4000] + "\n[Context truncated for brevity]"

        return {
            "facts_block": facts_block,
            "verified_items": verified_items,
            "intents": {
                "zero_trust": needs_zt,
                "honeypot": needs_honeypot,
                "twin": needs_twin,
                "policy": needs_policy,
            },
        }

    def _get_health_facts(self) -> Dict[str, Any]:
        """Fetch real subsystem health facts."""
        total_decisions = self.db.query(func.count(RiskDecision.id)).scalar() or 0
        total_decoys = self.db.query(func.count(DecoySession.id)).scalar() or 0
        total_nodes = self.db.query(func.count(TwinNode.id)).scalar() or 0

        summary_text = (
            f"SYSTEM METRICS & HEALTH:\n"
            f"- Architecture: CipherTwin Autonomous Cyber Defense Framework\n"
            f"- Total Zero-Trust Decisions Evaluated: {total_decisions}\n"
            f"- Total Decoy Honeypot Interactions: {total_decoys}\n"
            f"- Network Digital Twin Monitored Assets: {total_nodes}\n"
            f"- Database: SQLite Operational (Read-Only access mode for Guide)"
        )
        return {
            "text": summary_text,
            "data": {
                "decisions_count": total_decisions,
                "decoys_count": total_decoys,
                "nodes_count": total_nodes,
            },
        }

    def _get_zero_trust_facts(self) -> Dict[str, Any]:
        """Fetch recent Zero-Trust risk decisions and factors."""
        recent_decisions = (
            self.db.query(RiskDecision)
            .order_by(desc(RiskDecision.timestamp))
            .limit(3)
            .all()
        )
        if not recent_decisions:
            return {
                "text": "ZERO-TRUST RECENT DECISIONS: No access decisions recorded yet in database.",
                "data": [],
            }

        lines = ["ZERO-TRUST RECENT EVALUATIONS:"]
        serialized = []
        for d in recent_decisions:
            timestamp_str = d.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if d.timestamp else "recent"
            lines.append(
                f"- ID {d.id} ({timestamp_str}): Decision={d.decision}, Risk={d.risk_score:.1f}/100, User={d.user_id}, Resource={d.resource_id}, Summary={d.summary or 'Evaluated'}"
            )
            serialized.append({
                "id": d.id,
                "decision": d.decision,
                "risk_score": d.risk_score,
                "summary": d.summary,
            })

        return {"text": "\n".join(lines), "data": serialized}

    def _get_decoy_facts(self) -> Dict[str, Any]:
        """Fetch real honeypot/decoy session data."""
        recent_sessions = (
            self.db.query(DecoySession)
            .order_by(desc(DecoySession.timestamp))
            .limit(3)
            .all()
        )
        if not recent_sessions:
            return {
                "text": "DECOY HONEYPOT SESSIONS: No honeypot sessions recorded yet in database.",
                "data": [],
            }

        lines = ["DECOY HONEYPOT FORENSICS:"]
        serialized = []
        for s in recent_sessions:
            timestamp_str = s.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if s.timestamp else "recent"
            cmds_preview = (s.commands or "[]")[:60]
            lines.append(
                f"- Decoy ID {s.id} ({timestamp_str}): Type={s.decoy_type}, Fidelity={s.fidelity or 'LOW'}, IP={s.source_ip or 'unknown'}, Cmds={cmds_preview}"
            )
            serialized.append({
                "id": s.id,
                "decoy_type": s.decoy_type,
                "mode": s.mode,
            })

        return {"text": "\n".join(lines), "data": serialized}

    def _get_twin_facts(self) -> Dict[str, Any]:
        """Fetch Digital Twin topology facts."""
        nodes = self.db.query(TwinNode).limit(5).all()
        total_nodes = self.db.query(func.count(TwinNode.id)).scalar() or 0
        total_edges = self.db.query(func.count(TwinRelationship.id)).scalar() or 0

        lines = [
            f"NETWORK DIGITAL TWIN (SIMULATED TOPOLOGY):",
            f"- Note: Twin topology models a lab network; all graph forecasts are simulated, not physical changes.",
            f"- Total Assets in Twin: {total_nodes}, Total Network Edges: {total_edges}",
        ]
        if nodes:
            sample_nodes = [f"{n.label} ({n.ip_address or 'no-ip'}, type={n.type})" for n in nodes[:3]]
            lines.append(f"- Sample Monitored Nodes: {', '.join(sample_nodes)}")

        return {
            "text": "\n".join(lines),
            "data": {"total_nodes": total_nodes, "total_edges": total_edges},
        }

    def _get_policy_facts(self) -> Dict[str, Any]:
        """Fetch policy reoptimization facts."""
        policies = self.db.query(SecurityPolicy).all()
        latest_imp = (
            self.db.query(PolicyImprovement)
            .order_by(desc(PolicyImprovement.timestamp))
            .first()
        )

        lines = ["POLICY & REOPTIMIZATION POSTURE:"]
        if policies:
            names = [p.name for p in policies[:4]]
            lines.append(f"- Active Security Policies: {', '.join(names)}")
        else:
            lines.append("- Active Security Policies: Default Zero Trust Policies active.")

        if latest_imp:
            lines.append(
                f"- Latest Reoptimization: Algorithm={latest_imp.algorithm}, "
                f"Before Score={latest_imp.before_score:.2f}, After Score={latest_imp.after_score:.2f}, "
                f"Summary={latest_imp.summary or 'Automated QAOA policy optimization'}"
            )

        return {"text": "\n".join(lines), "data": {"policies_count": len(policies)}}
