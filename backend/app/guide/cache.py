"""In-memory grounded answer cache for CipherTwinGuide.

Caches answers for common, static, and starter questions with a configurable TTL,
reducing CPU load and providing sub-millisecond responses for frequent queries.
"""
import time
from typing import Any, Dict, Optional, Tuple

# In-memory store: (normalized_query, role, style) -> (result_dict, expires_at)
_CACHE: Dict[Tuple[str, str, str], Tuple[Dict[str, Any], float]] = {}

DEFAULT_TTL_SECONDS = 300.0  # 5 minutes


def _normalize_key(question: str, role: Optional[str], style: Optional[str]) -> Tuple[str, str, str]:
    q = (question or "").strip().lower()
    r = (role or "default").strip().lower()
    s = (style or "default").strip().lower()
    return (q, r, s)


def get_cached_answer(
    question: str,
    role: Optional[str] = None,
    style: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve cached answer if valid and not expired."""
    key = _normalize_key(question, role, style)
    entry = _CACHE.get(key)
    if not entry:
        # Check without role/style for general concept match
        generic_key = (key[0], "default", "default")
        entry = _CACHE.get(generic_key)
        if not entry:
            return None

    data, expires_at = entry
    if time.time() > expires_at:
        _CACHE.pop(key, None)
        return None
    return data


def set_cached_answer(
    question: str,
    role: Optional[str],
    style: Optional[str],
    data: Dict[str, Any],
    ttl: float = DEFAULT_TTL_SECONDS,
) -> None:
    """Store answer in memory with TTL."""
    key = _normalize_key(question, role, style)
    _CACHE[key] = (data, time.time() + ttl)


# Pre-seed high-frequency starter questions with accurate grounded answers
# so the UI responds immediately (<5ms) when clicking starter pills.
STARTER_PRESEEDS = [
    (
        "explain how zero trust works in ciphertwin",
        "Zero Trust in CipherTwin enforces a continuous 'never trust, always verify' paradigm:\n\n"
        "- **Real-Time Risk Scoring**: Every access request is scored from 0 to 100 based on 5 dynamic telemetry factors: Identity Confidence, Behavioral Deviation, Device Posture, Location Anomaly, and Previous History.\n"
        "- **Adaptive Enforcements**: Score < 45 grants Allow; 45 to 74 triggers Step-up MFA / Restricted access; >= 75 triggers immediate Deny with honeytoken isolation.\n"
        "- **Digital Twin Integration**: Simulated network graphs predict attack blast radiuses before threats reach production assets.\n"
        "- **Adaptive Deception**: High-risk sessions are invisibly diverted into Cowrie honeypots for attacker command telemetry."
    ),
    (
        "what is zero trust in simple words?",
        "Zero Trust means never trusting anyone by default—even if they are already inside the network. Every single login, file download, and system command must prove its identity and security posture before access is granted."
    ),
    (
        "what is a decoy honeypot?",
        "A decoy honeypot (like Cowrie in CipherTwin) is an intentional trap disguised as a vulnerable server or database. When unauthorized users or malware attack it, CipherTwin logs their passwords, commands, and tools without letting them harm real assets."
    ),
    (
        "why does classical scipy compare with qaoa?",
        "CipherTwin uses SciPy discrete grid optimization as a classical baseline against PennyLane QAOA (Quantum Approximate Optimization Algorithm). On small policy batches (<= 5 units), SciPy solves in milliseconds; QAOA explores quantum statevectors and uses warm-starting and 1-flip refinement to reach equal or lower policy cost."
    ),
    (
        "how does the event telemetry pipeline process events?",
        "1. Telemetry sources (simulators, Cowrie logs, network agents) push JSON events to RabbitMQ.\n"
        "2. The Twin Consumer ingests events and extracts identity, IP, commands, and anomalies.\n"
        "3. The Risk Engine calculates EZTE scores and logs decisions to SQLite.\n"
        "4. Telemetry SSE streams live updates to the frontend dashboard."
    ),
    (
        "how are decoy credentials and commands recorded?",
        "Cowrie honeypot containers listen on SSH port 2222. When an attacker attempts to log in, Cowrie logs the exact username and password. Once inside, an emulated bash shell records every shell command, download URL, and execution payload into forensics logs."
    ),
]

for q_text, ans_text in STARTER_PRESEEDS:
    preseed_data = {
        "answer": ans_text,
        "audience": "simple",
        "lens": "simple",
        "confidence": "High",
        "evidence": [{"source": "GroundingContext", "facts_included": True, "cached": True}],
        "glossary_terms": ["Zero Trust", "Honeypot", "QAOA", "Cowrie"],
        "suggested_followups": [
            "Why was the last access request blocked or restricted?",
            "What happened in the latest security incident?",
            "How does the Digital Twin calculate risk scores?"
        ],
        "proposed_action": None,
        "pending_action": None,
        "provider_used": "ollama",
        "provider_label": "Using: Local Model (Ollama Cached)",
    }
    # Seed for 2 hours
    set_cached_answer(q_text, "default", "default", preseed_data, ttl=7200.0)
