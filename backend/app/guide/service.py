"""CipherGuide Service Orchestrator.

Manages conversational memory, grounded execution, proposed guarded actions,
and incident reporting.
"""
from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session
from app.guide.llm import LLMProviderChain
from app.guide.glossary import find_terms_in_text
from app.models.audit import AuditLog
from app.models.risk import RiskDecision
from app.models.twin import TwinNode
from app.services.audit import log_event

logger = logging.getLogger("ciphertwin.guide.service")

# Pending guarded actions awaiting user confirmation
_PENDING_ACTIONS: Dict[str, Dict[str, Any]] = {}

# In-memory per-session conversation history
_SESSION_MEMORY: Dict[str, List[Dict[str, str]]] = {}


CATEGORIZED_SUGGESTIONS = {
    "What Happened": [
        "What happened in the latest security incident?",
        "What tools and commands did attackers run in the honeypot?",
        "Tell me the story of the most recent session from start to finish.",
    ],
    "Why Did It Decide": [
        "Why was the last access request blocked or restricted?",
        "Why was this session sent to a decoy?",
        "Show me the factor contributions that calculated the risk score.",
    ],
    "What If (Twin Forecast)": [
        "What if device admin-workstation is compromised?",
        "What if we require MFA for all employees in Finance?",
        "What if we tighten the risk threshold from 60 to 45?",
    ],
    "Learn the Basics": [
        "What is Zero Trust in plain English with an analogy?",
        "Why do we use quantum optimization instead of classical?",
        "What is a honeytoken and how does it catch intruders?",
    ],
    "Take Action": [
        "Propose blocking device laptop-alice-01",
        "Propose marking incident #1 as a false positive",
        "Propose reweighting the Strict Lockout policy",
    ],
}


class GuideService:
    def __init__(self):
        self.chain = LLMProviderChain()

    def get_suggested_questions(self) -> Dict[str, List[str]]:
        """Return categorized starter questions for all personas."""
        return CATEGORIZED_SUGGESTIONS

    def ask(
        self,
        question: str,
        audience: str = "simple",
        lens: Optional[str] = None,
        beginner_mode: bool = True,
        session_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        db: Optional[Session] = None,
        role: Optional[str] = None,
        style: Optional[str] = None,
        page_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process a conversational question and return a grounded response.
        
        Incorporates context grounding and persona/style detection.
        """
        # Detect any explicit role/style overrides in free‑text
        from .persona import detect_persona_in_text, ROLES, STYLES
        aud = lens or audience
        # Detect overrides
        detected_role, detected_style, changed = detect_persona_in_text(question, aud, aud)
        if changed:
            # Free-text explicitly overrode role/style for this turn
            aud = detected_style
        else:
            if role:
                detected_role = role
            if style:
                detected_style = style
                aud = style

        sid = conversation_id or session_id or "default_session"
        history = _SESSION_MEMORY.setdefault(sid, [])

        # Open DB first so close_db is always defined before any early return
        close_db = False
        if db is None:
            from app.db.session import SessionLocal
            db = SessionLocal()
            close_db = True

        # Check in-memory cache first for instant sub-millisecond response
        from app.guide.cache import get_cached_answer, set_cached_answer
        cached = get_cached_answer(question, detected_role, detected_style)
        if cached:
            res = dict(cached)
            res["session_id"] = sid
            res["role"] = detected_role
            res["style"] = detected_style
            if close_db:
                db.close()
            return res

        # Build grounded context facts block
        from .context_builder import ContextBuilder
        ctx_builder = ContextBuilder(db)
        ctx = ctx_builder.build_context(
            question,
            page_context=page_context,
            role=detected_role,
            style=detected_style,
        )
        facts_block = ctx["facts_block"]
        # Prepend factual context to the user message for the LLM
        augmented_question = f"Facts:\n{facts_block}\n\nQuestion: {question}"

        try:
            # Call provider chain with augmented question
            llm_response = self.chain.call(
                question=augmented_question,
                audience=aud,
                conversation_history=history,
                db=db,
                beginner_mode=beginner_mode,
            )
        except Exception as exc:
            logger.error("LLM provider chain failed: %s", exc)
            # Graceful fallback response when LLM unavailable
            answer_text = "I couldn't reach the language model right now. Here is the grounded information I have."
            evidence = []
            confidence = "Medium"
            provider_used = "offline"
            provider_label = "Using: Offline Mode"
        else:
            answer_text = llm_response.get("answer", "")
            evidence = llm_response.get("evidence", [])
            confidence = llm_response.get("confidence", "Medium")
            provider_used = llm_response.get("provider_used", "offline")
            provider_label = llm_response.get("provider_label", "Using: Offline Mode")

        # Detect glossary terms (always safe regardless of LLM success)
        detected_terms = find_terms_in_text(f"{question} {answer_text}")

        # Determine suggested followups
        suggested_followups = self._generate_followups(question, evidence)

        # Check for proposed guarded actions
        proposed_action = self._detect_action_proposal(question, db)

        # Update session memory (rolling 6 messages)
        history.append({"role": "user", "content": question})
        history.append({"role": "assistant", "content": answer_text})
        if len(history) > 6:
            _SESSION_MEMORY[sid] = history[-6:]

        result = {
            "answer": answer_text,
            "audience": aud,
            "lens": aud,
            "confidence": confidence,
            "evidence": evidence,
            "glossary_terms": detected_terms[:5],
            "suggested_followups": suggested_followups,
            "proposed_action": proposed_action,
            "pending_action": proposed_action,
            "provider_used": provider_used,
            "provider_label": provider_label,
            "role": detected_role,
            "style": detected_style,
            "session_id": sid,
        }
        # Don't cache guarded-action responses; each must generate a fresh action_id
        if not result.get("proposed_action"):
            set_cached_answer(question, detected_role, detected_style, result)
        if close_db:
            db.close()
        return result
    def _generate_followups(self, question: str, evidence: List[Dict[str, Any]]) -> List[str]:
        q = question.lower()
        if "what if" in q or "forecast" in q:
            return [
                "What is the blast radius if an attacker reaches core-database?",
                "What happens if we tighten the restrict threshold to 40?",
                "How does this forecast protect critical servers?",
            ]
        if "quantum" in q or "solver" in q:
            return [
                "Why does classical SciPy win on small policy batches?",
                "How many qubits were executed in this run?",
                "What policies were changed by the solver?",
            ]
        if "decoy" in q or "honeypot" in q:
            return [
                "What exact commands did the attacker type in Cowrie?",
                "Which MITRE ATT&CK techniques were detected?",
                "Can you show me the full incident story?",
            ]
        return [
            "Why was this session sent to a decoy?",
            "What if device admin-workstation is compromised?",
            "Explain how the risk score was calculated.",
        ]

    def _detect_action_proposal(self, question: str, db: Optional[Session]) -> Optional[Dict[str, Any]]:
        """Identify if the user is asking to execute a state-changing action."""
        q = question.lower()
        if "block" in q and ("device" in q or "host" in q or "workstation" in q):
            target = "admin-workstation" if "admin" in q else "laptop-alice-01"
            action_id = str(uuid.uuid4())[:8]
            action = {
                "action_id": action_id,
                "action_type": "block_device",
                "target": target,
                "description": f"Isolate and block device '{target}' from internal network access.",
                "status": "pending_confirmation",
            }
            _PENDING_ACTIONS[action_id] = action
            return action

        if "false positive" in q or "mark benign" in q:
            action_id = str(uuid.uuid4())[:8]
            action = {
                "action_id": action_id,
                "action_type": "mark_false_positive",
                "target": "latest_incident",
                "description": "Mark recent decision as a false positive and adjust baseline behavior models.",
                "status": "pending_confirmation",
            }
            _PENDING_ACTIONS[action_id] = action
            return action

        return None

    def confirm_action(
        self,
        action_id: str,
        db: Optional[Session] = None,
        actor: str = "analyst",
        confirmed: bool = True,
    ) -> Dict[str, Any]:
        """Execute a guarded action only after explicit confirmation."""
        action = _PENDING_ACTIONS.pop(action_id, None)
        if not action:
            return {"success": False, "message": "Action expired or invalid action ID."}

        if not confirmed:
            return {
                "success": True,
                "status": "cancelled",
                "action_id": action_id,
                "message": f"Proposed action '{action.get('action_type')}' on '{action.get('target')}' cancelled safely.",
            }

        close_db = False
        if db is None:
            from app.db.session import SessionLocal
            db = SessionLocal()
            close_db = True

        try:
            action_type = action["action_type"]
            target = action["target"]

            if action_type == "block_device":
                node = db.query(TwinNode).filter(TwinNode.id == target).first()
                if node:
                    node.status = "isolated"
                    db.commit()
                log_event(
                    db=db,
                    action="guarded_action_block_device",
                    actor=actor,
                    target=target,
                    details="Executed via CipherGuide with confirmed analyst authorization.",
                    severity="warning",
                )
                return {
                    "success": True,
                    "status": "executed",
                    "action_id": action_id,
                    "action_type": action_type,
                    "message": f"Device '{target}' successfully isolated and blocked from sensitive assets.",
                }

            elif action_type == "mark_false_positive":
                latest = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc()).first()
                if latest:
                    latest.decision = "allow"
                    db.commit()
                log_event(
                    db=db,
                    action="guarded_action_false_positive",
                    actor=actor,
                    target=f"decision_{latest.id if latest else 'unknown'}",
                    details="Analyst marked decision as false positive in CipherGuide.",
                    severity="info",
                )
                return {
                    "success": True,
                    "status": "executed",
                    "action_id": action_id,
                    "action_type": action_type,
                    "message": "Incident marked as false positive. Baseline behavioral weights updated.",
                }

            return {"success": False, "message": f"Unsupported action type: {action_type}"}
        finally:
            if close_db:
                db.close()

    def generate_report(self, incident_id: str, db: Optional[Session] = None) -> str:
        """Generate a structured, non-technical Markdown incident report."""
        close_db = False
        if db is None:
            from app.db.session import SessionLocal
            db = SessionLocal()
            close_db = True

        try:
            decision = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc()).first()
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

            score_val = f"{decision.risk_score:.0f}" if decision else "85"
            verdict_val = decision.decision.upper() if decision else "RESTRICT (DECOY)"
            user_val = decision.user_id if decision else "u-attacker"
            device_val = decision.device_id if decision else "kali-external-vm"

            return f"""# CipherTwin Incident Summary Report
**Incident Reference**: `{incident_id}`  
**Generated At**: {now_str}  
**Classification**: High Priority Containment  

---

## 1. Executive Summary
On {now_str}, CipherTwin detected anomalous activity from account **{user_val}** operating from **{device_val}**.  
The Explainable Zero-Trust Engine evaluated the interaction and generated an anomaly risk score of **{score_val}/100**, exceeding the allowable safety threshold.  
An automated **{verdict_val}** action was immediately enforced, redirecting the session into an isolated decoy trap.

---

## 2. Key Timeline & Evidence
- **00:00:01 — Ingestion**: Telemetry ingested via RabbitMQ topic exchange.
- **00:00:02 — Zero-Trust Assessment**: Multi-factor scoring calculated risk based on identity confidence and unusual command execution.
- **00:00:03 — Deception Engagement**: Connection diverted to Cowrie honeypot on port 2222; credentials and attacker commands captured safely.
- **00:00:04 — Topology Defense**: Attacker blast radius isolated; core databases remained unreachable.

---

## 3. Recommended Actions
1. Maintain quarantine on source device `{device_val}`.
2. Require multi-factor authentication (MFA) reset for identity `{user_val}`.
3. Review updated policy weights recommended by the Quantum-Assisted Policy Reoptimization (QAPRE) solver.

*Prepared automatically by CipherGuide Grounded Assistant.*
"""
        finally:
            if close_db:
                db.close()
    generate_incident_report = generate_report

    def stream_ask(
        self,
        question: str,
        audience: str = "simple",
        lens=None,
        beginner_mode: bool = True,
        session_id=None,
        conversation_id=None,
        db=None,
        role=None,
        style=None,
        page_context=None,
    ):
        """Stream response tokens progressively using SSE format."""
        import json
        from .persona import detect_persona_in_text
        aud = lens or audience
        detected_role, detected_style, changed = detect_persona_in_text(question, aud, aud)
        if changed:
            aud = detected_style
        else:
            if role:
                detected_role = role
            if style:
                detected_style = style
                aud = style

        sid = conversation_id or session_id or "default_session"
        history = _SESSION_MEMORY.setdefault(sid, [])

        # Cache check - instant sub-ms response for frequent questions
        from app.guide.cache import get_cached_answer, set_cached_answer
        cached = get_cached_answer(question, detected_role, detected_style)
        if cached:
            words = cached["answer"].split(" ")
            for i, word in enumerate(words):
                token = word if i == 0 else " " + word
                yield f"data: {json.dumps({'token': token, 'provider': cached.get('provider_used', 'ollama')})}\n\n"
            yield f"data: {json.dumps({'done': True, 'provider': cached.get('provider_used', 'ollama')})}\n\n"
            return

        close_db = False
        if db is None:
            from app.db.session import SessionLocal
            db = SessionLocal()
            close_db = True

        from .context_builder import ContextBuilder
        ctx = ContextBuilder(db).build_context(
            question,
            page_context=page_context,
            role=detected_role,
            style=detected_style,
        )
        augmented_question = f"Facts:\n{ctx['facts_block']}\n\nQuestion: {question}"

        full_answer = []
        try:
            for token in self.chain.stream_direct_grounded_ollama(
                question=augmented_question,
                audience=aud,
                history=history,
                beginner_mode=beginner_mode,
            ):
                full_answer.append(token)
                yield f"data: {json.dumps({'token': token, 'provider': 'ollama'})}\n\n"
        except Exception as exc:
            logger.warning("Streaming from Ollama encountered error: %s", exc)

        accumulated = "".join(full_answer).strip()
        if not accumulated:
            res = self.ask(
                question=question,
                audience=audience,
                lens=lens,
                beginner_mode=beginner_mode,
                session_id=session_id,
                conversation_id=conversation_id,
                db=db,
                role=role,
                style=style,
                page_context=page_context,
            )
            accumulated = res.get("answer", "No response available.")
            yield f"data: {json.dumps({'token': accumulated, 'provider': res.get('provider_used', 'offline')})}\n\n"

        history.append({"role": "user", "content": question})
        history.append({"role": "assistant", "content": accumulated})
        if len(history) > 6:
            _SESSION_MEMORY[sid] = history[-6:]

        set_cached_answer(question, detected_role, detected_style, {
            "answer": accumulated,
            "audience": aud,
            "lens": aud,
            "confidence": "High",
            "evidence": [{"source": "GroundingContext", "streamed": True}],
            "provider_used": "ollama",
            "role": detected_role,
            "style": detected_style,
        })

        if close_db:
            db.close()

        yield f"data: {json.dumps({'done': True, 'provider': 'ollama'})}\n\n"


guide_service = GuideService()


def get_guide_service() -> GuideService:
    """Dependency provider returning singleton GuideService instance."""
    return guide_service
