"""Explainable Zero Trust risk engine.

Computes a weighted risk score in [0, 100] from contributing factors and
returns a human-readable explanation of the decision.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.risk import RiskDecision, RiskFactor
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.ml.inference import predict as ml_predict


# Default factor weights. Sum is normalized to 1.0 in the engine.
DEFAULT_WEIGHTS = {
    "identity": 0.20,
    "behavior": 0.30,
    "device": 0.20,
    "location": 0.10,
    "history": 0.20,
}


_TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parents[1] / "templates"),
    autoescape=False,
)
_RISK_SUMMARY_TEMPLATE = _TEMPLATE_ENV.get_template("risk_summary.j2")


@dataclass
class FactorResult:
    name: str
    score: Optional[float]
    weight: float
    contribution: float
    description: str


@dataclass
class EngineResult:
    risk_score: float
    decision: str
    confidence: float
    summary: str
    factors: List[FactorResult] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    ml: Dict[str, float | str] = field(default_factory=dict)


class ZeroTrustEngine:
    """Weighted, explainable Zero Trust decision engine."""

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}

    # ---- per-factor scoring helpers ----
    def score_identity(self, event: TelemetryEvent, db: Optional[Session] = None) -> Tuple[Optional[float], str]:
        if not event.user_id:
            return None, "Identity unobserved in telemetry (anonymous action)"
        indicators = event.risk_indicators or []
        user_trust = 90.0
        if db:
            user_node = db.query(TwinNode).filter(TwinNode.id == event.user_id).first()
            if user_node and user_node.trust_score is not None:
                user_trust = float(user_node.trust_score)
        baseline_risk = max(4.0, round(100.0 - user_trust, 1))
        score = baseline_risk
        reasons: List[str] = []
        if event.event_type == "failed_login":
            score += 35
            reasons.append("Authentication failure recorded")
        if "brute_force" in indicators:
            score += 35
            reasons.append("Brute-force pattern detected")
        if "impossible_travel" in indicators:
            score += 25
            reasons.append("Impossible-travel event detected")
        if "credential_stuffing" in indicators:
            score += 30
            reasons.append("Credential-stuffing signature")
        try:
            import json as _json
            raw_dict = _json.loads(event.raw) if isinstance(event.raw, str) else (event.raw or {})
            fl = int(raw_dict.get("failed_logins", 0))
            if fl >= 3:
                score += 35
                reasons.append(f"{fl} repeated login failures recorded")
            elif fl > 0:
                score += 15
                reasons.append(f"{fl} failed login attempt recorded")
        except Exception:
            pass
        score = min(100.0, score)
        desc = "; ".join(reasons) if reasons else f"User {event.user_id} verified (trust: {user_trust:.0f}%)"
        return score, desc

    def score_behavior(self, event: TelemetryEvent, ml_result: Optional[Dict[str, Any]] = None) -> Tuple[Optional[float], str]:
        indicators = event.risk_indicators or []
        ml_anomaly = float(ml_result.get("anomaly_score", 0.08)) if ml_result else 0.08
        norm_anomaly = (ml_anomaly / 100.0) if ml_anomaly > 1.0 else ml_anomaly
        base_score = max(4.0, round(norm_anomaly * 40.0, 1))
        reasons: List[str] = []
        high_risk_types = {
            "privilege_escalation": 55,
            "powershell": 45,
            "abnormal_process": 35,
            "usb_insertion": 25,
            "lateral_movement": 60,
            "data_exfiltration": 70,
        }
        if event.event_type in high_risk_types:
            base_score += high_risk_types[event.event_type]
            reasons.append(f"{event.event_type.replace('_', ' ').title()} observed")
        if "off_hours" in indicators:
            base_score += 15
            reasons.append("Activity outside business hours")
        if "high_volume" in indicators:
            base_score += 20
            reasons.append("Anomalous request volume")
        if "brute_force" in indicators or "credential_stuffing" in indicators or "credential_dump" in indicators:
            base_score += 40
            reasons.append("Brute-force or credential attack pattern detected")
        if "sensitive_resource" in indicators:
            base_score += 25
            reasons.append("Sensitive resource touched")
        if ml_result and ml_result.get("predicted_class") == "malicious":
            base_score += 40
            reasons.append("ML threat classifier flagged malicious pattern")
        score = min(100.0, base_score)
        desc = "; ".join(reasons) if reasons else f"Behavioral baseline normal (anomaly: {ml_anomaly:.2f})"
        return score, desc

    def score_device(self, event: TelemetryEvent, db: Session) -> Tuple[Optional[float], str]:
        if not event.device_id:
            return None, "Device unobserved in telemetry payload"
        score = 0.0
        reasons: List[str] = []
        node = db.query(TwinNode).filter(TwinNode.id == event.device_id).first()
        indicators = event.risk_indicators or []
        if node:
            device_trust = float(node.trust_score if node.trust_score is not None else 85.0)
            score = max(4.0, round(100.0 - device_trust, 1))
            if node.status == "compromised":
                score += 80
                reasons.append(f"Device {node.label} is marked compromised")
            if device_trust < 40:
                score += 40
                reasons.append(f"Device trust score low ({device_trust:.0f}%)")
            if node.os and "Unknown" in node.os:
                score += 25
                reasons.append("Unrecognised operating system")
            desc_base = f"Device {node.label} enrolled (trust: {device_trust:.0f}%)"
        else:
            score = 65.0
            reasons.append(f"Unknown device not enrolled in Digital Twin: {event.device_id}")
            desc_base = f"Unenrolled device {event.device_id}"

        if "usb_insertion" in indicators:
            score += 30
            reasons.append("USB device inserted")
        if "unsigned_binary" in indicators:
            score += 30
            reasons.append("Unsigned binary executed")
        score = min(100.0, score)
        desc = "; ".join(reasons) if reasons else desc_base
        return score, desc

    def score_location(self, event: TelemetryEvent) -> Tuple[Optional[float], str]:
        if not event.location:
            return None, "Location data not reported in telemetry payload"
        score = 4.0
        reasons: List[str] = []
        loc = (event.location or "").lower()
        if "impossible_travel" in (event.risk_indicators or []):
            score += 70
            reasons.append("Impossible travel between locations")
        if any(token in loc for token in ["tor", "anonymous", "unknown", "proxy"]):
            score += 40
            reasons.append(f"Anonymous network: {event.location}")
        if any(c in loc for c in ["ru", "cn", "kp", "ir"]) and "headquarters" not in loc:
            score += 25
            reasons.append(f"High-risk geolocation: {event.location}")
        if "vpn" in loc:
            score += 10
            reasons.append("VPN egress detected")
        if "remote" in loc:
            score += 5
            reasons.append("Remote access context")
        score = min(100.0, score)
        desc = "; ".join(reasons) if reasons else f"Location verified: {event.location}"
        return score, desc

    def score_history(self, event: TelemetryEvent, db: Session) -> Tuple[Optional[float], str]:
        if not event.user_id:
            return None, "No historical context available for unauthenticated principal"
        score = 3.0
        reasons: List[str] = []
        recent = (
            db.query(TelemetryEvent)
            .filter(TelemetryEvent.user_id == event.user_id)
            .order_by(TelemetryEvent.timestamp.desc())
            .limit(20)
            .all()
        )
        if recent:
            failures = sum(1 for e in recent if e.status == "failure" or e.event_type == "failed_login")
            if failures >= 3:
                score += 40
                reasons.append(f"{failures} failed actions in recent history")
            elif failures > 0:
                score += failures * 5.0
                reasons.append(f"{failures} prior failure in history")
            risky = sum(1 for e in recent if (e.risk_indicators or "").count("sensitive_resource"))
            if risky >= 1:
                score += 20
                reasons.append("Prior sensitive resource access")
        try:
            import json as _json
            raw_dict = _json.loads(event.raw) if isinstance(event.raw, str) else (event.raw or {})
            if raw_dict.get("failed_logins", 0) >= 3:
                score += 35
                reasons.append(f"{raw_dict.get('failed_logins')} repeated login failures in current session")
        except Exception:
            pass
        score = min(100.0, score)
        desc = "; ".join(reasons) if reasons else "No adverse history recorded (clean baseline)"
        return score, desc


    # ---- main evaluation ----
    def evaluate(self, event: TelemetryEvent, db: Session) -> EngineResult:
        # 1. Run ML inference first so behavioral analysis has ML features available
        ml_result: Dict[str, float | str] = {}
        try:
            node = None
            if event.device_id:
                node = db.query(TwinNode).filter(TwinNode.id == event.device_id).first()
            ml_result = ml_predict(event, device_trust=node.trust_score if node else None)
        except Exception:
            pass

        identity_score, identity_desc = self.score_identity(event, db)
        behavior_score, behavior_desc = self.score_behavior(event, ml_result)
        device_score, device_desc = self.score_device(event, db)
        location_score, location_desc = self.score_location(event)
        history_score, history_desc = self.score_history(event, db)

        raw_factors = [
            ("Identity Confidence", identity_score, self.weights["identity"], identity_desc),
            ("Behaviour Deviation", behavior_score, self.weights["behavior"], behavior_desc),
            ("Device Posture", device_score, self.weights["device"], device_desc),
            ("Location Anomaly", location_score, self.weights["location"], location_desc),
            ("Previous History", history_score, self.weights["history"], history_desc),
        ]

        # Calculate raw rule score from available factors
        raw_weighted_sum = sum(
            (score if score is not None else 0.0) * weight
            for _, score, weight, _ in raw_factors
        )
        rule_score = round(min(100.0, raw_weighted_sum), 1)

        # 2. Blend rule score with ML inference score
        total = rule_score
        confidence = 85.0
        if ml_result and "ml_risk_score" in ml_result:
            try:
                ml_score = float(ml_result["ml_risk_score"])
                ml_conf = float(ml_result.get("confidence", 85.0))
                total = round(min(100.0, 0.65 * rule_score + 0.35 * ml_score), 1)
                confidence = round(min(99.0, 0.70 * confidence + 0.30 * ml_conf), 1)
            except Exception:
                pass

        # 3. Proportionally distribute total decision score across factors so sum(contributions) == total
        factors: List[FactorResult] = []
        if raw_weighted_sum > 0:
            scale_ratio = total / raw_weighted_sum
            for name, score, weight, desc in raw_factors:
                if score is not None:
                    contrib = round(score * weight * scale_ratio, 1)
                    factors.append(FactorResult(name, round(score, 1), weight, contrib, desc))
                else:
                    factors.append(FactorResult(name, None, weight, 0.0, desc))
        else:
            for name, score, weight, desc in raw_factors:
                contrib = round(total * weight, 1) if score is not None else 0.0
                s = round(score, 1) if score is not None else None
                factors.append(FactorResult(name, s, weight, contrib, desc))

        # Ensure contributions sum EXACTLY to total (eliminate minor floating-point difference)
        current_sum = round(sum(f.contribution for f in factors), 1)
        diff = round(total - current_sum, 1)
        if diff != 0 and factors:
            # Add difference to the largest contributing factor
            max_factor = max(factors, key=lambda f: f.contribution)
            max_factor.contribution = round(max_factor.contribution + diff, 1)

        # Map MITRE ATT&CK technique and tactic
        try:
            import json as _json
            from app.services.mitre import map_event_to_mitre
            indicators = _json.loads(event.risk_indicators) if isinstance(event.risk_indicators, str) else (event.risk_indicators or [])
            mitre_match = map_event_to_mitre(event.event_type, indicators)
            if mitre_match:
                event.mitre_technique = mitre_match["technique_id"]
                event.mitre_tactic = mitre_match["tactic"]
        except Exception:
            pass

        # Evaluate against active Zero Trust policies
        from app.models.policy import Policy
        active_policies = db.query(Policy).filter(Policy.enabled == 1).order_by(Policy.priority.desc()).all()
        policy_decision = None
        for p in active_policies:
            rule_str = p.rule.lower()
            if "deny_if:risk>60" in rule_str and total > 60:
                policy_decision = "deny" if total >= 80 else "deceive"
                break
            elif "deny" in rule_str and total >= settings.risk_threshold_deny:
                policy_decision = "deny"
                break

        if policy_decision:
            decision = policy_decision
        elif total < settings.risk_threshold_allow:
            decision = "allow"
        elif total < settings.risk_threshold_restricted:
            decision = "restricted"
        elif total < settings.risk_threshold_deny:
            decision = "deceive"
        else:
            decision = "deny"

        contributing = [f for f in factors if f.score is not None and f.score >= 35]
        if decision == "allow":
            summary = "Access allowed. All Zero Trust factors within baseline."
        else:
            reasons = [f.description for f in contributing if f.description]
            top_factors = [f.name for f in sorted(factors, key=lambda f: f.contribution, reverse=True) if f.contribution > 0]
            summary = _RISK_SUMMARY_TEMPLATE.render(
                decision=decision,
                risk_score=total,
                top_factors=top_factors[:2],
                elevated_count=len(reasons),
                reasons=reasons[:3],
                ml=ml_result,
            )

        return EngineResult(
            risk_score=total,
            decision=decision,
            confidence=round(confidence, 2),
            summary=summary,
            factors=factors,
            reasons=[f.description for f in contributing],
            ml=ml_result,
        )

    def persist(self, event: TelemetryEvent, result: EngineResult, db: Session) -> RiskDecision:
        decision = RiskDecision(
            telemetry_id=event.id,
            user_id=event.user_id,
            device_id=event.device_id,
            resource_id=event.target_id,
            risk_score=result.risk_score,
            decision=result.decision,
            confidence=result.confidence,
            summary=result.summary,
        )
        db.add(decision)
        db.flush()
        for f in result.factors:
            db.add(
                RiskFactor(
                    decision_id=decision.id,
                    name=f.name,
                    weight=f.weight,
                    score=f.score,
                    contribution=f.contribution,
                    description=f.description,
                )
            )
        event.processed = 1
        db.flush()
        return decision


engine = ZeroTrustEngine()
