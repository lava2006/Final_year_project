"""Unit & integration tests for dynamic honeypot and adaptive deception persona selection."""
import pytest
from app.db.session import SessionLocal
from app.models.deception import DecoySession
from app.seed import init_schema
from app.services.deception import DeceptionEngine, DECOY_CONFIGURATIONS


def test_select_adaptive_decoy_ssh():
    # SSH brute-force or execution signal
    decision = DeceptionEngine.select_adaptive_decoy(
        risk_score=85.0,
        mitre_technique="T1021.004",
        event_type="ssh_attempt",
    )
    assert decision.selected_decoy == "ssh"
    assert decision.fidelity_level == "HIGH"
    assert "Debian" in decision.persona
    assert "OpenSSH" in decision.banner
    assert decision.confidence >= 0.90


def test_select_adaptive_decoy_database():
    # Database exfiltration signal — risk=75 triggers HIGH fidelity (Issue 2 fix)
    decision = DeceptionEngine.select_adaptive_decoy(
        risk_score=75.0,
        mitre_technique="T1041",
        event_type="data_exfiltration",
        sensitivity="critical",
    )
    assert decision.selected_decoy == "database"
    # data_exfiltration at risk>=75 is HIGH fidelity per the corrected rule
    assert decision.fidelity_level == "HIGH"
    assert "MySQL" in decision.persona or "PostgreSQL" in decision.persona
    assert decision.banner != ""


def test_select_adaptive_decoy_admin_panel():
    # Admin brute force signal
    decision = DeceptionEngine.select_adaptive_decoy(
        risk_score=90.0,
        mitre_technique="T1110",
        event_type="failed_login",
        device_trust=20.0,
    )
    assert decision.selected_decoy == "admin_panel"
    assert decision.fidelity_level == "HIGH"
    assert "Okta" in decision.persona or "Keycloak" in decision.persona


def test_select_adaptive_decoy_api():
    # API token probing signal — risk=50 is in suspicious/moderate range → MEDIUM fidelity (Issue 2 fix)
    decision = DeceptionEngine.select_adaptive_decoy(
        risk_score=50.0,
        event_type="api_token_probe",
    )
    assert decision.selected_decoy == "api"
    # api_token_probe at risk=50 is MEDIUM fidelity per the corrected rule
    assert decision.fidelity_level == "MEDIUM"
    assert "Decoy" in decision.persona or "REST" in decision.persona


def test_select_adaptive_decoy_web():
    # Generic web probe
    decision = DeceptionEngine.select_adaptive_decoy(
        risk_score=65.0,
        event_type="web_request",
    )
    assert decision.selected_decoy == "web"
    assert decision.fidelity_level == "MEDIUM"
    assert "Wiki" in decision.persona or "Confluence" in decision.persona or "Portal" in decision.persona


def test_open_decoy_persists_persona_and_banner():
    init_schema()
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        session = engine.open_decoy(
            actor="test_attacker_42",
            source_ip="192.168.1.100",
            threat_id=None,
            risk_score=88.0,
            mitre_technique="T1021.004",
            event_type="ssh_attempt",
        )
        assert session.id is not None
        assert session.decoy_type == "ssh"
        assert session.fidelity == "HIGH"
        assert session.persona == DECOY_CONFIGURATIONS["ssh"]["HIGH"]["persona"]
        assert session.banner == DECOY_CONFIGURATIONS["ssh"]["HIGH"]["banner"]

        # Check serialization
        d = session.to_dict()
        assert d["persona"] == session.persona
        assert d["banner"] == session.banner
        assert any("Deployed Persona:" in act for act in d["activity"])
    finally:
        db.close()
