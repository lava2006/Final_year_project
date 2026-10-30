"""Aggregate analytics endpoints used by the dashboard."""
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.deception import DecoySession
from app.models.policy import Policy, PolicyImprovement
from app.models.risk import RiskDecision
from app.models.session import ActiveSession
from app.models.telemetry import TelemetryEvent
from app.models.threat import Threat
from app.models.twin import TwinNode, TwinRelationship
from app.models.user import User

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    nodes = db.query(TwinNode).all()
    online = sum(1 for n in nodes if n.status == "online")
    offline = sum(1 for n in nodes if n.status == "offline")
    compromised = sum(1 for n in nodes if n.status == "compromised")

    sessions = db.query(ActiveSession).filter(ActiveSession.status == "active").all()

    # Risk level = function of compromised assets + recent high-risk decisions
    last_hour = datetime.now(timezone.utc) - timedelta(hours=1)
    high_recent = db.query(RiskDecision).filter(
        RiskDecision.timestamp >= last_hour,
        RiskDecision.risk_score >= 60,
    ).count()

    if compromised >= 2 or high_recent >= 5:
        risk_level = "critical"
    elif compromised >= 1 or high_recent >= 2:
        risk_level = "high"
    elif high_recent >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    total_users = db.query(TwinNode).filter(TwinNode.type == "user").count()
    total_tel_24h = db.query(TelemetryEvent).filter(
        TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()
    threats_active = db.query(Threat).filter(Threat.status == "active").count()
    decoys = db.query(DecoySession).count()
    policies_count = db.query(Policy).count()

    # Risk trend: hourly average score over last 24h via single indexed aggregation
    trend_counts = (
        db.query(
            func.strftime("%Y-%m-%d %H:00:00", RiskDecision.timestamp).label("hour_slot"),
            func.avg(RiskDecision.risk_score),
            func.count(RiskDecision.id),
        )
        .filter(RiskDecision.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24))
        .group_by("hour_slot")
        .all()
    )
    trend_map = {r[0]: (r[1] or 0.0, r[2] or 0) for r in trend_counts}
    risk_trend = []
    for hour in range(23, -1, -1):
        ts_to = datetime.now(timezone.utc) - timedelta(hours=hour)
        slot_key = ts_to.strftime("%Y-%m-%d %H:00:00")
        avg, cnt = trend_map.get(slot_key, (0.0, 0))
        risk_trend.append({
            "hour": ts_to.strftime("%H:%M"),
            "score": round(avg, 2),
            "count": cnt,
        })

    # Telemetry by type via SQL group-by
    type_counts = (
        db.query(TelemetryEvent.event_type, func.count(TelemetryEvent.id))
        .group_by(TelemetryEvent.event_type)
        .order_by(func.count(TelemetryEvent.id).desc())
        .all()
    )
    telemetry_by_type = [{"event_type": k, "count": v} for k, v in type_counts]

    # Top attacked assets via SQL group-by
    target_counts = (
        db.query(TelemetryEvent.target_id, func.count(TelemetryEvent.id))
        .filter(TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24))
        .group_by(TelemetryEvent.target_id)
        .order_by(func.count(TelemetryEvent.id).desc())
        .limit(8)
        .all()
    )
    target_nodes = {n.id: n for n in nodes}
    top_attacked = [
        {"target_id": tid, "label": target_nodes[tid].label if tid in target_nodes else tid, "count": c}
        for tid, c in target_counts
    ]

    # Top risky users (avg risk in last 24h) via SQL group-by
    user_counts = (
        db.query(RiskDecision.user_id, func.avg(RiskDecision.risk_score), func.count(RiskDecision.id))
        .filter(RiskDecision.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24))
        .group_by(RiskDecision.user_id)
        .order_by(func.avg(RiskDecision.risk_score).desc())
        .limit(8)
        .all()
    )
    top_risky_users = [
        {
            "user_id": uid,
            "label": target_nodes[uid].label if uid in target_nodes else uid,
            "department": target_nodes[uid].department if uid in target_nodes else None,
            "avg_risk": round(avg or 0.0, 2),
            "events": count,
        }
        for uid, avg, count in user_counts
    ]

    return {
        "online_devices": online,
        "offline_devices": offline,
        "compromised_assets": compromised,
        "trust_relationships": db.query(TwinRelationship).count(),
        "active_sessions": len(sessions),
        "risk_level": risk_level,
        "total_users": total_users,
        "total_telemetry_24h": total_tel_24h,
        "threats_active": threats_active,
        "decoy_sessions": decoys,
        "policies_count": policies_count,
        "risk_trend": risk_trend,
        "telemetry_by_type": telemetry_by_type,
        "top_attacked": top_attacked,
        "top_risky_users": top_risky_users,
    }


@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    buckets = {"0-20": 0, "20-40": 0, "40-60": 0, "60-80": 0, "80-100": 0}
    for d in db.query(RiskDecision).all():
        s = d.risk_score
        if s < 20:
            buckets["0-20"] += 1
        elif s < 40:
            buckets["20-40"] += 1
        elif s < 60:
            buckets["40-60"] += 1
        elif s < 80:
            buckets["60-80"] += 1
        else:
            buckets["80-100"] += 1
    return [{"range": k, "count": v} for k, v in buckets.items()]


@router.get("/threat-categories")
def threat_categories(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    counter = Counter()
    for t in db.query(Threat).all():
        techniques = json.loads(t.techniques or "[]")
        counter[len(techniques)] += 1
    return [{"techniques_count": k, "threats": v} for k, v in sorted(counter.items())]


@router.get("/attack-heatmap")
def attack_heatmap(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Day-of-week x hour-of-day heatmap data."""
    grid = [[0 for _ in range(24)] for _ in range(7)]
    for ev in db.query(TelemetryEvent).filter(
        TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).all():
        ts = ev.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        grid[ts.weekday()][ts.hour] += 1
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return {"days": days, "hours": list(range(24)), "grid": grid}


@router.get("/optimization-timeline")
def optimization_timeline(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = db.query(PolicyImprovement).order_by(PolicyImprovement.timestamp.asc()).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "score": r.after_score,
            "improvement": round(r.before_score - r.after_score, 2),
        }
        for r in rows
    ]


@router.get("/telemetry-volume")
def telemetry_volume(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    vol_counts = (
        db.query(
            func.strftime("%Y-%m-%d %H:00:00", TelemetryEvent.timestamp).label("hour_slot"),
            func.count(TelemetryEvent.id),
        )
        .filter(TelemetryEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24))
        .group_by("hour_slot")
        .all()
    )
    vol_map = {r[0]: r[1] for r in vol_counts}
    data = []
    for hour in range(23, -1, -1):
        ts_to = datetime.now(timezone.utc) - timedelta(hours=hour)
        slot_key = ts_to.strftime("%Y-%m-%d %H:00:00")
        data.append({"hour": ts_to.strftime("%H:%M"), "count": vol_map.get(slot_key, 0)})
    return data


@router.get("/pipeline-status")
def pipeline_status():
    from app.workers.pipeline import status as pipeline_status_fn
    return pipeline_status_fn()
