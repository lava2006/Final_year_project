"""Risk decision endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import get_current_user
from app.models.risk import RiskDecision
from app.models.user import User
from app.ml.inference import metadata as ml_metadata, predict as ml_predict
from app.models.telemetry import TelemetryEvent
from app.models.twin import TwinNode
from app.schemas.risk import RiskPredictionIn

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/decisions")
def list_decisions(decision: Optional[str] = None, user_id: Optional[str] = None,
                   page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                   db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    q = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc())
    if decision:
        q = q.filter(RiskDecision.decision == decision)
    if user_id:
        q = q.filter(RiskDecision.user_id == user_id)
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [d.to_dict() for d in items],
    }


@router.get("/decisions/{decision_id}")
def decision_detail(decision_id: int, db: Session = Depends(get_db),
                     _: User = Depends(get_current_user)):
    d = db.query(RiskDecision).filter(RiskDecision.id == decision_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Risk decision not found")
    return d.to_dict()


@router.get("/ml-status")
def ml_status(_: User = Depends(get_current_user)):
    """Return training metadata for verification without changing the dashboard UI."""
    return ml_metadata()


@router.post("/predict")
def predict_risk(
    payload: RiskPredictionIn,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Run persisted Random Forest inference on one incoming telemetry payload.

    The event is not persisted and the model is loaded from disk; it is never
    retrained during an API request.
    """
    import json

    event = TelemetryEvent(
        user_id=payload.user_id,
        device_id=payload.device_id,
        target_id=payload.target_id,
        event_type=payload.event_type,
        location=payload.location,
        ip_address=payload.ip_address,
        status=payload.status,
        risk_indicators=json.dumps(payload.risk_indicators),
        raw=json.dumps({"failed_logins": payload.failed_logins}),
    )
    device_trust = payload.device_trust
    if device_trust is None and payload.device_id:
        node = db.query(TwinNode).filter(TwinNode.id == payload.device_id).first()
        if node is not None and node.trust_score is not None:
            device_trust = float(node.trust_score)

    # Every valid request returns an inference result. If no matching device
    # exists, the feature extractor applies its documented default trust value.
    return ml_predict(event, device_trust=device_trust)


@router.get("/ml-metrics")
def ml_metrics(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return real-time ML metrics derived from genuine backend decisions and analyst feedback."""
    decisions = db.query(RiskDecision).all()
    total_preds = len(decisions)

    # Class counts based on actual Zero Trust risk thresholds & decisions
    normal_count = sum(1 for d in decisions if d.decision == "allow")
    suspicious_count = sum(1 for d in decisions if d.decision in ("restricted", "deceive"))
    malicious_count = sum(1 for d in decisions if d.decision == "deny")

    avg_conf = (sum(d.confidence for d in decisions) / total_preds) if total_preds else 0.0

    # Analyst feedback stats
    from app.models.risk import AnalystFeedback
    feedback_entries = db.query(AnalystFeedback).all()
    tp = sum(1 for f in feedback_entries if f.analyst_label == "TRUE_POSITIVE")
    fp = sum(1 for f in feedback_entries if f.analyst_label == "FALSE_POSITIVE")
    tn = sum(1 for f in feedback_entries if f.analyst_label == "TRUE_NEGATIVE")
    fn = sum(1 for f in feedback_entries if f.analyst_label == "FALSE_NEGATIVE")
    total_fb = len(feedback_entries)
    feedback_acc = ((tp + tn) / total_fb * 100) if total_fb else None

    meta = ml_metadata()
    holdout_accuracy = meta.get("accuracy")
    holdout_acc = round(float(holdout_accuracy) * 100, 2) if holdout_accuracy is not None else None

    return {
        "model_version": "v1.2.0-rf-iso",
        "model_type": "RandomForest + IsolationForest",
        "total_predictions": total_preds,
        "normal_count": normal_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "average_confidence": round(avg_conf, 2),
        "holdout_accuracy": holdout_acc,
        "feedback_accuracy": round(feedback_acc, 2) if feedback_acc is not None else None,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "true_negatives": tn,
        "total_feedback": total_fb,
    }


@router.post("/feedback")
def submit_feedback(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Submit analyst feedback for a specific risk prediction (TP, FP, TN, FN)."""
    from app.models.risk import AnalystFeedback
    from app.services.audit import log_event

    decision_id = payload.get("decision_id")
    analyst_label = payload.get("analyst_label", "").upper()
    reason = payload.get("reason", "")

    if analyst_label not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE"):
        return {"error": "Invalid label. Must be TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, or FALSE_NEGATIVE"}

    decision = db.query(RiskDecision).filter(RiskDecision.id == decision_id).first()
    if not decision:
        return {"error": "Decision not found"}

    fb = AnalystFeedback(
        decision_id=decision.id,
        analyst_id=user.username,
        original_prediction=decision.decision,
        analyst_label=analyst_label,
        reason=reason,
    )
    db.add(fb)
    db.commit()

    log_event(
        db,
        action="analyst_feedback",
        actor=user.username,
        target=f"decision_{decision.id}",
        details=f"Label={analyst_label}; Original={decision.decision}; Reason={reason}",
        severity="info",
    )

    return fb.to_dict()


@router.get("/feedback")
def list_feedback(
    decision_id: Optional[int] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List submitted analyst feedback."""
    from app.models.risk import AnalystFeedback
    q = db.query(AnalystFeedback)
    if decision_id:
        q = q.filter(AnalystFeedback.decision_id == decision_id)
    return [f.to_dict() for f in q.order_by(AnalystFeedback.timestamp.desc()).all()]


@router.get("/behaviour-analysis")
def get_behaviour_analysis(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Compute data-driven behaviour percentages from Zero Trust risk decisions."""
    decisions = db.query(RiskDecision).all()
    total = len(decisions)
    if total == 0:
        return {
            "total_evaluated": 0,
            "normal_pct": 0.0,
            "suspicious_pct": 0.0,
            "anomalous_pct": 0.0,
            "malicious_pct": 0.0,
            "counts": {"normal": 0, "suspicious": 0, "anomalous": 0, "malicious": 0},
            "average_risk_score": 0.0,
            "average_confidence": 0.0,
            "summary": "No telemetry behaviour evaluated yet.",
        }

    normal_c = sum(1 for d in decisions if d.decision == "allow")
    suspicious_c = sum(1 for d in decisions if d.decision == "restricted")
    anomalous_c = sum(1 for d in decisions if d.decision == "deceive")
    malicious_c = sum(1 for d in decisions if d.decision == "deny")

    avg_risk = round(sum(d.risk_score for d in decisions) / total, 1)
    avg_conf = round(sum(d.confidence for d in decisions) / total, 1)

    normal_pct = round((normal_c / total) * 100, 2)
    suspicious_pct = round((suspicious_c / total) * 100, 2)
    anomalous_pct = round((anomalous_c / total) * 100, 2)
    malicious_pct = round((malicious_c / total) * 100, 2)

    diff = round(100.0 - (normal_pct + suspicious_pct + anomalous_pct + malicious_pct), 2)
    if diff != 0:
        counts_list = [("normal", normal_c), ("suspicious", suspicious_c), ("anomalous", anomalous_c), ("malicious", malicious_c)]
        largest_key = max(counts_list, key=lambda x: x[1])[0]
        if largest_key == "normal":
            normal_pct = round(normal_pct + diff, 2)
        elif largest_key == "suspicious":
            suspicious_pct = round(suspicious_pct + diff, 2)
        elif largest_key == "anomalous":
            anomalous_pct = round(anomalous_pct + diff, 2)
        else:
            malicious_pct = round(malicious_pct + diff, 2)

    return {
        "total_evaluated": total,
        "normal_pct": normal_pct,
        "suspicious_pct": suspicious_pct,
        "anomalous_pct": anomalous_pct,
        "malicious_pct": malicious_pct,
        "counts": {
            "normal": normal_c,
            "suspicious": suspicious_c,
            "anomalous": anomalous_c,
            "malicious": malicious_c,
        },
        "average_risk_score": avg_risk,
        "average_confidence": avg_conf,
        "summary": f"Data-driven behavioral distribution across {total} evaluated access events.",
    }
