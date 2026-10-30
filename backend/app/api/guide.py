"""CipherGuide API router.

Exposes grounded, explainable endpoints for the beginner assistant:
- Natural-language Q&A through the multi-provider LLM chain
- Categorized suggestions for all personas
- 8-step interactive guided tour backed by real-time twin state
- Interactive terminology glossary
- Scenario replay kickoff & status
- Guarded action confirmation workflow
- Incident report generation (Markdown)
- Provider status check
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.guide.service import get_guide_service, GuideService
from app.guide.tour import get_tour_step, get_all_tour_steps, TourStep
from app.guide.glossary import get_glossary_term, get_all_terms, GlossaryTerm
from app.guide.llm import test_providers_smoke, LLMProviderChain

router = APIRouter(prefix="/api/guide", tags=["guide"])


class AskRequest(BaseModel):
    question: str = Field(..., description="The user's natural language question")
    lens: str = Field(default="simple", description="Audience lens: simple, manager, or analyst")
    beginner_mode: bool = Field(default=True, description="Whether to include jargon tooltips and analogies")
    conversation_id: Optional[str] = Field(default=None, description="Optional conversation session ID")
    role: Optional[str] = Field(default=None, description="Role / persona")
    style: Optional[str] = Field(default=None, description="Response style")
    page_context: Optional[str] = Field(default=None, description="Active UI page or panel context")


class ChatRequest(BaseModel):
    message: Optional[str] = Field(default=None, description="The user's message")
    question: Optional[str] = Field(default=None, description="Alternative field for message")
    role: Optional[str] = Field(default="Beginner/General user", description="Role/Persona")
    style: Optional[str] = Field(default="Simple Explanation", description="Response style")
    lens: Optional[str] = Field(default=None, description="Audience lens")
    beginner_mode: bool = Field(default=True, description="Whether beginner mode is active")
    conversation_id: Optional[str] = Field(default=None, description="Optional conversation session ID")
    history: Optional[List[Dict[str, str]]] = Field(default=None, description="Short conversation history")
    page_context: Optional[str] = Field(default=None, description="Current dashboard page")


class ConfirmActionRequest(BaseModel):
    action_id: str = Field(..., description="ID of the pending action to confirm")
    confirmed: bool = Field(default=True, description="User confirmation acknowledgement")


class ScenarioStartRequest(BaseModel):
    scenario_type: str = Field(default="brute_force_lateral", description="Scenario type to replay")


@router.get("/health")
def guide_health() -> Dict[str, Any]:
    """Lightweight health check for CipherTwinGuide."""
    ollama_ok = LLMProviderChain.is_ollama_available()
    return {
        "status": "HEALTHY",
        "guide_online": True,
        "ollama_connected": ollama_ok,
        "active_provider": "ollama" if ollama_ok else "offline",
    }


@router.post("/chat")
def chat_guide(
    req: ChatRequest,
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, Any]:
    """CipherTwinGuide Chat endpoint matching multi-persona requirements."""
    prompt = req.message or req.question or ""
    lens = req.lens or req.style or "simple"
    return guide.ask(
        question=prompt,
        lens=lens,
        beginner_mode=req.beginner_mode,
        conversation_id=req.conversation_id,
        role=req.role,
        style=req.style,
        page_context=req.page_context,
    )



@router.post("/chat-stream")
def chat_guide_stream(
    req: ChatRequest,
    guide: GuideService = Depends(get_guide_service),
):
    """Streaming CipherTwinGuide endpoint using Server-Sent Events."""
    prompt = req.message or req.question or ""
    lens = req.lens or req.style or "simple"
    return StreamingResponse(
        guide.stream_ask(
            question=prompt,
            lens=lens,
            beginner_mode=req.beginner_mode,
            conversation_id=req.conversation_id,
            role=req.role,
            style=req.style,
            page_context=req.page_context,
        ),
        media_type="text/event-stream",
    )


@router.post("/ask")
def ask_guide(
    req: AskRequest,
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, Any]:
    """Ask CipherGuide a question with grounded system evidence."""
    return guide.ask(
        question=req.question,
        lens=req.lens,
        beginner_mode=req.beginner_mode,
        conversation_id=req.conversation_id,
        role=req.role,
        style=req.style,
        page_context=req.page_context,
    )


@router.get("/suggestions")
def get_suggestions(
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, List[str]]:
    """Return categorized suggested questions for all personas."""
    return guide.get_suggested_questions()


@router.get("/tour")
def get_tour() -> List[Dict[str, Any]]:
    """Return all 8 steps of the Guided Tour with live system data."""
    steps = get_all_tour_steps()
    return [step.to_dict() for step in steps]


@router.get("/tour/{step_id}")
def get_tour_step_by_id(step_id: int) -> Dict[str, Any]:
    """Return a single tour step with refreshed live data."""
    step = get_tour_step(step_id)
    if not step:
        raise HTTPException(status_code=404, detail=f"Tour step {step_id} not found (must be 1-8)")
    return step.to_dict()


@router.get("/glossary")
def get_glossary(search: Optional[str] = Query(default=None)) -> List[Dict[str, Any]]:
    """Return the glossary of cybersecurity terms, optionally filtered."""
    terms = get_all_terms()
    if search:
        s = search.lower()
        terms = [t for t in terms if s in t.term.lower() or s in t.simple_definition.lower()]
    return [t.to_dict() for t in terms]


@router.get("/glossary/{term}")
def get_single_term(term: str) -> Dict[str, Any]:
    """Retrieve details and analogies for a specific cybersecurity term."""
    entry = get_glossary_term(term)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Term '{term}' not found in glossary")
    return entry.to_dict()


@router.post("/scenario/start")
def start_scenario(
    req: ScenarioStartRequest,
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, Any]:
    """Kick off a guided scenario replay with narrative steps."""
    return guide.start_guided_scenario(scenario_type=req.scenario_type)


@router.post("/actions/confirm")
def confirm_action(
    req: ConfirmActionRequest,
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, Any]:
    """Confirm and execute a guarded action (e.g. block IP, isolate device)."""
    return guide.confirm_action(action_id=req.action_id, confirmed=req.confirmed)


@router.get("/report/{incident_id}")
def get_incident_report(
    incident_id: str,
    guide: GuideService = Depends(get_guide_service),
) -> Dict[str, str]:
    """Generate a downloadable Markdown report for an incident or session."""
    md = guide.generate_incident_report(incident_id)
    return {"incident_id": incident_id, "markdown": md}


@router.get("/providers")
def check_providers() -> Dict[str, Any]:
    """Smoke check available LLM providers (xAI, Ollama, Offline)."""
    return test_providers_smoke()
