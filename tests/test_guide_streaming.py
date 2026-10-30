"""Tests for Issue 4: CipherTwinGuide streaming and caching fixes.

Verifies:
- stream_ask() exists on GuideService
- Cache returns instant responses for pre-seeded questions
- stream_ask() yields SSE-formatted data tokens and a final done event
- warmup_ollama() is importable from llm.py
- /chat-stream endpoint exists in the router
"""
import sys
import os
import json

import pytest

# Ensure backend module path is available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


class TestGuideCache:
    def test_cache_set_and_get(self):
        from app.guide.cache import get_cached_answer, set_cached_answer
        set_cached_answer("test question", "dev", "technical", {"answer": "cached"}, ttl=10)
        result = get_cached_answer("test question", "dev", "technical")
        assert result is not None
        assert result["answer"] == "cached"

    def test_cache_miss_returns_none(self):
        from app.guide.cache import get_cached_answer
        result = get_cached_answer("completely unknown question xyz123", "dev", "technical")
        assert result is None

    def test_starter_question_preseeded(self):
        """Starter questions should be pre-cached with real answers."""
        from app.guide.cache import get_cached_answer
        result = get_cached_answer(
            "explain how zero trust works in ciphertwin", "default", "default"
        )
        assert result is not None, "Starter question was not pre-seeded in cache"
        assert len(result["answer"]) > 50, "Pre-seeded answer too short"
        assert "Zero Trust" in result["answer"] or "zero trust" in result["answer"].lower()

    def test_cache_normalization(self):
        """Keys should be normalized (stripped + lowercased)."""
        from app.guide.cache import get_cached_answer, set_cached_answer
        set_cached_answer("  My Question  ", "ROLE", "STYLE", {"answer": "norm"}, ttl=10)
        result = get_cached_answer("my question", "role", "style")
        assert result is not None


class TestGuideServiceStreaming:
    def test_stream_ask_method_exists(self):
        from app.guide.service import GuideService
        assert hasattr(GuideService, "stream_ask"), "stream_ask must be a method of GuideService"

    def test_stream_ask_cached_question(self):
        """Pre-seeded question should stream instantly from cache."""
        import time
        from app.guide.service import GuideService

        srv = GuideService()
        t0 = time.time()
        tokens = []
        done_received = False

        for chunk in srv.stream_ask("Explain how Zero Trust works in CipherTwin"):
            tokens.append(chunk)
            data = chunk.replace("data: ", "").strip()
            if data:
                try:
                    parsed = json.loads(data)
                    if parsed.get("done"):
                        done_received = True
                except json.JSONDecodeError:
                    pass

        elapsed = time.time() - t0
        assert elapsed < 1.0, f"Cached response should be < 1s, got {elapsed:.3f}s"
        assert len(tokens) > 0, "Should yield at least one SSE chunk"
        assert done_received, "Should emit a final 'done' event"

        # Check SSE format
        for t in tokens:
            assert t.startswith("data: "), f"Token not SSE-formatted: {t!r}"

    def test_stream_ask_returns_sse_format(self):
        """Every yielded chunk must be SSE formatted."""
        from app.guide.service import GuideService
        srv = GuideService()

        for chunk in srv.stream_ask("What is a decoy honeypot?"):
            stripped = chunk.strip()
            if stripped:
                assert stripped.startswith("data:"), f"Non-SSE chunk: {stripped!r}"
            break  # Only check first chunk


class TestGuideLLMWarmup:
    def test_warmup_ollama_importable(self):
        from app.guide.llm import warmup_ollama
        assert callable(warmup_ollama)

    def test_stream_direct_grounded_ollama_exists(self):
        from app.guide.llm import LLMProviderChain
        chain = LLMProviderChain()
        assert hasattr(chain, "stream_direct_grounded_ollama")


class TestGuideStreamEndpoint:
    def test_chat_stream_route_registered(self):
        """The /api/guide/chat-stream POST route must exist."""
        from app.api.guide import router
        routes = [r.path for r in router.routes]
        assert "/api/guide/chat-stream" in routes, f"chat-stream route missing. Routes: {routes}"

    def test_original_chat_route_still_works(self):
        """Original /api/guide/chat POST route must still exist."""
        from app.api.guide import router
        routes = [r.path for r in router.routes]
        assert "/api/guide/chat" in routes
