from __future__ import annotations

import builtins
import importlib
import sys
import types
import unittest
from unittest.mock import patch

from security_system.application.use_cases.analyze import analyze
from security_system.application.use_cases.run_scan import ScanOutput
from security_system.domain.models import GitContext


class AnalyzeTest(unittest.TestCase):
    def test_llm_package_exports_gemini_provider(self) -> None:
        fake_dotenv = types.ModuleType("dotenv")
        fake_dotenv.load_dotenv = lambda: None
        fake_google = types.ModuleType("google")
        fake_genai = types.ModuleType("google.genai")
        fake_google.genai = fake_genai

        sys.modules.pop("security_system.infrastructure.llm", None)
        sys.modules.pop("security_system.infrastructure.llm.provider", None)
        with patch.dict(
            sys.modules,
            {"dotenv": fake_dotenv, "google": fake_google, "google.genai": fake_genai},
        ):
            llm_module = importlib.import_module("security_system.infrastructure.llm")

        self.assertTrue(hasattr(llm_module, "GeminiProvider"))
        self.assertIn("GeminiProvider", llm_module.__all__)

    def test_missing_api_key_returns_fallback(self) -> None:
        fake_llm = types.ModuleType("security_system.infrastructure.llm")

        class UnavailableProvider:
            def __init__(self, api_key=None):
                raise EnvironmentError("GOOGLE_API_KEY is not set")

        fake_llm.GeminiProvider = UnavailableProvider
        with patch.dict(
            sys.modules,
            {"security_system.infrastructure.llm": fake_llm},
        ):
            result = analyze(ScanOutput(), GitContext.empty())

        self.assertEqual(result.errors, ["GOOGLE_API_KEY is not set"])
        self.assertEqual(result.reasoning, "LLM analysis unavailable.")

    def test_missing_llm_dependency_returns_fallback(self) -> None:
        real_import = builtins.__import__

        def fail_llm_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "security_system.infrastructure.llm":
                raise ImportError("Gemini dependency unavailable")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fail_llm_import):
            result = analyze(ScanOutput(), GitContext.empty())

        self.assertEqual(result.errors, ["Gemini dependency unavailable"])
        self.assertEqual(result.reasoning, "LLM analysis unavailable.")


if __name__ == "__main__":
    unittest.main()
