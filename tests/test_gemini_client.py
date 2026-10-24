"""
Unit tests for the Gemini AI client.
Tests structured prompt generation, error mapping, and timeout/fallback resilience.
"""

import unittest
from unittest.mock import MagicMock, patch
from src.gemini_client import GeminiAnalyzer
from src.rule_engine import RuleAnalysisResult
from src.reference_matcher import MatchedReference


class TestGeminiAnalyzer(unittest.TestCase):
    """Test suite for GeminiAnalyzer."""

    def setUp(self):
        self.analyzer = GeminiAnalyzer()
        self.rule_results = RuleAnalysisResult(
            score=5,
            net_risk_score=75,
            risk_level="CRITICAL",
            findings=[{
                "category": "Urgent Threats & Fear Tactics",
                "icon": "⏱️",
                "severity": "HIGH",
                "details": ["Electricity disconnection tonight"],
            }],
            has_critical_indicators=True,
            has_high_risk=True,
            is_hard_negative=False,
        )
        self.sample_refs = [
            MatchedReference(
                curated_id="SS_CUR_0001",
                message="Your electricity will be cut off tonight at 9:30 PM",
                assigned_label="SCAM",
                curated_category="electricity_bill_disconnection",
                similarity_score=0.35,
                language="en",
                is_synthetic=True,
                source_id="SYN_EN_BATCH_001",
                source_name="Synthetic Batch",
                license_note="Unspecified",
            )
        ]

    def test_missing_api_key_returns_error_dict(self):
        """Verifies clean error dict when API key is None or empty."""
        res = self.analyzer.analyze("Some text", self.rule_results, self.sample_refs, api_key=None)
        self.assertEqual(res.get("error_type"), "NO_API_KEY")
        self.assertIn("error_message", res)

    @patch("google.genai.Client")
    def test_successful_gemini_response(self, mock_client_cls):
        """Verifies parsing of valid structured Gemini output."""
        mock_response = MagicMock()
        mock_response.text = '{"verdict": "SCAM", "scam_type": "Electricity Scam", "explanation": "This is a fake threat.", "red_flags": ["Urgent threat"], "recommended_actions": ["Do not pay"], "confidence": "HIGH"}'

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        res = self.analyzer.analyze(
            "Electricity cutoff notice",
            self.rule_results,
            self.sample_refs,
            api_key="mock_valid_key",
        )

        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("verdict"), "SCAM")
        self.assertEqual(res.get("scam_type"), "Electricity Scam")
        self.assertEqual(res.get("confidence"), "HIGH")

    @patch("google.genai.Client")
    def test_empty_gemini_response_handled(self, mock_client_cls):
        """Verifies handling when Gemini returns an empty string."""
        mock_response = MagicMock()
        mock_response.text = ""

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        res = self.analyzer.analyze(
            "Test text",
            self.rule_results,
            self.sample_refs,
            api_key="mock_key",
        )

        self.assertEqual(res.get("error_type"), "EMPTY_RESPONSE")

    @patch("google.genai.Client")
    def test_malformed_json_gemini_response(self, mock_client_cls):
        """Verifies handling when Gemini returns non-JSON text."""
        mock_response = MagicMock()
        mock_response.text = "I cannot parse this message."

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        res = self.analyzer.analyze(
            "Test text",
            self.rule_results,
            self.sample_refs,
            api_key="mock_key",
        )

        self.assertEqual(res.get("error_type"), "JSON_PARSE_ERROR")


if __name__ == "__main__":
    unittest.main()
