"""
Unit tests for the Decision Engine.
Verifies safety guardrails, consensus reconciliation, and offline fallback logic.
"""

import unittest
from src.decision_engine import DecisionEngine
from src.rule_engine import RuleAnalysisResult
from src.reference_matcher import DatasetMatchResult, MatchedReference


class TestDecisionEngine(unittest.TestCase):
    """Test suite for DecisionEngine."""

    def setUp(self):
        self.engine = DecisionEngine()

    def test_critical_safety_override(self):
        """
        GUARDRAIL TEST:
        If AI mistakenly returns SAFE, but rules found a CRITICAL indicator (.apk download),
        the decision engine must override to SCAM.
        """
        rule_res = RuleAnalysisResult(
            score=5,
            net_risk_score=75,
            risk_level="CRITICAL",
            findings=[{
                "category": "Suspicious Links & Downloads",
                "icon": "🔗",
                "severity": "CRITICAL",
                "details": [".apk download link detected"],
            }],
            has_critical_indicators=True,
            has_high_risk=True,
            is_hard_negative=False,
        )
        dataset_matches = DatasetMatchResult()
        # Simulated buggy or jailbroken AI output claiming it is SAFE
        buggy_ai = {
            "success": True,
            "verdict": "SAFE",
            "scam_type": "Benign Link",
            "explanation": "No issue found.",
            "red_flags": [],
            "recommended_actions": [],
            "confidence": "HIGH",
        }

        decision = self.engine.reconcile(rule_res, dataset_matches, buggy_ai)

        self.assertEqual(decision.verdict, "SCAM")
        self.assertEqual(decision.confidence, "HIGH")
        self.assertTrue(any("Safety Guardrail" in note for note in decision.reconciliation_notes))

    def test_hard_negative_reconciliation(self):
        """
        RECONCILIATION TEST:
        If AI says SUSPICIOUS on a standard bank debit SMS, but rules confirmed
        hard-negative and dataset matches SAFE, system reconciles to SAFE.
        """
        rule_res = RuleAnalysisResult(
            score=0,
            net_risk_score=0,
            risk_level="LOW",
            findings=[],
            has_critical_indicators=False,
            has_high_risk=False,
            is_hard_negative=True,
            hard_negative_reasons=["Standard bank transactional alert"],
        )
        safe_ref = MatchedReference(
            curated_id="SS_01",
            message="Your account XX12 has been debited by Rs 500",
            assigned_label="SAFE",
            curated_category="legitimate_banking_transaction",
            similarity_score=0.25,
            language="en",
            is_synthetic=False,
            source_id="SRC_PUB_UCI_SMSSPAM",
        )
        dataset_matches = DatasetMatchResult(
            matched_references=[safe_ref],
            top_label="SAFE",
            consensus_label="SAFE",
            top_category="legitimate_banking_transaction",
            max_similarity=0.25,
            has_strong_match=True,
        )
        ambiguous_ai = {
            "success": True,
            "verdict": "SUSPICIOUS",
            "scam_type": "Uncertain Alert",
            "explanation": "Message mentions money.",
            "red_flags": ["Mentions debit"],
            "recommended_actions": ["Check with bank"],
            "confidence": "MEDIUM",
        }

        decision = self.engine.reconcile(rule_res, dataset_matches, ambiguous_ai)

        self.assertEqual(decision.verdict, "SAFE")
        self.assertEqual(decision.confidence, "HIGH")
        self.assertTrue(any("Legitimate transactional alert confirmed" in note for note in decision.reconciliation_notes))

    def test_offline_fallback_scam(self):
        """Verifies offline fallback produces SCAM when critical rules trigger without AI."""
        rule_res = RuleAnalysisResult(
            score=5,
            net_risk_score=75,
            risk_level="CRITICAL",
            findings=[{
                "category": "Urgent Threats & Fear Tactics",
                "icon": "⏱️",
                "severity": "CRITICAL",
                "details": ["Digital arrest warrant issued"],
            }],
            has_critical_indicators=True,
            has_high_risk=True,
            is_hard_negative=False,
        )
        dataset_matches = DatasetMatchResult(
            top_label="SCAM",
            consensus_label="SCAM",
            top_category="digital_arrest_police_govt_impersonation",
            max_similarity=0.30,
            has_strong_match=True,
        )

        decision = self.engine.reconcile(rule_res, dataset_matches, gemini_result=None)

        self.assertFalse(decision.is_ai)
        self.assertEqual(decision.verdict, "SCAM")
        self.assertIn("Digital Arrest", decision.scam_type)
        self.assertEqual(decision.confidence, "HIGH")

    def test_offline_fallback_unverified_text(self):
        """
        ELDERLY SAFETY TEST:
        Unverified neutral text with no triggers and no safe pattern
        must default to SUSPICIOUS for safety.
        """
        rule_res = RuleAnalysisResult(
            score=0,
            net_risk_score=0,
            risk_level="LOW",
            findings=[],
            has_critical_indicators=False,
            has_high_risk=False,
            is_hard_negative=False,
        )
        dataset_matches = DatasetMatchResult()

        decision = self.engine.reconcile(rule_res, dataset_matches, gemini_result=None)

        self.assertEqual(decision.verdict, "SUSPICIOUS")
        self.assertEqual(decision.confidence, "LOW")


if __name__ == "__main__":
    unittest.main()
