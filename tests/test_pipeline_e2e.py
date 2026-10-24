"""
End-to-end integration tests for the Scam Shield pipeline.
Verifies input -> rules -> dataset -> AI / fallback -> final decision across languages and modes.
"""

import os
import unittest
from dotenv import load_dotenv

from src.pipeline import ScamShieldPipeline

load_dotenv(override=True)


class TestPipelineE2E(unittest.TestCase):
    """End-to-end pipeline test suite."""

    @classmethod
    def setUpClass(cls):
        cls.pipeline = ScamShieldPipeline()
        cls.api_key = os.getenv("GEMINI_API_KEY")

    def test_pipeline_initialized_with_dataset(self):
        """Verifies pipeline correctly discovered and indexed the curated dataset."""
        self.assertTrue(self.pipeline.is_dataset_available)
        self.assertEqual(self.pipeline.train_records_count, 1180)

    def test_fraudulent_message_offline_and_online(self):
        """Verifies clearly fraudulent message detection in both offline and AI modes."""
        msg = (
            "Dear Consumer, Your Electricity power will be disconnected tonight at 9:30 PM from the electricity "
            "office because your previous month bill was not updated. Please immediately contact our electricity "
            "officer Rahul Sharma at 9876543210 or update bill through link: http://bit.ly/bijli-bill-pay"
        )

        # 1. Offline Mode
        res_offline = self.pipeline.analyze(msg, api_key=None)
        self.assertEqual(res_offline.verdict, "SCAM")
        self.assertFalse(res_offline.is_ai)
        self.assertTrue(res_offline.is_dataset_informed)
        self.assertEqual(res_offline.confidence, "HIGH")

        # 2. Online AI Mode (if API key available)
        if self.api_key and self.api_key != "your_gemini_api_key_here":
            res_online = self.pipeline.analyze(msg, api_key=self.api_key)
            self.assertEqual(res_online.verdict, "SCAM")
            self.assertTrue(res_online.is_ai)
            self.assertEqual(res_online.confidence, "HIGH")

    def test_safe_transaction_alert(self):
        """Verifies safe bank debit alert is not falsely flagged as scam."""
        msg = (
            "Dear Customer, your A/C XX4921 has been debited by Rs 1,250.00 on 22-Oct-26 at Apollo Pharmacy "
            "via UPI. Avail Bal: Rs 24,180.50. If not done by you, call 1800-11-2211 - State Bank of India"
        )

        res = self.pipeline.analyze(msg, api_key=self.api_key if self.api_key else None)
        self.assertEqual(res.verdict, "SAFE")
        self.assertIn("Transactional", res.scam_type)

    def test_hindi_scam_input(self):
        """Verifies Hindi Devanagari scam input processing."""
        msg = "प्रिय उपभोक्ता, आपके घर का बिजली कनेक्शन आज रात काट दिया जाएगा तुरंत बिल भुगतान करें: http://bijli-pay.xyz"
        res = self.pipeline.analyze(msg, api_key=self.api_key if self.api_key else None)
        self.assertEqual(res.verdict, "SCAM")

    def test_hinglish_digital_arrest(self):
        """Verifies Hinglish Digital arrest input processing."""
        msg = (
            "delhi cyber crime police... apke phone se banned adult video dekhne pr cyber act me case darj hua h... "
            "police gadi apke ghar aa rhi h... turant arrest se bachne k liye digital arrest skype call join krein"
        )
        res = self.pipeline.analyze(msg, api_key=self.api_key if self.api_key else None)
        self.assertEqual(res.verdict, "SCAM")
        self.assertEqual(res.confidence, "HIGH")

    def test_empty_message_input(self):
        """Verifies empty message is handled cleanly."""
        res = self.pipeline.analyze("", api_key=None)
        self.assertEqual(res.verdict, "SUSPICIOUS")
        self.assertEqual(res.scam_type, "Empty Message")

    def test_pipeline_without_dataset_graceful_fallback(self):
        """Verifies pipeline works completely even if dataset directory is None."""
        standalone_pipeline = ScamShieldPipeline(dataset_dir=None)
        self.assertFalse(standalone_pipeline.is_dataset_available)
        self.assertEqual(standalone_pipeline.train_records_count, 0)

        # Should still detect critical scam via rules
        msg = "Your electricity will be cut off tonight. Call 9876543210 or click http://bit.ly/pay"
        res = standalone_pipeline.analyze(msg, api_key=None)
        self.assertEqual(res.verdict, "SCAM")
        self.assertFalse(res.is_dataset_informed)


if __name__ == "__main__":
    unittest.main()
