"""
Unit tests for the multi-lingual Rule Engine.
Covers urgent threats, credential theft, links, APK downloads, hard negatives, and false-positive resilience.
"""

import unittest
from src.rule_engine import RuleEngine


class TestRuleEngine(unittest.TestCase):
    """Test suite for RuleEngine."""

    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine()

    def test_electricity_threat(self):
        """Verifies electricity disconnection threat detection."""
        text = "Dear Consumer, your power supply will be disconnected tonight at 9:30 PM due to unpaid bill."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_high_risk)
        self.assertIn(res.risk_level, ["HIGH", "CRITICAL"])
        categories = [f["category"] for f in res.findings]
        self.assertIn("Urgent Threats & Fear Tactics", categories)

    def test_apk_malware_link(self):
        """Verifies .apk direct download flag as CRITICAL."""
        text = "Please download the updated YONO APK app: http://sbi-update.xyz/app.apk to restore account."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_critical_indicators)
        self.assertEqual(res.risk_level, "CRITICAL")
        categories = [f["category"] for f in res.findings]
        self.assertIn("Suspicious Links & Downloads", categories)

    def test_digital_arrest_severe_threat(self):
        """Verifies Digital arrest / CBI narcotics threat in Hinglish."""
        text = "delhi cyber crime police... aapke phone se banned adult video dekhne par case darj hua h... digital arrest warrant issued."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_critical_indicators)
        self.assertEqual(res.risk_level, "CRITICAL")

    def test_active_otp_theft(self):
        """Verifies active demand to share OTP is flagged as CRITICAL."""
        text = "Customer care officer here, apna OTP batayein verification complete karne ke liye."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_critical_indicators)
        categories = [f["category"] for f in res.findings]
        self.assertIn("Credential & KYC Demands", categories)

    def test_upi_pin_inversion_scam(self):
        """Verifies QR code / enter UPI PIN to receive money trap."""
        text = "Congratulations! To receive ₹5,000 cashback, enter upi pin to receive funds immediately."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_critical_indicators)

    def test_kbc_lottery_hinglish(self):
        """Verifies KBC lottery and advance fee demand."""
        text = "Badhai ho! Aapne WhatsApp lottery me 25 lakh cash prize jeeta hai. Registration fee jama karein."
        res = self.engine.analyze(text)
        self.assertTrue(res.has_high_risk)
        categories = [f["category"] for f in res.findings]
        self.assertIn("Payment Demands & Lottery Traps", categories)

    def test_hard_negative_bank_debit(self):
        """Verifies that legitimate bank debit SMS is marked as safe hard-negative."""
        text = "Dear Customer, your A/C XX4921 has been debited by Rs 1,250.00 on 22-Oct-26 at Apollo Pharmacy via UPI. Avail Bal: Rs 24,180.50. Ref: 4295821092."
        res = self.engine.analyze(text)
        self.assertTrue(res.is_hard_negative)
        self.assertEqual(res.risk_level, "LOW")
        self.assertEqual(res.net_risk_score, 0)

    def test_hard_negative_legitimate_otp_with_warning(self):
        """Verifies that legitimate OTP notification stating 'Do not share' is treated as safe."""
        text = "719204 is the OTP to add beneficiary Rohan Verma in Bank of Baroda. Valid for 10 mins. Do not share this OTP with anyone."
        res = self.engine.analyze(text)
        self.assertTrue(res.is_hard_negative)
        self.assertEqual(res.risk_level, "LOW")

    def test_hard_negative_delivery_update(self):
        """Verifies routine delivery / courier notification is not falsely flagged."""
        text = "Your Blue Dart package #BD-991203 has been delivered to your address. Thank you for shopping with us."
        res = self.engine.analyze(text)
        self.assertTrue(res.is_hard_negative)
        self.assertEqual(res.risk_level, "LOW")

    def test_official_domain_not_flagged_as_lookalike(self):
        """Verifies that genuine domains like sbi.bank.in or cybercrime.gov.in are not flagged as fake lookalikes."""
        text = "Please visit official SBI portal at https://sbi.bank.in or https://cybercrime.gov.in"
        res = self.engine.analyze(text)
        # Should not have suspicious links findings
        link_findings = [f for f in res.findings if f["category"] == "Suspicious Links & Downloads"]
        self.assertEqual(len(link_findings), 0)


if __name__ == "__main__":
    unittest.main()
