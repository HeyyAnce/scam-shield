"""
Unit tests for the reference matcher.
Verifies train-only indexing, multilingual similarity search, and provenance preservation.
"""

import unittest
from src.config import resolve_dataset_dir
from src.dataset_loader import DatasetLoader
from src.reference_matcher import DatasetReferenceMatcher


class TestReferenceMatcher(unittest.TestCase):
    """Test suite for DatasetReferenceMatcher."""

    @classmethod
    def setUpClass(cls):
        dataset_dir = resolve_dataset_dir()
        loader = DatasetLoader(dataset_dir)
        cls.dataset, _ = loader.load()
        cls.matcher = DatasetReferenceMatcher(cls.dataset)

    def test_train_partition_strict_indexing(self):
        """Verifies matcher indexes exactly and only the train partition (1,180 records)."""
        self.assertEqual(self.matcher.num_docs, 1180)
        self.assertEqual(len(self.matcher.doc_token_counts), 1180)

        # Ensure no val or test IDs exist in the indexed docs
        val_ids = set(self.dataset.df_val["curated_id"])
        test_ids = set(self.dataset.df_test["curated_id"])
        indexed_ids = set(self.matcher.train_df["curated_id"])

        self.assertEqual(len(val_ids & indexed_ids), 0, "Validation IDs leaked into matcher index!")
        self.assertEqual(len(test_ids & indexed_ids), 0, "Test IDs leaked into matcher index!")

    def test_english_scam_retrieval(self):
        """Verifies retrieval of electricity scam reference cases in English."""
        query = "URGENT: Your electricity connection will be disconnected tonight. Call officer at 9876543210."
        result = self.matcher.find_similar(query, top_k=3)

        self.assertGreater(len(result.matched_references), 0)
        self.assertEqual(result.consensus_label, "SCAM")
        self.assertEqual(result.top_category, "electricity_bill_disconnection")
        self.assertGreater(result.max_similarity, 0.15)
        self.assertTrue(result.has_strong_match)

    def test_hindi_scam_retrieval(self):
        """Verifies retrieval of Hindi (Devanagari) scam reference cases."""
        query = "प्रिय उपभोक्ता, आपके घर का बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछला बिल जमा नहीं है"
        result = self.matcher.find_similar(query, top_k=3)

        self.assertGreater(len(result.matched_references), 0)
        self.assertEqual(result.consensus_label, "SCAM")
        self.assertEqual(result.top_category, "electricity_bill_disconnection")
        self.assertGreater(result.max_similarity, 0.20)

    def test_hinglish_lottery_retrieval(self):
        """Verifies retrieval of Hinglish KBC / lottery scam reference cases."""
        query = "Badhai ho! Aapka number KBC lucky draw me 25 lakh cash prize jeeta hai turant sampark karein"
        result = self.matcher.find_similar(query, top_k=3)

        self.assertGreater(len(result.matched_references), 0)
        self.assertEqual(result.consensus_label, "SCAM")
        self.assertEqual(result.top_category, "lottery_prize_reward_scam")

    def test_legitimate_bank_transaction_retrieval(self):
        """Verifies retrieval of legitimate bank transactional reference cases."""
        query = "Dear Customer, your A/C XX4921 has been debited by Rs 1,250.00 on 22-Oct-26 at Apollo Pharmacy. Avail Bal: Rs 24,180.50."
        result = self.matcher.find_similar(query, top_k=3)

        self.assertGreater(len(result.matched_references), 0)
        self.assertEqual(result.consensus_label, "SAFE")
        self.assertIn("banking", result.top_category or "")

    def test_empty_query_handling(self):
        """Verifies that empty query returns empty results cleanly."""
        res = self.matcher.find_similar("", top_k=3)
        self.assertEqual(len(res.matched_references), 0)
        self.assertEqual(res.max_similarity, 0.0)


if __name__ == "__main__":
    unittest.main()
