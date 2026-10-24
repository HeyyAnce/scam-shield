"""
Unit tests for the dataset loader and validator.
Verifies schema, partition isolation, and exclusion enforcement.
"""

import unittest
from pathlib import Path
import tempfile
import pandas as pd

from src.config import resolve_dataset_dir
from src.dataset_loader import DatasetLoader, DatasetValidationReport


class TestDatasetLoader(unittest.TestCase):
    """Test suite for DatasetLoader."""

    @classmethod
    def setUpClass(cls):
        cls.dataset_dir = resolve_dataset_dir()

    def test_load_real_curated_dataset(self):
        """Validates that the real curated dataset loads cleanly and passes all integrity checks."""
        self.assertIsNotNone(self.dataset_dir, "Curated dataset directory could not be resolved.")
        loader = DatasetLoader(self.dataset_dir)
        dataset, report = loader.load()

        self.assertIsNotNone(dataset)
        self.assertTrue(report.is_valid)
        self.assertEqual(len(report.validation_errors), 0)

        # Check total record count and split partitions
        self.assertEqual(report.total_records, 1687)
        self.assertEqual(report.train_records, 1180)
        self.assertEqual(report.val_records, 253)
        self.assertEqual(report.test_records, 254)

        # Verify strict partition separation
        self.assertEqual(len(dataset.df_train), 1180)
        self.assertEqual(len(dataset.df_val), 253)
        self.assertEqual(len(dataset.df_test), 254)

        # Verify label distributions
        self.assertIn("SCAM", report.label_distribution)
        self.assertIn("SAFE", report.label_distribution)
        self.assertIn("SUSPICIOUS", report.label_distribution)

        # Verify synthetic ratio tracking
        self.assertGreater(report.synthetic_ratio, 0.80)
        self.assertEqual(report.public_records_count + report.synthetic_records_count, 1687)

    def test_sources_metadata_lookup(self):
        """Verifies source provenance and licensing info lookup."""
        loader = DatasetLoader(self.dataset_dir)
        dataset, _ = loader.load()

        # Public source lookup
        src_pub = dataset.get_source_info("SRC_PUB_UCI_SMSSPAM")
        self.assertIn("UCI", src_pub.get("source_name", ""))

        # Synthetic source lookup
        src_syn = dataset.get_source_info("SYN_HI_BATCH_001")
        self.assertIn("synthetic", src_syn.get("source_name", "").lower())

    def test_missing_directory_handling(self):
        """Verifies graceful degradation when dataset directory does not exist."""
        fake_path = Path("C:/non_existent_scam_shield_path_12345")
        loader = DatasetLoader(fake_path)
        dataset, report = loader.load()

        self.assertIsNone(dataset)
        self.assertFalse(report.is_valid)
        self.assertGreater(len(report.validation_errors), 0)

    def test_invalid_schema_detection(self):
        """Verifies that missing required columns trigger validation errors."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Create a CSV missing required columns
            bad_df = pd.DataFrame({
                "curated_id": ["SS_01"],
                "message": ["Some test text"],
                # missing assigned_label, split, language, etc.
            })
            bad_df.to_csv(tmp_path / "dataset.csv", index=False)

            loader = DatasetLoader(tmp_path)
            dataset, report = loader.load()

            self.assertIsNone(dataset)
            self.assertFalse(report.is_valid)
            self.assertTrue(any("Missing required columns" in err for err in report.validation_errors))


if __name__ == "__main__":
    unittest.main()
