"""
Evaluation benchmark for Scam Shield.
Evaluates the integrated detection pipeline against the validation (253 records)
and held-out test (254 records) partitions.
Disaggregates metrics across languages (en, hi, hinglish) and origins (public vs synthetic).
"""

import unittest
from collections import defaultdict
from typing import Dict, List, Any
import pandas as pd

from src.config import resolve_dataset_dir
from src.dataset_loader import DatasetLoader
from src.pipeline import ScamShieldPipeline


def compute_classification_metrics(y_true: List[str], y_pred: List[str], labels=("SCAM", "SAFE", "SUSPICIOUS")) -> Dict[str, Any]:
    """Computes accuracy, precision, recall, and F1 score per label and overall."""
    total = len(y_true)
    if total == 0:
        return {}

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / total

    metrics: Dict[str, Any] = {"total": total, "accuracy": round(accuracy, 4), "per_class": {}}

    for lbl in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p == lbl)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lbl and p == lbl)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p != lbl)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        metrics["per_class"][lbl] = {
            "support": sum(1 for t in y_true if t == lbl),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    # Macro F1
    macro_f1 = sum(m["f1"] for m in metrics["per_class"].values()) / len(labels)
    metrics["macro_f1"] = round(macro_f1, 4)

    # Safe to Scam false positive rate (SAFE classified as SCAM)
    safe_total = sum(1 for t in y_true if t == "SAFE")
    safe_as_scam = sum(1 for t, p in zip(y_true, y_pred) if t == "SAFE" and p == "SCAM")
    metrics["false_positive_rate_safe_to_scam"] = round(safe_as_scam / safe_total, 4) if safe_total > 0 else 0.0

    return metrics


class TestDatasetEvaluation(unittest.TestCase):
    """Evaluates detector on validation and held-out test splits."""

    @classmethod
    def setUpClass(cls):
        dataset_dir = resolve_dataset_dir()
        loader = DatasetLoader(dataset_dir)
        cls.dataset, _ = loader.load()
        cls.pipeline = ScamShieldPipeline(dataset_dir=dataset_dir)

    def _evaluate_split(self, df_split: pd.DataFrame, split_name: str) -> Dict[str, Any]:
        """Runs evaluation over a dataframe partition."""
        y_true = []
        y_pred = []
        records_meta = []

        for _, row in df_split.iterrows():
            msg = str(row["message"])
            true_lbl = str(row["assigned_label"]).upper()
            lang = str(row.get("language", "en"))
            is_synth = bool(row.get("is_synthetic", True))

            # Offline analysis (no external API call during mass batch evaluation)
            output = self.pipeline.analyze(msg, api_key=None)
            pred_lbl = output.verdict.upper()

            y_true.append(true_lbl)
            y_pred.append(pred_lbl)
            records_meta.append({"lang": lang, "is_synth": is_synth, "true": true_lbl, "pred": pred_lbl})

        # Overall
        overall_metrics = compute_classification_metrics(y_true, y_pred)

        # By Language
        by_lang = {}
        for l in ["en", "hi", "hinglish"]:
            sub = [r for r in records_meta if r["lang"] == l]
            if sub:
                by_lang[l] = compute_classification_metrics(
                    [r["true"] for r in sub], [r["pred"] for r in sub]
                )

        # By Origin (Public Real vs Synthetic AI)
        by_origin = {}
        pub_records = [r for r in records_meta if not r["is_synth"]]
        synth_records = [r for r in records_meta if r["is_synth"]]

        if pub_records:
            by_origin["public_real"] = compute_classification_metrics(
                [r["true"] for r in pub_records], [r["pred"] for r in pub_records]
            )
        if synth_records:
            by_origin["synthetic_ai"] = compute_classification_metrics(
                [r["true"] for r in synth_records], [r["pred"] for r in synth_records]
            )

        return {
            "split": split_name,
            "overall": overall_metrics,
            "by_language": by_lang,
            "by_origin": by_origin,
        }

    def test_validation_split_evaluation(self):
        """Runs evaluation on the validation partition (253 records)."""
        val_res = self._evaluate_split(self.dataset.df_val, "validation")

        print("\n" + "=" * 60)
        print("SCAM SHIELD — VALIDATION PARTITION EVALUATION REPORT")
        print("=" * 60)
        overall = val_res["overall"]
        print(f"Total Records  : {overall['total']}")
        print(f"Accuracy       : {overall['accuracy'] * 100:.2f}%")
        print(f"Macro F1       : {overall['macro_f1'] * 100:.2f}%")
        print(f"FP Rate (SAFE->SCAM): {overall['false_positive_rate_safe_to_scam'] * 100:.2f}%")
        print("\nPer-Class Breakdown:")
        for cls_name, vals in overall["per_class"].items():
            print(f"  * {cls_name:10s} (N={vals['support']:3d}): Precision={vals['precision']:.3f}, Recall={vals['recall']:.3f}, F1={vals['f1']:.3f}")

        print("\nBy Language Accuracy:")
        for lang, lvals in val_res["by_language"].items():
            print(f"  * {lang:8s} (N={lvals['total']:3d}): Acc={lvals['accuracy'] * 100:.2f}%, Macro F1={lvals['macro_f1'] * 100:.2f}%")

        print("\nBy Origin Accuracy:")
        for orig, ovals in val_res["by_origin"].items():
            print(f"  * {orig:12s} (N={ovals['total']:3d}): Acc={ovals['accuracy'] * 100:.2f}%, Macro F1={ovals['macro_f1'] * 100:.2f}%")
        print("=" * 60)

        # Baseline checks
        self.assertGreater(overall["accuracy"], 0.65, "Validation accuracy is below benchmark threshold!")
        self.assertLess(overall["false_positive_rate_safe_to_scam"], 0.15, "False positive rate on SAFE messages is too high!")

    def test_test_split_evaluation(self):
        """Runs final evaluation on the held-out test partition (254 records)."""
        test_res = self._evaluate_split(self.dataset.df_test, "test")

        print("\n" + "=" * 60)
        print("SCAM SHIELD — HELD-OUT TEST PARTITION EVALUATION REPORT")
        print("=" * 60)
        overall = test_res["overall"]
        print(f"Total Records  : {overall['total']}")
        print(f"Accuracy       : {overall['accuracy'] * 100:.2f}%")
        print(f"Macro F1       : {overall['macro_f1'] * 100:.2f}%")
        print(f"FP Rate (SAFE->SCAM): {overall['false_positive_rate_safe_to_scam'] * 100:.2f}%")
        print("\nPer-Class Breakdown:")
        for cls_name, vals in overall["per_class"].items():
            print(f"  * {cls_name:10s} (N={vals['support']:3d}): Precision={vals['precision']:.3f}, Recall={vals['recall']:.3f}, F1={vals['f1']:.3f}")

        print("\nBy Language Accuracy:")
        for lang, lvals in test_res["by_language"].items():
            print(f"  * {lang:8s} (N={lvals['total']:3d}): Acc={lvals['accuracy'] * 100:.2f}%, Macro F1={lvals['macro_f1'] * 100:.2f}%")

        print("\nBy Origin Accuracy:")
        for orig, ovals in test_res["by_origin"].items():
            print(f"  * {orig:12s} (N={ovals['total']:3d}): Acc={ovals['accuracy'] * 100:.2f}%, Macro F1={ovals['macro_f1'] * 100:.2f}%")
        print("=" * 60)

        # Baseline checks
        self.assertGreater(overall["accuracy"], 0.65, "Held-out test accuracy is below benchmark threshold!")
        self.assertLess(overall["false_positive_rate_safe_to_scam"], 0.15, "False positive rate on SAFE messages is too high!")


if __name__ == "__main__":
    unittest.main()
