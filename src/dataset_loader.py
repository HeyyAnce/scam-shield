"""
Dataset loader and validator for the curated Scam Shield dataset.
Strictly isolates train, validation, and test partitions to prevent data leakage.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import pandas as pd
from pydantic import BaseModel, Field

REQUIRED_COLUMNS = [
    "curated_id",
    "message",
    "assigned_label",
    "split",
    "language",
    "curated_category",
    "is_synthetic",
    "source_id",
]

VALID_LABELS = {"SCAM", "SAFE", "SUSPICIOUS"}
VALID_SPLITS = {"train", "val", "test"}
VALID_LANGUAGES = {"en", "hi", "hinglish"}


class DatasetValidationReport(BaseModel):
    """Validation report describing dataset integrity and partitioning."""
    is_valid: bool
    total_records: int = 0
    train_records: int = 0
    val_records: int = 0
    test_records: int = 0
    label_distribution: Dict[str, int] = Field(default_factory=dict)
    language_distribution: Dict[str, int] = Field(default_factory=dict)
    synthetic_ratio: float = 0.0
    public_records_count: int = 0
    synthetic_records_count: int = 0
    validation_errors: List[str] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)


class CuratedDataset:
    """Encapsulates loaded dataset partitions and source registry."""
    def __init__(
        self,
        df_train: pd.DataFrame,
        df_val: pd.DataFrame,
        df_test: pd.DataFrame,
        sources_df: Optional[pd.DataFrame] = None,
        report: Optional[DatasetValidationReport] = None,
        dataset_path: Optional[Path] = None,
    ):
        self.df_train = df_train
        self.df_val = df_val
        self.df_test = df_test
        self.sources_df = sources_df if sources_df is not None else pd.DataFrame()
        self.report = report
        self.dataset_path = dataset_path

        # Source metadata lookup by source_id
        self._source_lookup: Dict[str, Dict[str, Any]] = {}
        if not self.sources_df.empty and "source_id" in self.sources_df.columns:
            for _, row in self.sources_df.iterrows():
                self._source_lookup[str(row["source_id"])] = row.to_dict()

    def get_source_info(self, source_id: str) -> Dict[str, Any]:
        """Returns provenance and licensing information for a given source ID."""
        return self._source_lookup.get(
            str(source_id),
            {
                "source_name": "Unknown",
                "stated_license": "Unspecified",
                "redistribution_status": "Unknown",
                "is_synthetic": True,
            },
        )

    @property
    def train_count(self) -> int:
        return len(self.df_train)

    @property
    def val_count(self) -> int:
        return len(self.df_val)

    @property
    def test_count(self) -> int:
        return len(self.df_test)


class DatasetLoader:
    """Loads and validates the curated scam detection dataset."""

    def __init__(self, dataset_dir: Optional[Path] = None):
        self.dataset_dir = dataset_dir

    def load(self) -> Tuple[Optional[CuratedDataset], DatasetValidationReport]:
        """
        Loads dataset.csv and sources.csv from the configured directory.
        Performs thorough validation on schema, labels, splits, and nulls.
        Returns (CuratedDataset, DatasetValidationReport).
        """
        if not self.dataset_dir or not Path(self.dataset_dir).exists():
            report = DatasetValidationReport(
                is_valid=False,
                validation_errors=[
                    f"Dataset directory does not exist or is not specified: {self.dataset_dir}"
                ],
            )
            return None, report

        csv_path = Path(self.dataset_dir) / "dataset.csv"
        sources_path = Path(self.dataset_dir) / "sources.csv"
        exclusions_path = Path(self.dataset_dir) / "exclusions.csv"
        review_path = Path(self.dataset_dir) / "review_required.csv"

        if not csv_path.exists():
            report = DatasetValidationReport(
                is_valid=False,
                validation_errors=[f"Required dataset file missing: {csv_path}"],
            )
            return None, report

        try:
            df = pd.read_csv(csv_path, encoding="utf-8")
        except Exception as e:
            report = DatasetValidationReport(
                is_valid=False,
                validation_errors=[f"Failed to read CSV at {csv_path}: {str(e)}"],
            )
            return None, report

        sources_df = None
        if sources_path.exists():
            try:
                sources_df = pd.read_csv(sources_path, encoding="utf-8")
            except Exception:
                pass

        # Validate Schema
        errors: List[str] = []
        warnings: List[str] = []

        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            errors.append(f"Missing required columns in dataset.csv: {missing_cols}")

        if errors:
            return None, DatasetValidationReport(is_valid=False, validation_errors=errors)

        # Check for empty messages
        empty_msg_mask = df["message"].isna() | (df["message"].astype(str).str.strip() == "")
        if empty_msg_mask.any():
            count_empty = empty_msg_mask.sum()
            errors.append(f"Found {count_empty} records with missing or empty messages.")

        # Validate Labels
        invalid_labels = set(df["assigned_label"].dropna().unique()) - VALID_LABELS
        if invalid_labels:
            errors.append(f"Found unexpected labels in assigned_label: {invalid_labels}")

        # Validate Splits
        invalid_splits = set(df["split"].dropna().unique()) - VALID_SPLITS
        if invalid_splits:
            errors.append(f"Found unexpected splits in split: {invalid_splits}")

        # Check for exclusions or review_required records in approved dataset
        excluded_ids = set()
        if exclusions_path.exists():
            try:
                ex_df = pd.read_csv(exclusions_path, encoding="utf-8")
                id_col = "curated_id" if "curated_id" in ex_df.columns else ex_df.columns[0]
                excluded_ids.update(ex_df[id_col].dropna().astype(str))
            except Exception:
                pass

        if review_path.exists():
            try:
                rev_df = pd.read_csv(review_path, encoding="utf-8")
                id_col = "curated_id" if "curated_id" in rev_df.columns else rev_df.columns[0]
                excluded_ids.update(rev_df[id_col].dropna().astype(str))
            except Exception:
                pass

        if excluded_ids:
            curated_ids_in_dataset = set(df["curated_id"].dropna().astype(str))
            leaked_exclusions = curated_ids_in_dataset & excluded_ids
            if leaked_exclusions:
                errors.append(
                    f"Found {len(leaked_exclusions)} records from exclusions or review_required present in candidate dataset!"
                )

        if errors:
            return None, DatasetValidationReport(
                is_valid=False,
                validation_errors=errors,
                validation_warnings=warnings,
            )

        # Split into partitions
        df_train = df[df["split"] == "train"].copy().reset_index(drop=True)
        df_val = df[df["split"] == "val"].copy().reset_index(drop=True)
        df_test = df[df["split"] == "test"].copy().reset_index(drop=True)

        if len(df_train) == 0:
            errors.append("Train partition is empty.")
        if len(df_val) == 0:
            warnings.append("Validation partition is empty.")
        if len(df_test) == 0:
            warnings.append("Test partition is empty.")

        # Summary statistics
        total_records = len(df)
        label_dist = df["assigned_label"].value_counts().to_dict()
        lang_dist = df["language"].value_counts().to_dict() if "language" in df.columns else {}
        synthetic_count = int(df["is_synthetic"].sum()) if "is_synthetic" in df.columns else 0
        public_count = total_records - synthetic_count
        synth_ratio = round(synthetic_count / total_records, 4) if total_records > 0 else 0.0

        if synth_ratio > 0.8:
            warnings.append(
                f"High synthetic data proportion ({synth_ratio * 100:.1f}%). Candidate records require provenance tracking."
            )

        report = DatasetValidationReport(
            is_valid=True,
            total_records=total_records,
            train_records=len(df_train),
            val_records=len(df_val),
            test_records=len(df_test),
            label_distribution=label_dist,
            language_distribution=lang_dist,
            synthetic_ratio=synth_ratio,
            public_records_count=public_count,
            synthetic_records_count=synthetic_count,
            validation_errors=errors,
            validation_warnings=warnings,
        )

        curated_dataset = CuratedDataset(
            df_train=df_train,
            df_val=df_val,
            df_test=df_test,
            sources_df=sources_df,
            report=report,
            dataset_path=Path(self.dataset_dir),
        )

        return curated_dataset, report
