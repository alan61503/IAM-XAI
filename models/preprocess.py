"""Phase 6 preprocessing: load the Phase 5 CSV and build train/val/test splits.

Implements CLAUDE.md section 6.2 (feature set) and 6.4 (70/15/15 split,
``random_state = 42``). The split is *grouped by scenario*: every path of one
synthetic environment lands in the same split, so the test set measures
generalization to unseen environments rather than recall of near-duplicate
paths from environments already seen in training.

Feature groups come from ``dataset.schema`` -- ground-truth columns
(``risk_score``, ``attack_type``, ``risk_cause``, ``scenario_patterns``,
``target_classification``) are never model inputs.
"""

from pathlib import Path
from typing import Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from dataset.schema import BINARY_FEATURES, CATEGORICAL_FEATURES, NUMERIC_FEATURES

RANDOM_STATE = 42
LABEL_COLUMN = "risk_label"
GROUP_COLUMN = "scenario_id"

__all__ = [
    "RANDOM_STATE",
    "LABEL_COLUMN",
    "GROUP_COLUMN",
    "NUMERIC_FEATURES",
    "BINARY_FEATURES",
    "CATEGORICAL_FEATURES",
    "load_dataset",
    "build_feature_matrix",
    "split_dataset",
    "align_features",
]


def load_dataset(csv_path: Union[str, Path]) -> pd.DataFrame:
    return pd.read_csv(csv_path)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode categorical columns and assemble the full feature matrix."""
    encoded = pd.get_dummies(df[CATEGORICAL_FEATURES].astype(str), prefix=CATEGORICAL_FEATURES, dtype=int)
    numeric = df[NUMERIC_FEATURES + BINARY_FEATURES].reset_index(drop=True)
    return pd.concat([numeric, encoded.reset_index(drop=True)], axis=1)


def _group_split(groups: pd.Series, test_size: float) -> Tuple[np.ndarray, np.ndarray]:
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=RANDOM_STATE)
    return next(splitter.split(np.zeros(len(groups)), groups=groups))


def split_dataset(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """70/15/15 train/val/test split with no scenario shared between splits."""
    df = df.reset_index(drop=True)
    X = build_feature_matrix(df)
    y = df[LABEL_COLUMN]
    groups = df[GROUP_COLUMN]

    train_idx, temp_idx = _group_split(groups, test_size=0.30)
    val_rel, test_rel = _group_split(groups.iloc[temp_idx].reset_index(drop=True), test_size=0.50)
    val_idx, test_idx = temp_idx[val_rel], temp_idx[test_rel]

    return X.iloc[train_idx], X.iloc[val_idx], X.iloc[test_idx], y.iloc[train_idx], y.iloc[val_idx], y.iloc[test_idx]


def align_features(row: pd.DataFrame, feature_columns: list) -> pd.DataFrame:
    """Reindex a feature frame (from ``build_feature_matrix``) onto the exact
    column set a saved model was trained with, filling unseen dummy columns
    with 0 (e.g. a ``target_service`` value not present in that frame).
    """
    return row.reindex(columns=feature_columns, fill_value=0)
