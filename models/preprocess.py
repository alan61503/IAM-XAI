"""Phase 6 preprocessing: load the Phase 5 CSV and build train/val/test splits.

Implements CLAUDE.md section 6.2 (feature set) and 6.4 (70/15/15 split,
``random_state = 42``). ``target_type`` isn't a column in the Phase 5 CSV
(CLAUDE.md section 5.1) -- it's derived here from the ``target_resource``
node id prefix (``user:`` / ``role:`` / ``resource:``).
"""

from pathlib import Path
from typing import Tuple, Union

import pandas as pd
from sklearn.model_selection import train_test_split

RANDOM_STATE = 42

NUMERIC_FEATURES = ["path_length", "role_count", "user_count"]
BINARY_FEATURES = [
    "assume_role",
    "pass_role",
    "wildcard_action",
    "wildcard_resource",
    "policy_modification",
    "external_trust",
    "cross_account",
    "sensitive_target",
    "admin_permission",
]
CATEGORICAL_FEATURES = ["attack_type", "target_type"]
LABEL_COLUMN = "risk_label"


def _target_type(target_resource: str) -> str:
    return target_resource.split(":", 1)[0] if ":" in target_resource else "unknown"


def load_dataset(csv_path: Union[str, Path]) -> pd.DataFrame:
    """Load the Phase 5 CSV and derive ``target_type`` from ``target_resource``."""
    df = pd.read_csv(csv_path)
    df["target_type"] = df["target_resource"].map(_target_type)
    return df


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode categorical columns and assemble the full feature matrix."""
    encoded = pd.get_dummies(df[CATEGORICAL_FEATURES], prefix=CATEGORICAL_FEATURES)
    numeric = df[NUMERIC_FEATURES + BINARY_FEATURES].reset_index(drop=True)
    return pd.concat([numeric, encoded.reset_index(drop=True)], axis=1)


def split_dataset(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """70/15/15 train/val/test split, stratified on ``risk_label``."""
    X = build_feature_matrix(df)
    y = df[LABEL_COLUMN].reset_index(drop=True)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def align_features(row: pd.DataFrame, feature_columns: list) -> pd.DataFrame:
    """Reindex a single-row feature frame (from ``build_feature_matrix``) onto the
    exact column set a saved model was trained with, filling unseen dummy columns
    with 0 (e.g. an ``attack_type`` value not present in that row).
    """
    return row.reindex(columns=feature_columns, fill_value=0)
