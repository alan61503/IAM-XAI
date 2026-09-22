"""Estimator adapters shared by training, prediction and explanation."""

from typing import Any

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.preprocessing import LabelEncoder


class LabelEncodedClassifier(ClassifierMixin, BaseEstimator):
    """Wraps a classifier that only accepts integer labels (e.g. XGBoost) so it
    trains on and predicts the string risk labels like the scikit-learn models.
    """

    def __init__(self, estimator: Any = None):
        self.estimator = estimator

    def fit(self, X, y, **fit_params):
        self.label_encoder_ = LabelEncoder().fit(y)
        self.classes_ = self.label_encoder_.classes_
        self.estimator_ = clone(self.estimator).fit(X, self.label_encoder_.transform(y), **fit_params)
        return self

    def predict(self, X) -> np.ndarray:
        return self.classes_[np.asarray(self.estimator_.predict(X), dtype=int)]

    def predict_proba(self, X) -> np.ndarray:
        return self.estimator_.predict_proba(X)
