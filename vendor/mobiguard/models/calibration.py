import numpy as np
from typing import Dict, Any, Optional
from sklearn.calibration import CalibratedClassifierCV
from sklearn.base import BaseEstimator


class CalibratedModelWrapper:
    """Wraps an estimator with Platt Sigmoid or Isotonic probability calibration."""

    def __init__(self, method: str = "sigmoid"):
        self.method = method
        self.calibrator: Optional[CalibratedClassifierCV] = None

    def fit_calibration(self, estimator: BaseEstimator, X_val: np.ndarray, y_val: np.ndarray):
        """Fit calibration on the validation split using the pre-fitted base estimator."""
        self.calibrator = CalibratedClassifierCV(
            estimator=estimator,
            method=self.method,
            cv="prefit",
        )
        self.calibrator.fit(X_val, y_val)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.calibrator is None:
            raise ValueError("Calibrator has not been fitted!")
        return self.calibrator.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self.calibrator is None:
            raise ValueError("Calibrator has not been fitted!")
        return self.calibrator.predict(X)
