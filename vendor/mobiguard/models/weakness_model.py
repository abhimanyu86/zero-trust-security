import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any
from xgboost import XGBClassifier
from .calibration import CalibratedModelWrapper


class WeaknessPredictor:
    """Binary XGBoost model estimating probability of current serving cell degradation."""

    def __init__(
        self,
        xgb_params: Optional[Dict[str, Any]] = None,
        calibration_method: str = "sigmoid",
    ):
        default_params = {
            "n_estimators": 100,
            "max_depth": 3,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "objective": "binary:logistic",
            "random_state": 42,
            "eval_metric": "logloss",
        }
        if xgb_params:
            default_params.update(xgb_params)

        self.model = XGBClassifier(**default_params)
        self.calibrator = CalibratedModelWrapper(method=calibration_method)
        self.is_trained = False
        self.feature_names: List[str] = []

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame,
        y_val: pd.Series,
    ):
        self.feature_names = list(X_train.columns)
        self.model.fit(
            X_train.values,
            y_train.values,
            eval_set=[(X_val.values, y_val.values)],
            verbose=False,
        )
        self.calibrator.fit_calibration(self.model, X_val.values, y_val.values)
        self.is_trained = True

    def predict_weakness_risk(self, X: pd.DataFrame) -> float:
        """Returns calibrated probability in [0.0, 1.0] of imminent cell weakening."""
        if not self.is_trained:
            raise RuntimeError("WeaknessPredictor is not trained!")
        X_mat = X[self.feature_names].values
        probs = self.calibrator.predict_proba(X_mat)[0]
        # Probability of class 1
        return float(probs[1])

    def predict_batch_weakness_risk(self, X: pd.DataFrame) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError("WeaknessPredictor is not trained!")
        X_mat = X[self.feature_names].values
        return self.calibrator.predict_proba(X_mat)[:, 1]

    def save(self, filepath: str):
        joblib.dump(
            {
                "model": self.model,
                "calibrator": self.calibrator,
                "feature_names": self.feature_names,
                "is_trained": self.is_trained,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> "WeaknessPredictor":
        data = joblib.load(filepath)
        instance = cls()
        instance.model = data["model"]
        instance.calibrator = data["calibrator"]
        instance.feature_names = data["feature_names"]
        instance.is_trained = data["is_trained"]
        return instance
