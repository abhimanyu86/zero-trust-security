import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from xgboost import XGBClassifier
from .calibration import CalibratedModelWrapper


class NextCellPredictor:
    """Multi-class XGBoost model predicting probabilities for candidate next serving cells."""

    def __init__(
        self,
        cell_classes: List[str],
        xgb_params: Optional[Dict[str, Any]] = None,
        calibration_method: str = "sigmoid",
    ):
        self.cell_classes = sorted(cell_classes)
        self.class_to_idx = {c: i for i, c in enumerate(self.cell_classes)}
        self.idx_to_class = {i: c for i, c in enumerate(self.cell_classes)}
        self.num_classes = len(self.cell_classes)

        default_params = {
            "n_estimators": 120,
            "max_depth": 4,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
            "objective": "multi:softprob",
            "num_class": self.num_classes,
            "random_state": 42,
            "eval_metric": "mlogloss",
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
        y_train_idx = y_train.map(self.class_to_idx).values
        y_val_idx = y_val.map(self.class_to_idx).values

        # 1. Fit base XGBoost model
        self.model.fit(
            X_train.values,
            y_train_idx,
            eval_set=[(X_val.values, y_val_idx)],
            verbose=False,
        )

        # 2. Fit probability calibrator on validation split
        self.calibrator.fit_calibration(self.model, X_val.values, y_val_idx)
        self.is_trained = True

    def predict_probabilities(self, X: pd.DataFrame) -> Dict[str, float]:
        """Returns calibrated probability distribution dictionary for a single sample."""
        if not self.is_trained:
            raise RuntimeError("NextCellPredictor is not trained!")

        X_mat = X[self.feature_names].values
        probs = self.calibrator.predict_proba(X_mat)[0]

        prob_dict = {self.idx_to_class[i]: float(probs[i]) for i in range(len(probs))}
        return prob_dict

    def predict_batch_probabilities(self, X: pd.DataFrame) -> np.ndarray:
        """Returns calibrated (N, num_classes) probability matrix."""
        if not self.is_trained:
            raise RuntimeError("NextCellPredictor is not trained!")
        X_mat = X[self.feature_names].values
        return self.calibrator.predict_proba(X_mat)

    def save(self, filepath: str):
        joblib.dump(
            {
                "model": self.model,
                "calibrator": self.calibrator,
                "cell_classes": self.cell_classes,
                "feature_names": self.feature_names,
                "is_trained": self.is_trained,
            },
            filepath,
        )

    @classmethod
    def load(cls, filepath: str) -> "NextCellPredictor":
        data = joblib.load(filepath)
        instance = cls(cell_classes=data["cell_classes"])
        instance.model = data["model"]
        instance.calibrator = data["calibrator"]
        instance.feature_names = data["feature_names"]
        instance.is_trained = data["is_trained"]
        return instance
