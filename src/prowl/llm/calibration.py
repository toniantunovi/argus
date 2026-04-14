"""Confidence calibration per (model, language, category)."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CalibrationResult:
    model_id: str
    language: str
    category: str
    promote_threshold: float = 0.7
    batch_threshold: float = 0.4
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    sample_size: int = 0

@dataclass
class CalibrationData:
    predicted_confidence: float
    actual_positive: bool

class CalibrationManager:
    def __init__(self, calibration_dir: Path):
        self.calibration_dir = calibration_dir
        self.calibration_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, CalibrationResult] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        for f in self.calibration_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                result = CalibrationResult(**data)
                key = f"{result.model_id}:{result.language}:{result.category}"
                self._cache[key] = result
            except (json.JSONDecodeError, Exception):
                continue

    def get_thresholds(self, model_id: str, language: str, category: str) -> tuple[float, float]:
        """Get calibrated thresholds for a specific (model, language, category) tuple.

        Returns (promote_threshold, batch_threshold).
        Falls back to conservative defaults if uncalibrated.
        """
        key = f"{model_id}:{language}:{category}"
        if key in self._cache:
            result = self._cache[key]
            return result.promote_threshold, result.batch_threshold

        # Try language-level fallback
        lang_key = f"{model_id}:{language}:*"
        if lang_key in self._cache:
            result = self._cache[lang_key]
            # Shift toward higher confidence for uncalibrated category
            return min(result.promote_threshold + 0.05, 0.95), min(result.batch_threshold + 0.05, 0.7)

        # Conservative fallback for uncalibrated
        return 0.75, 0.45

    def get_custom_rubric_thresholds(self, has_test_cases: bool = False) -> tuple[float, float]:
        """Get thresholds for custom rubrics.

        Custom rubrics use higher thresholds unless calibration test cases are provided.
        """
        if has_test_cases:
            return 0.7, 0.4  # normal thresholds if calibrated
        return 0.85, 0.6  # conservative for uncalibrated

    def calibrate(self, model_id: str, language: str, category: str, data: list[CalibrationData]) -> CalibrationResult:
        """Run calibration against benchmark data.

        Computes calibration curve and adjusts thresholds.
        """
        if not data:
            return CalibrationResult(model_id=model_id, language=language, category=category)

        # Sort by predicted confidence
        data.sort(key=lambda d: d.predicted_confidence)

        # Compute true positive rate at different thresholds
        total_positives = sum(1 for d in data if d.actual_positive)
        total_negatives = len(data) - total_positives

        if total_positives == 0 or total_negatives == 0:
            return CalibrationResult(
                model_id=model_id, language=language, category=category,
                sample_size=len(data),
            )

        # Find threshold that gives ~80% precision for promote
        best_promote = 0.7
        best_batch = 0.4

        for threshold in [i / 20.0 for i in range(1, 20)]:
            above = [d for d in data if d.predicted_confidence >= threshold]
            if not above:
                continue
            tp = sum(1 for d in above if d.actual_positive)
            precision = tp / len(above) if above else 0

            if precision >= 0.8 and threshold < best_promote:
                best_promote = threshold
            if precision >= 0.5 and threshold < best_batch:
                best_batch = threshold

        # Compute overall metrics
        promote_preds = [d for d in data if d.predicted_confidence >= best_promote]
        tp = sum(1 for d in promote_preds if d.actual_positive)
        fp = sum(1 for d in promote_preds if not d.actual_positive)
        tpr = tp / total_positives if total_positives else 0
        fpr = fp / total_negatives if total_negatives else 0

        result = CalibrationResult(
            model_id=model_id,
            language=language,
            category=category,
            promote_threshold=best_promote,
            batch_threshold=best_batch,
            true_positive_rate=tpr,
            false_positive_rate=fpr,
            sample_size=len(data),
        )

        # Cache result
        key = f"{model_id}:{language}:{category}"
        self._cache[key] = result

        # Persist
        filename = f"{model_id}_{language}_{category}.json".replace("/", "_").replace(":", "_")
        (self.calibration_dir / filename).write_text(json.dumps({
            "model_id": result.model_id,
            "language": result.language,
            "category": result.category,
            "promote_threshold": result.promote_threshold,
            "batch_threshold": result.batch_threshold,
            "true_positive_rate": result.true_positive_rate,
            "false_positive_rate": result.false_positive_rate,
            "sample_size": result.sample_size,
        }, indent=2))

        return result

    def detect_model_change(self, current_model_id: str) -> bool:
        """Check if the model has changed since last calibration."""
        if not self._cache:
            return True
        # Check if any cached calibration is for a different model
        for key, result in self._cache.items():
            if result.model_id != current_model_id:
                return True
        return False
