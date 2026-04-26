"""
AI SBC Security - Anomaly Detection Engine
Uses Isolation Forest + statistical analysis for multi-dimensional anomaly detection.
Works offline on SBCs with minimal RAM usage.
"""
import os
import json
import logging
import asyncio
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

logger = logging.getLogger("ai_sbc.anomaly")

MODEL_PATH = os.environ.get("MODEL_PATH", "/var/lib/ai-sbc-security/models")
os.makedirs(MODEL_PATH, exist_ok=True)

ANOMALY_MODEL_FILE = os.path.join(MODEL_PATH, "anomaly_model.pkl")

# Feature names used for the model
FEATURE_NAMES = [
    "cpu_percent", "ram_percent", "disk_percent",
    "net_bytes_sent_rate", "net_bytes_recv_rate",
    "net_packets_sent_rate", "net_packets_recv_rate",
    "cpu_temp_normalized",
    "login_attempts_per_min",
    "failed_logins_per_min",
    "open_connections",
    "processes_count",
    "hour_of_day",          # temporal feature
    "day_of_week",          # temporal feature
]


@dataclass
class AnomalyResult:
    timestamp: datetime
    is_anomaly: bool
    anomaly_score: float        # -1.0 (normal) to 1.0 (highly anomalous)
    confidence: float           # 0.0 to 1.0
    anomalous_features: List[str]
    severity: str               # "low", "medium", "high", "critical"
    description: str
    raw_features: Dict[str, float]


class AnomalyDetector:
    """
    Multi-variate anomaly detection using Isolation Forest.
    Supports online learning — model retrains periodically from collected baselines.
    Designed to run efficiently on low-RAM SBCs.
    """

    def __init__(self, contamination: float = 0.05, sensitivity: float = 0.8):
        self.contamination = contamination
        self.sensitivity = sensitivity
        self.model: Optional[Pipeline] = None
        self.is_trained = False
        self.training_buffer: deque = deque(maxlen=5000)  # Rolling buffer
        self.prediction_history: deque = deque(maxlen=200)
        self._lock = asyncio.Lock()
        self._load_model()

    def _build_model(self) -> Pipeline:
        return Pipeline([
            ("scaler", StandardScaler()),
            ("iforest", IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                max_samples="auto",
                random_state=42,
                n_jobs=1,           # Single job for SBC efficiency
                warm_start=False
            ))
        ])

    def _load_model(self):
        """Load pre-trained model from disk if available."""
        try:
            if os.path.exists(ANOMALY_MODEL_FILE):
                self.model = joblib.load(ANOMALY_MODEL_FILE)
                self.is_trained = True
                logger.info("Anomaly model loaded from disk")
        except Exception as e:
            logger.warning(f"Could not load anomaly model: {e}")
            self.model = self._build_model()

    def _save_model(self):
        try:
            joblib.dump(self.model, ANOMALY_MODEL_FILE)
        except Exception as e:
            logger.error(f"Could not save anomaly model: {e}")

    def extract_features(self, metrics: Dict[str, Any]) -> np.ndarray:
        """Extract and normalize feature vector from raw metrics."""
        now = datetime.utcnow()
        cpu_temp = metrics.get("cpu_temp", 50.0) or 50.0
        features = [
            float(metrics.get("cpu_percent", 0)),
            float(metrics.get("ram_percent", 0)),
            float(metrics.get("disk_percent", 0)),
            float(metrics.get("net_bytes_sent_rate", 0)),
            float(metrics.get("net_bytes_recv_rate", 0)),
            float(metrics.get("net_packets_sent_rate", 0)),
            float(metrics.get("net_packets_recv_rate", 0)),
            min(float(cpu_temp) / 100.0, 1.5),   # normalized
            float(metrics.get("login_attempts_per_min", 0)),
            float(metrics.get("failed_logins_per_min", 0)),
            float(metrics.get("open_connections", 0)),
            float(metrics.get("processes_count", 100)),
            float(now.hour) / 23.0,               # 0-1 normalized
            float(now.weekday()) / 6.0,           # 0-1 normalized
        ]
        return np.array(features).reshape(1, -1)

    async def add_to_baseline(self, metrics: Dict[str, Any]):
        """Add a data point to the training buffer."""
        async with self._lock:
            features = self.extract_features(metrics)
            self.training_buffer.append(features.flatten())
            # Auto-retrain when we have enough new data
            if len(self.training_buffer) % 500 == 0 and len(self.training_buffer) >= 100:
                await self.train()

    async def train(self):
        """Train/retrain the Isolation Forest model."""
        async with self._lock:
            if len(self.training_buffer) < 50:
                logger.info(f"Not enough training data ({len(self.training_buffer)} samples)")
                return
            try:
                X = np.array(list(self.training_buffer))
                model = self._build_model()
                model.fit(X)
                self.model = model
                self.is_trained = True
                self._save_model()
                logger.info(f"Anomaly model trained on {len(X)} samples")
            except Exception as e:
                logger.error(f"Anomaly training failed: {e}")

    async def detect(self, metrics: Dict[str, Any]) -> AnomalyResult:
        """Run anomaly detection on current metrics."""
        features = self.extract_features(metrics)
        now = datetime.utcnow()

        if not self.is_trained or self.model is None:
            # Fallback: rule-based detection when model isn't ready
            return self._rule_based_detection(metrics, features, now)

        try:
            # Isolation Forest: -1 = anomaly, 1 = normal
            prediction = self.model.predict(features)[0]
            # Score: more negative = more anomalous (convert to 0-1 scale)
            raw_score = self.model.decision_function(features)[0]
            # Normalize to 0 (normal) to 1 (highly anomalous)
            anomaly_score = max(0.0, min(1.0, (-raw_score + 0.5) * self.sensitivity))

            is_anomaly = (prediction == -1) and (anomaly_score > 0.5)

            # Identify which features are most anomalous via contribution analysis
            anomalous_features = self._identify_anomalous_features(metrics)

            severity = self._score_to_severity(anomaly_score)
            description = self._build_description(is_anomaly, anomaly_score, anomalous_features, metrics)

            result = AnomalyResult(
                timestamp=now,
                is_anomaly=is_anomaly,
                anomaly_score=round(anomaly_score, 4),
                confidence=min(1.0, len(self.training_buffer) / 500),
                anomalous_features=anomalous_features,
                severity=severity,
                description=description,
                raw_features={k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))}
            )
            self.prediction_history.append(result)
            return result
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return self._rule_based_detection(metrics, features, now)

    def _rule_based_detection(self, metrics: Dict, features: np.ndarray, now: datetime) -> AnomalyResult:
        """Simple threshold-based detection as fallback."""
        anomalies = []
        score = 0.0

        checks = [
            ("cpu_percent", 90, "CPU usage extremely high"),
            ("ram_percent", 92, "RAM near exhaustion"),
            ("failed_logins_per_min", 10, "Multiple failed login attempts"),
            ("login_attempts_per_min", 30, "Login attempt flood"),
            ("net_bytes_recv_rate", 100_000_000, "Network flood (>100MB/s)"),
        ]
        for key, threshold, label in checks:
            val = metrics.get(key, 0)
            if val and float(val) > threshold:
                anomalies.append(key)
                score += 0.2

        score = min(1.0, score)
        return AnomalyResult(
            timestamp=now,
            is_anomaly=len(anomalies) > 0,
            anomaly_score=score,
            confidence=0.6,
            anomalous_features=anomalies,
            severity=self._score_to_severity(score),
            description="Rule-based detection (AI model warming up)" if not anomalies else
                        f"Threshold exceeded: {', '.join(anomalies)}",
            raw_features={k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))}
        )

    def _identify_anomalous_features(self, metrics: Dict) -> List[str]:
        """Identify which features deviate most from baseline."""
        if len(self.training_buffer) < 50:
            return []
        X_hist = np.array(list(self.training_buffer))
        means = X_hist.mean(axis=0)
        stds = X_hist.std(axis=0) + 1e-8
        current = self.extract_features(metrics).flatten()
        z_scores = np.abs((current - means) / stds)
        anomalous = [FEATURE_NAMES[i] for i, z in enumerate(z_scores) if z > 3.0]
        return anomalous

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 0.85: return "critical"
        if score >= 0.65: return "high"
        if score >= 0.40: return "medium"
        return "low"

    @staticmethod
    def _build_description(is_anomaly: bool, score: float, features: List[str], metrics: Dict) -> str:
        if not is_anomaly:
            return "System behavior within normal parameters"
        feat_str = ", ".join(features[:3]) if features else "multiple metrics"
        return (f"Anomaly detected (score: {score:.2f}) — "
                f"Unusual activity in: {feat_str}. "
                f"CPU: {metrics.get('cpu_percent', 0):.1f}%, "
                f"RAM: {metrics.get('ram_percent', 0):.1f}%")

    def get_stats(self) -> Dict:
        return {
            "is_trained": self.is_trained,
            "training_samples": len(self.training_buffer),
            "predictions_made": len(self.prediction_history),
            "model_confidence": min(1.0, len(self.training_buffer) / 500),
            "recent_anomalies": sum(1 for r in self.prediction_history if r.is_anomaly),
        }


# Singleton
_detector: Optional[AnomalyDetector] = None

def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
