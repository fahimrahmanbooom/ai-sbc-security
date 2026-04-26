"""
AI SBC Security - Predictive Threat Model
Time-series forecasting to predict future threat levels.
Uses exponential smoothing + Holt-Winters + statistical trend analysis.
Lightweight enough to run on Raspberry Pi Zero.
"""
import logging
import asyncio
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import math

import numpy as np

logger = logging.getLogger("ai_sbc.predictor")


@dataclass
class ThreatForecast:
    generated_at: datetime
    forecast_horizon_hours: int
    hourly_predictions: List[Dict]      # [{hour, predicted_score, confidence, risk_level}]
    peak_threat_hour: int
    peak_threat_score: float
    overall_risk: str                   # low, medium, high, critical
    trend: str                          # increasing, stable, decreasing
    trend_strength: float               # 0-1
    summary: str
    recommendations: List[str]


class ExponentialSmoother:
    """
    Double Exponential Smoothing (Holt's method) for trend-aware forecasting.
    Extremely lightweight — no external ML dependencies.
    """
    def __init__(self, alpha: float = 0.3, beta: float = 0.1):
        self.alpha = alpha      # Level smoothing
        self.beta = beta        # Trend smoothing
        self.level: Optional[float] = None
        self.trend: float = 0.0
        self._fitted = False

    def fit(self, series: List[float]):
        if len(series) < 2:
            return
        self.level = series[0]
        self.trend = series[1] - series[0]
        for value in series[1:]:
            prev_level = self.level
            self.level = self.alpha * value + (1 - self.alpha) * (self.level + self.trend)
            self.trend = self.beta * (self.level - prev_level) + (1 - self.beta) * self.trend
        self._fitted = True

    def forecast(self, steps: int) -> List[float]:
        if not self._fitted or self.level is None:
            return [0.0] * steps
        predictions = []
        for h in range(1, steps + 1):
            pred = self.level + h * self.trend
            pred = max(0.0, min(1.0, pred))  # Clamp to [0,1]
            predictions.append(pred)
        return predictions


class SeasonalDecomposer:
    """
    Simple seasonal decomposition for 24-hour cyclical patterns.
    Detects typical attack patterns by hour-of-day.
    """
    def __init__(self, period: int = 24):
        self.period = period
        self.seasonal_factors = [1.0] * period
        self._fitted = False

    def fit(self, hourly_values: Dict[int, List[float]]):
        """hourly_values: dict of {hour: [scores]}"""
        if not hourly_values:
            return
        all_mean = np.mean([v for vals in hourly_values.values() for v in vals]) + 1e-8
        for h in range(self.period):
            vals = hourly_values.get(h, [all_mean])
            if vals:
                self.seasonal_factors[h] = np.mean(vals) / all_mean
        self._fitted = True

    def adjust(self, value: float, hour: int) -> float:
        if not self._fitted:
            return value
        return value * self.seasonal_factors[hour % self.period]


class ThreatPredictor:
    """
    Predictive threat model combining:
    1. Exponential smoothing for trend detection
    2. Seasonal decomposition for time-of-day patterns
    3. Statistical momentum for short-term spikes
    """

    def __init__(self, forecast_hours: int = 24, min_history: int = 48):
        self.forecast_hours = forecast_hours
        self.min_history = min_history
        self.history: deque = deque(maxlen=2000)  # (timestamp, threat_score) tuples
        self.hourly_buckets: Dict[int, List[float]] = {h: [] for h in range(24)}
        self.smoother = ExponentialSmoother(alpha=0.25, beta=0.1)
        self.seasonal = SeasonalDecomposer()
        self._last_forecast: Optional[ThreatForecast] = None
        self._lock = asyncio.Lock()

    async def record(self, threat_score: float, timestamp: Optional[datetime] = None):
        """Record a threat observation."""
        ts = timestamp or datetime.utcnow()
        async with self._lock:
            self.history.append((ts, float(max(0.0, min(1.0, threat_score)))))
            hour = ts.hour
            self.hourly_buckets[hour].append(float(threat_score))
            # Keep hourly buckets bounded
            if len(self.hourly_buckets[hour]) > 500:
                self.hourly_buckets[hour] = self.hourly_buckets[hour][-200:]

    def _get_recent_series(self, hours: int = 48) -> List[float]:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [score for ts, score in self.history if ts > cutoff]

    def _aggregate_to_hourly(self, hours: int = 48) -> List[float]:
        """Aggregate recent data into hourly averages."""
        now = datetime.utcnow()
        hourly = []
        for h in range(hours, 0, -1):
            start = now - timedelta(hours=h)
            end = now - timedelta(hours=h - 1)
            bucket = [score for ts, score in self.history if start <= ts < end]
            hourly.append(np.mean(bucket) if bucket else 0.0)
        return hourly

    def _calculate_trend(self, series: List[float]) -> Tuple[str, float]:
        """Linear regression to determine trend direction and strength."""
        if len(series) < 3:
            return "stable", 0.0
        n = len(series)
        x = np.arange(n)
        slope = np.polyfit(x, series, 1)[0]
        # Normalize slope relative to value range
        value_range = max(max(series) - min(series), 0.01)
        strength = min(1.0, abs(slope * n) / value_range)
        if slope > 0.005: trend = "increasing"
        elif slope < -0.005: trend = "decreasing"
        else: trend = "stable"
        return trend, round(strength, 3)

    def _momentum_score(self, series: List[float], window: int = 6) -> float:
        """Short-term momentum: how fast is threat level changing right now?"""
        if len(series) < window:
            return 0.0
        recent = series[-window:]
        older = series[-window*2:-window] if len(series) >= window*2 else series[:window]
        recent_avg = np.mean(recent)
        older_avg = np.mean(older) if older else recent_avg
        return float(np.clip((recent_avg - older_avg) / max(older_avg, 0.01), -1, 1))

    async def generate_forecast(self) -> ThreatForecast:
        """Generate a threat forecast for the next N hours."""
        async with self._lock:
            series = self._aggregate_to_hourly(hours=self.min_history)
            has_data = len([v for v in series if v > 0]) >= 5

        if not has_data:
            return self._empty_forecast()

        # Fit models
        self.smoother.fit(series)
        self.seasonal.fit(self.hourly_buckets)

        # Generate base forecasts
        base_preds = self.smoother.forecast(self.forecast_hours)

        # Apply seasonal adjustment
        now = datetime.utcnow()
        hourly_predictions = []
        for i, base in enumerate(base_preds):
            future_hour = (now.hour + i + 1) % 24
            seasonal_adjusted = self.seasonal.adjust(base, future_hour)
            seasonal_adjusted = float(np.clip(seasonal_adjusted, 0.0, 1.0))

            # Confidence decays with forecast horizon
            confidence = max(0.3, 1.0 - (i / self.forecast_hours) * 0.6)

            risk_level = "low"
            if seasonal_adjusted >= 0.75: risk_level = "critical"
            elif seasonal_adjusted >= 0.55: risk_level = "high"
            elif seasonal_adjusted >= 0.35: risk_level = "medium"

            hourly_predictions.append({
                "hour": future_hour,
                "hour_offset": i + 1,
                "predicted_score": round(seasonal_adjusted, 4),
                "confidence": round(confidence, 3),
                "risk_level": risk_level,
                "forecast_time": (now + timedelta(hours=i+1)).isoformat()
            })

        # Peak prediction
        peak_idx = max(range(len(hourly_predictions)),
                       key=lambda i: hourly_predictions[i]["predicted_score"])
        peak_score = hourly_predictions[peak_idx]["predicted_score"]
        peak_hour = hourly_predictions[peak_idx]["hour"]

        # Trend analysis
        trend, strength = self._calculate_trend(series)
        momentum = self._momentum_score(series)

        # Overall risk
        avg_predicted = np.mean([p["predicted_score"] for p in hourly_predictions])
        if avg_predicted >= 0.7 or peak_score >= 0.85:
            overall_risk = "critical"
        elif avg_predicted >= 0.5 or peak_score >= 0.65:
            overall_risk = "high"
        elif avg_predicted >= 0.3 or peak_score >= 0.45:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        # Build summary and recommendations
        summary = self._build_summary(trend, strength, peak_score, peak_hour, avg_predicted, momentum)
        recommendations = self._build_recommendations(overall_risk, trend, peak_hour)

        forecast = ThreatForecast(
            generated_at=now,
            forecast_horizon_hours=self.forecast_hours,
            hourly_predictions=hourly_predictions,
            peak_threat_hour=peak_hour,
            peak_threat_score=round(peak_score, 4),
            overall_risk=overall_risk,
            trend=trend,
            trend_strength=strength,
            summary=summary,
            recommendations=recommendations
        )
        self._last_forecast = forecast
        return forecast

    def _empty_forecast(self) -> ThreatForecast:
        now = datetime.utcnow()
        return ThreatForecast(
            generated_at=now,
            forecast_horizon_hours=self.forecast_hours,
            hourly_predictions=[{
                "hour": (now.hour + i + 1) % 24,
                "hour_offset": i + 1,
                "predicted_score": 0.0,
                "confidence": 0.2,
                "risk_level": "low",
                "forecast_time": (now + timedelta(hours=i+1)).isoformat()
            } for i in range(self.forecast_hours)],
            peak_threat_hour=0,
            peak_threat_score=0.0,
            overall_risk="low",
            trend="stable",
            trend_strength=0.0,
            summary="Collecting baseline data — predictive model warming up.",
            recommendations=["Continue monitoring to build baseline data"]
        )

    @staticmethod
    def _build_summary(trend, strength, peak_score, peak_hour, avg, momentum):
        parts = [f"Threat level is {trend}"]
        if strength > 0.5:
            parts.append(f"with strong {trend} momentum")
        if peak_score >= 0.6:
            parts.append(f". Peak risk predicted at {peak_hour:02d}:00 UTC (score: {peak_score:.0%})")
        if momentum > 0.3:
            parts.append(". Short-term threat escalation detected")
        elif momentum < -0.3:
            parts.append(". Short-term threat de-escalation observed")
        return " ".join(parts) + "."

    @staticmethod
    def _build_recommendations(risk: str, trend: str, peak_hour: int) -> List[str]:
        recs = []
        if risk in ("critical", "high"):
            recs.append("Increase monitoring frequency and alert thresholds")
            recs.append(f"Prepare incident response for peak activity at {peak_hour:02d}:00 UTC")
        if trend == "increasing":
            recs.append("Review and update firewall rules proactively")
            recs.append("Ensure intrusion detection signatures are up to date")
        if risk == "critical":
            recs.append("Consider enabling automatic IP blocking for detected threats")
            recs.append("Notify security team of elevated threat forecast")
        if not recs:
            recs.append("Continue standard monitoring procedures")
        return recs

    def get_stats(self) -> Dict:
        return {
            "history_points": len(self.history),
            "hourly_bucket_coverage": sum(1 for v in self.hourly_buckets.values() if v),
            "last_forecast": self._last_forecast.generated_at.isoformat() if self._last_forecast else None,
            "current_trend": self._last_forecast.trend if self._last_forecast else "unknown",
            "overall_risk": self._last_forecast.overall_risk if self._last_forecast else "unknown",
        }


# Singleton
_predictor: Optional[ThreatPredictor] = None

def get_predictor() -> ThreatPredictor:
    global _predictor
    if _predictor is None:
        _predictor = ThreatPredictor()
    return _predictor
