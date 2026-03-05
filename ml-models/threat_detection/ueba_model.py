"""
CyberShield-X — UEBA Anomaly Detection Model
Autoencoder-based unsupervised anomaly detection with Isolation Forest
as a secondary detector.

Architecture:
  Encoder: 50 → 32 → 16 → 8 (bottleneck)
  Decoder: 8 → 16 → 32 → 50
  Anomaly score = MSE reconstruction error.
  Dynamic threshold = rolling mean + 3 × std.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch import Tensor

logger = logging.getLogger("cybershield.ml.ueba_model")

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

INPUT_DIM = 50          # user behaviour feature vector length
BOTTLENECK_DIM = 8
THRESHOLD_STD_FACTOR = 3.0


# ──────────────────────────────────────────────
# Autoencoder
# ──────────────────────────────────────────────

class UEBAAutoencoder(nn.Module):
    """Autoencoder for user-entity behaviour anomaly detection.

    Parameters
    ----------
    input_dim : int
        Feature vector length (default 50).
    bottleneck_dim : int
        Latent bottleneck dimension (default 8).
    dropout : float
        Dropout rate (default 0.2).
    """

    def __init__(
        self,
        input_dim: int = INPUT_DIM,
        bottleneck_dim: int = BOTTLENECK_DIM,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, bottleneck_dim),
        )

        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: Tensor) -> Tuple[Tensor, Tensor]:
        """Forward pass.

        Returns
        -------
        reconstructed : Tensor
            Reconstructed input.
        latent : Tensor
            Bottleneck representation.
        """
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed, latent

    def encode(self, x: Tensor) -> Tensor:
        """Encode input to latent space."""
        return self.encoder(x)

    def reconstruction_error(self, x: Tensor) -> Tensor:
        """Compute per-sample MSE reconstruction error.

        Parameters
        ----------
        x : Tensor [B, input_dim]

        Returns
        -------
        errors : Tensor [B]
        """
        reconstructed, _ = self.forward(x)
        return ((x - reconstructed) ** 2).mean(dim=1)


# ──────────────────────────────────────────────
# Dynamic Threshold
# ──────────────────────────────────────────────

class DynamicThreshold:
    """Rolling-window dynamic anomaly threshold.

    threshold = rolling_mean + factor * rolling_std

    Parameters
    ----------
    window_size : int
        Number of recent scores to keep (default 1000).
    factor : float
        Standard deviation multiplier (default 3.0).
    """

    def __init__(
        self,
        window_size: int = 1000,
        factor: float = THRESHOLD_STD_FACTOR,
    ) -> None:
        self._window_size = window_size
        self._factor = factor
        self._scores: list[float] = []

    def update(self, scores: list[float] | np.ndarray) -> None:
        """Add new scores to the rolling window."""
        self._scores.extend(scores if isinstance(scores, list) else scores.tolist())
        if len(self._scores) > self._window_size:
            self._scores = self._scores[-self._window_size:]

    @property
    def threshold(self) -> float:
        """Current anomaly threshold."""
        if len(self._scores) < 2:
            return float("inf")
        arr = np.array(self._scores)
        return float(arr.mean() + self._factor * arr.std())

    def is_anomaly(self, score: float) -> bool:
        """Check if a score exceeds the dynamic threshold."""
        return score > self.threshold

    def batch_detect(self, scores: np.ndarray) -> np.ndarray:
        """Return boolean mask of anomalies for a batch of scores."""
        return scores > self.threshold


# ──────────────────────────────────────────────
# Isolation Forest wrapper
# ──────────────────────────────────────────────

class IsolationForestDetector:
    """Isolation Forest secondary anomaly detector.

    Parameters
    ----------
    contamination : float
        Expected fraction of anomalies (default 0.05).
    n_estimators : int
        Number of trees (default 200).
    random_state : int
        Reproducibility seed (default 42).
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self._fitted = False

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        """Fit on normal behaviour features.

        Parameters
        ----------
        X : ndarray [N, features]
        """
        self._model.fit(X)
        self._fitted = True
        logger.info("IsolationForest fitted on %d samples", X.shape[0])
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly labels: -1 = anomaly, 1 = normal."""
        if not self._fitted:
            raise RuntimeError("IsolationForest not fitted yet.")
        return self._model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores (lower = more anomalous)."""
        if not self._fitted:
            raise RuntimeError("IsolationForest not fitted yet.")
        return self._model.score_samples(X)


# ──────────────────────────────────────────────
# Ensemble detector
# ──────────────────────────────────────────────

class UEBAEnsembleDetector:
    """Combined autoencoder + Isolation Forest detector.

    Parameters
    ----------
    autoencoder : UEBAAutoencoder
        Trained autoencoder model.
    iso_forest : IsolationForestDetector
        Trained Isolation Forest.
    threshold : DynamicThreshold
        Dynamic threshold for autoencoder scores.
    ae_weight : float
        Weight for autoencoder anomaly (default 0.6).
    """

    def __init__(
        self,
        autoencoder: UEBAAutoencoder,
        iso_forest: IsolationForestDetector,
        threshold: DynamicThreshold,
        ae_weight: float = 0.6,
    ) -> None:
        self.autoencoder = autoencoder
        self.iso_forest = iso_forest
        self.threshold = threshold
        self.ae_weight = ae_weight

    @torch.no_grad()
    def detect(self, x: Tensor) -> dict:
        """Run combined detection on a batch of user-behaviour vectors.

        Parameters
        ----------
        x : Tensor [B, input_dim]

        Returns
        -------
        dict with keys:
            anomaly_scores : ndarray [B]
            is_anomaly : ndarray [B] (bool)
            ae_scores : ndarray [B]
            iso_scores : ndarray [B]
        """
        self.autoencoder.eval()
        ae_errors = self.autoencoder.reconstruction_error(x).cpu().numpy()

        x_np = x.cpu().numpy()
        iso_scores = self.iso_forest.score_samples(x_np)
        # Normalise iso_score to [0, 1] range (higher = more anomalous)
        iso_norm = 1 - (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-10)

        # Normalise ae_errors to [0, 1]
        ae_norm = (ae_errors - ae_errors.min()) / (ae_errors.max() - ae_errors.min() + 1e-10)

        combined = self.ae_weight * ae_norm + (1 - self.ae_weight) * iso_norm
        self.threshold.update(combined.tolist())
        is_anomaly = self.threshold.batch_detect(combined)

        return {
            "anomaly_scores": combined,
            "is_anomaly": is_anomaly,
            "ae_scores": ae_errors,
            "iso_scores": iso_scores,
        }
