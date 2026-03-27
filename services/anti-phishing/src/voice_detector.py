"""
P07 — Voice/Audio Deepfake Detector
Detects AI-generated voice in vishing (voice phishing) attacks using
MFCC feature extraction + lightweight CNN classifier.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import numpy as np

logger = logging.getLogger("cybershield.antiphishing.voice_detector")


@dataclass
class VoiceAnalysisResult:
    is_deepfake: bool
    confidence: float
    mfcc_anomaly_score: float
    spectral_features: dict


class VoiceDeepfakeDetector:
    """CNN-based deepfake voice detector using MFCC features."""

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path
        self._loaded = False

    def _fallback_mfcc(self, audio_data: np.ndarray) -> np.ndarray:
        """Lightweight FFT-based fallback when librosa is unavailable or fails at runtime."""
        n_fft = 512
        hop = 160
        frames = max((len(audio_data) - n_fft) // hop + 1, 1)
        mfccs = np.zeros((40, frames))
        for i in range(frames):
            start = i * hop
            frame = audio_data[start:start + n_fft]
            if len(frame) < n_fft:
                frame = np.pad(frame, (0, n_fft - len(frame)))
            spectrum = np.abs(np.fft.rfft(frame))[:40]
            mfccs[:len(spectrum), i] = np.log1p(spectrum)
        return mfccs

    def load_model(self):
        """Load pre-trained deepfake detection model."""
        try:
            import torch
            import torch.nn as nn

            class DeepfakeCNN(nn.Module):
                def __init__(self):
                    super().__init__()
                    self.features = nn.Sequential(
                        nn.Conv2d(1, 32, kernel_size=3, padding=1),
                        nn.ReLU(),
                        nn.MaxPool2d(2),
                        nn.Conv2d(32, 64, kernel_size=3, padding=1),
                        nn.ReLU(),
                        nn.MaxPool2d(2),
                        nn.Conv2d(64, 128, kernel_size=3, padding=1),
                        nn.ReLU(),
                        nn.AdaptiveAvgPool2d((4, 4)),
                    )
                    self.classifier = nn.Sequential(
                        nn.Linear(128 * 4 * 4, 256),
                        nn.ReLU(),
                        nn.Dropout(0.3),
                        nn.Linear(256, 2),  # [genuine, deepfake]
                    )

                def forward(self, x):
                    x = self.features(x)
                    x = x.view(x.size(0), -1)
                    return self.classifier(x)

            self.model = DeepfakeCNN()
            if self.model_path:
                state = torch.load(self.model_path, map_location="cpu")
                self.model.load_state_dict(state)
            self.model.eval()
            self._loaded = True
            logger.info("Voice deepfake CNN loaded")
        except Exception as e:
            logger.warning("Model load failed: %s — using heuristic", e)

    def extract_mfcc(self, audio_data: np.ndarray, sample_rate: int = 16000) -> np.ndarray:
        """Extract MFCC features from raw audio samples."""
        if audio_data.size == 0:
            return np.zeros((40, 1))
        try:
            import librosa
            mfccs = librosa.feature.mfcc(y=audio_data.astype(float), sr=sample_rate, n_mfcc=40)
            return mfccs
        except Exception as e:
            logger.warning("MFCC extraction fallback engaged: %s", e)
            return self._fallback_mfcc(audio_data)

    def _compute_spectral_features(self, audio_data: np.ndarray, sr: int = 16000) -> dict:
        """Compute spectral features that differ between real and synthetic speech."""
        if audio_data.size == 0:
            return {
                "spectral_centroid": 0.0,
                "spectral_rolloff": 0.0,
                "spectral_flatness": 0.0,
                "zero_crossing_rate": 0.0,
            }
        spectrum = np.abs(np.fft.rfft(audio_data))
        freqs = np.fft.rfftfreq(len(audio_data), 1.0 / sr)

        spectral_centroid = np.sum(freqs * spectrum) / (np.sum(spectrum) + 1e-10)
        spectral_rolloff = freqs[np.searchsorted(np.cumsum(spectrum), 0.85 * np.sum(spectrum))]
        spectral_flatness = np.exp(np.mean(np.log(spectrum + 1e-10))) / (np.mean(spectrum) + 1e-10)

        return {
            "spectral_centroid": float(spectral_centroid),
            "spectral_rolloff": float(spectral_rolloff),
            "spectral_flatness": float(spectral_flatness),
            "zero_crossing_rate": float(np.mean(np.abs(np.diff(np.sign(audio_data))))),
        }

    def analyze(self, audio_data: np.ndarray, sample_rate: int = 16000) -> VoiceAnalysisResult:
        """Analyze audio for deepfake indicators."""
        mfccs = self.extract_mfcc(audio_data, sample_rate)
        spectral = self._compute_spectral_features(audio_data, sample_rate)

        # MFCC anomaly: deepfakes often have unnaturally smooth MFCCs
        mfcc_variance = np.var(mfccs, axis=1).mean()
        mfcc_anomaly = 1.0 / (1.0 + mfcc_variance)  # Low variance → higher anomaly

        if self._loaded and self.model is not None:
            import torch
            # Reshape MFCCs for CNN: (1, 1, n_mfcc, n_frames)
            mfcc_tensor = torch.tensor(mfccs, dtype=torch.float32).unsqueeze(0).unsqueeze(0)
            with torch.no_grad():
                logits = self.model(mfcc_tensor)
                probs = torch.softmax(logits, dim=-1).squeeze()
            deepfake_prob = float(probs[1])
        else:
            # Heuristic: combine spectral features
            deepfake_prob = 0.0
            if spectral["spectral_flatness"] > 0.5:
                deepfake_prob += 0.3
            if mfcc_anomaly > 0.7:
                deepfake_prob += 0.3
            if spectral["zero_crossing_rate"] < 0.05:
                deepfake_prob += 0.2

        return VoiceAnalysisResult(
            is_deepfake=deepfake_prob >= 0.5,
            confidence=max(deepfake_prob, 1 - deepfake_prob),
            mfcc_anomaly_score=float(mfcc_anomaly),
            spectral_features=spectral,
        )
