"""
P10 — ECG Signal Processor
Processes electrocardiogram signals for biometric identity verification.
Extracts R-peak intervals, heart-rate variability (HRV), and morphological
features that form a unique cardiac signature per user.
"""

import logging
from dataclasses import dataclass
from typing import List, Optional

import numpy as np

logger = logging.getLogger("cybershield.bioauth.ecg")


@dataclass
class ECGFeatures:
    rr_intervals: List[float]       # R-R intervals in ms
    mean_hr: float                  # Mean heart rate (bpm)
    sdnn: float                     # Standard deviation of NN intervals
    rmssd: float                    # Root mean square of successive differences
    pnn50: float                    # Percentage of successive RR > 50ms
    qrs_duration_ms: float          # Average QRS complex duration
    morphology_vector: List[float]  # 64-dim morphological embedding


class ECGProcessor:
    """Extracts biometric features from raw ECG signals."""

    def __init__(self, sample_rate: int = 500):
        self.sample_rate = sample_rate

    def process(self, signal: np.ndarray) -> ECGFeatures:
        """Extract biometric features from a raw ECG signal."""
        # Band-pass filter (0.5–40 Hz) — simplified
        filtered = self._bandpass_filter(signal)

        # R-peak detection (Pan-Tompkins simplified)
        r_peaks = self._detect_r_peaks(filtered)

        # RR intervals
        rr_intervals = np.diff(r_peaks) / self.sample_rate * 1000  # ms

        if len(rr_intervals) < 2:
            rr_intervals = np.array([800.0, 810.0])

        # HRV features
        mean_rr = np.mean(rr_intervals)
        mean_hr = 60000.0 / mean_rr if mean_rr > 0 else 70.0
        sdnn = float(np.std(rr_intervals))
        diffs = np.diff(rr_intervals)
        rmssd = float(np.sqrt(np.mean(diffs ** 2))) if len(diffs) > 0 else 0.0
        pnn50 = float(np.sum(np.abs(diffs) > 50) / len(diffs)) if len(diffs) > 0 else 0.0

        # QRS duration estimation
        qrs_dur = self._estimate_qrs_duration(filtered, r_peaks)

        # Morphological embedding (average beat template → 64-dim)
        morph = self._extract_morphology(filtered, r_peaks)

        return ECGFeatures(
            rr_intervals=rr_intervals.tolist(),
            mean_hr=float(mean_hr),
            sdnn=sdnn,
            rmssd=rmssd,
            pnn50=pnn50,
            qrs_duration_ms=qrs_dur,
            morphology_vector=morph.tolist(),
        )

    def _bandpass_filter(self, signal: np.ndarray) -> np.ndarray:
        """Simple band-pass using FFT (0.5–40 Hz)."""
        n = len(signal)
        freqs = np.fft.rfftfreq(n, 1.0 / self.sample_rate)
        fft = np.fft.rfft(signal)
        mask = (freqs >= 0.5) & (freqs <= 40)
        fft[~mask] = 0
        return np.fft.irfft(fft, n)

    def _detect_r_peaks(self, signal: np.ndarray) -> np.ndarray:
        """Simplified Pan-Tompkins R-peak detection."""
        # Differentiate
        diff = np.diff(signal)
        # Square
        squared = diff ** 2
        # Moving average window (~150ms)
        win = max(int(0.15 * self.sample_rate), 1)
        integrated = np.convolve(squared, np.ones(win) / win, mode="same")

        # Adaptive threshold
        threshold = 0.4 * np.max(integrated)
        peaks = []
        refractory = int(0.2 * self.sample_rate)  # 200ms refractory period

        i = 0
        while i < len(integrated):
            if integrated[i] > threshold:
                # Find local max in window
                end = min(i + refractory, len(integrated))
                local_max = i + np.argmax(integrated[i:end])
                peaks.append(local_max)
                i = local_max + refractory
            else:
                i += 1

        return np.array(peaks)

    def _estimate_qrs_duration(self, signal: np.ndarray, r_peaks: np.ndarray) -> float:
        """Estimate average QRS complex duration in ms."""
        if len(r_peaks) == 0:
            return 100.0
        durations = []
        half_win = int(0.06 * self.sample_rate)  # ~60ms each side
        for rp in r_peaks:
            start = max(0, rp - half_win)
            end = min(len(signal), rp + half_win)
            segment = signal[start:end]
            # QRS width ≈ points above 50% of peak amplitude
            peak_val = np.max(np.abs(segment))
            above = np.sum(np.abs(segment) > 0.5 * peak_val)
            dur_ms = above / self.sample_rate * 1000
            durations.append(dur_ms)
        return float(np.mean(durations))

    def _extract_morphology(self, signal: np.ndarray, r_peaks: np.ndarray) -> np.ndarray:
        """Extract 64-dimensional morphological embedding from averaged beats."""
        template_half = int(0.3 * self.sample_rate)  # 300ms each side
        beats = []
        for rp in r_peaks:
            start = rp - template_half
            end = rp + template_half
            if start >= 0 and end < len(signal):
                beat = signal[start:end]
                beats.append(beat)

        if len(beats) == 0:
            return np.zeros(64)

        # Average template
        avg_beat = np.mean(beats, axis=0)
        # Down-sample to 64 points
        indices = np.linspace(0, len(avg_beat) - 1, 64).astype(int)
        morphology = avg_beat[indices]
        # Normalize
        norm = np.linalg.norm(morphology)
        if norm > 0:
            morphology = morphology / norm
        return morphology
