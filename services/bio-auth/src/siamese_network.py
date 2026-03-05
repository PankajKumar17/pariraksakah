"""
P10 — Siamese Neural Network for Biometric Verification
One-shot learning network with contrastive loss for biometric
template matching (ECG morphology, keystroke embeddings).
"""

import logging
from typing import Optional, Tuple

import numpy as np

logger = logging.getLogger("cybershield.bioauth.siamese")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# ── Contrastive Loss ────────────────────────────

if TORCH_AVAILABLE:

    class ContrastiveLoss(nn.Module):
        """Contrastive loss for Siamese networks.

        Same-class pairs → distance minimized.
        Different-class pairs → distance pushed beyond margin.
        """

        def __init__(self, margin: float = 2.0):
            super().__init__()
            self.margin = margin

        def forward(self, output1: torch.Tensor, output2: torch.Tensor, label: torch.Tensor) -> torch.Tensor:
            euclidean = F.pairwise_distance(output1, output2)
            loss = label * euclidean.pow(2) + \
                   (1 - label) * F.relu(self.margin - euclidean).pow(2)
            return loss.mean()

    # ── Siamese Network ────────────────────────

    class SiameseNetwork(nn.Module):
        """Twin-tower embedding network for biometric verification."""

        def __init__(self, input_dim: int = 64, embedding_dim: int = 32):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(128, 64),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, embedding_dim),
            )

        def forward_one(self, x: torch.Tensor) -> torch.Tensor:
            return self.encoder(x)

        def forward(self, x1: torch.Tensor, x2: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
            return self.forward_one(x1), self.forward_one(x2)

    # ── Trainer ─────────────────────────────────

    class SiameseTrainer:
        """Training loop for the Siamese biometric network."""

        def __init__(
            self,
            input_dim: int = 64,
            embedding_dim: int = 32,
            lr: float = 1e-3,
            margin: float = 2.0,
        ):
            self.model = SiameseNetwork(input_dim, embedding_dim)
            self.criterion = ContrastiveLoss(margin)
            self.optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)

        def train_epoch(self, pairs, labels) -> float:
            """Train one epoch. pairs: (N,2,D), labels: (N,) 1=same 0=diff."""
            self.model.train()
            x1 = torch.tensor(pairs[:, 0], dtype=torch.float32).to(self.device)
            x2 = torch.tensor(pairs[:, 1], dtype=torch.float32).to(self.device)
            y = torch.tensor(labels, dtype=torch.float32).to(self.device)

            self.optimizer.zero_grad()
            e1, e2 = self.model(x1, x2)
            loss = self.criterion(e1, e2, y)
            loss.backward()
            self.optimizer.step()
            return float(loss.item())

        def get_embedding(self, x: np.ndarray) -> np.ndarray:
            """Generate embedding vector for a biometric sample."""
            self.model.eval()
            with torch.no_grad():
                t = torch.tensor(x, dtype=torch.float32).unsqueeze(0).to(self.device)
                emb = self.model.forward_one(t)
            return emb.cpu().numpy().squeeze()

        def verify(self, template: np.ndarray, sample: np.ndarray, threshold: float = 1.0) -> Tuple[bool, float]:
            """Compare a stored template against a new sample."""
            e1 = self.get_embedding(template)
            e2 = self.get_embedding(sample)
            distance = float(np.linalg.norm(e1 - e2))
            return distance < threshold, distance


# ── Fallback for environments without torch ─────

class HeuristicSiamese:
    """Fallback biometric matcher using cosine similarity (no PyTorch needed)."""

    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold

    def get_embedding(self, x: np.ndarray) -> np.ndarray:
        """Normalize input as a crude 'embedding'."""
        norm = np.linalg.norm(x)
        return x / norm if norm > 0 else x

    def verify(self, template: np.ndarray, sample: np.ndarray) -> Tuple[bool, float]:
        e1 = self.get_embedding(template)
        e2 = self.get_embedding(sample)
        cosine_sim = float(np.dot(e1, e2))
        return cosine_sim >= self.threshold, cosine_sim
