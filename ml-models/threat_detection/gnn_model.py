"""
CyberShield-X — Graph Neural Network Threat Detection Model
3-layer Graph Attention Network (GAT) for binary threat classification
and multi-class attack-type prediction.

Architecture:
  Input (32-dim) → GATConv(128, 8-head) → GATConv(128, 8-head) → GATConv(128, 4-head)
  → MLP head → binary + 10-class output
Includes dropout (0.3), batch norm, residual connections,
weighted CrossEntropyLoss for imbalanced data, and per-class metrics.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import GATConv, BatchNorm, global_mean_pool  # type: ignore[import-untyped]
from torch_geometric.data import Data, Batch  # type: ignore[import-untyped]

logger = logging.getLogger("cybershield.ml.gnn_model")

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

INPUT_DIM = 32          # node feature dimension
HIDDEN_DIM = 128        # hidden layer width
NUM_HEADS_1 = 8         # attention heads layer 1-2
NUM_HEADS_3 = 4         # attention heads layer 3
DROPOUT = 0.3
NUM_ATTACK_CLASSES = 10 # multi-class attack types
EDGE_DIM = 4            # bytes, duration, frequency, time_delta

ATTACK_LABELS = [
    "BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet",
    "Infiltration", "WebAttack", "Ransomware", "C2", "Exfiltration",
]


# ──────────────────────────────────────────────
# GAT Block (with batch norm + residual skip)
# ──────────────────────────────────────────────

class GATBlock(nn.Module):
    """Single GAT layer wrapped with BatchNorm, residual connection, and dropout."""

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        heads: int = 8,
        edge_dim: int = EDGE_DIM,
        dropout: float = DROPOUT,
        concat: bool = True,
    ) -> None:
        super().__init__()
        self.gat = GATConv(
            in_channels,
            out_channels,
            heads=heads,
            edge_dim=edge_dim,
            dropout=dropout,
            concat=concat,
        )
        actual_out = out_channels * heads if concat else out_channels
        self.bn = BatchNorm(actual_out)
        self.dropout = nn.Dropout(dropout)

        # Residual projection if dimensions mismatch
        self.residual: Optional[nn.Linear] = None
        if in_channels != actual_out:
            self.residual = nn.Linear(in_channels, actual_out)

    def forward(
        self, x: Tensor, edge_index: Tensor, edge_attr: Optional[Tensor] = None
    ) -> Tensor:
        identity = x
        out = self.gat(x, edge_index, edge_attr=edge_attr)
        out = self.bn(out)
        out = F.elu(out)
        out = self.dropout(out)

        # Residual
        if self.residual is not None:
            identity = self.residual(identity)
        out = out + identity; return out


# ──────────────────────────────────────────────
# Main GNN Model
# ──────────────────────────────────────────────

class ThreatDetectionGNN(nn.Module):
    """3-layer GAT model for network threat detection.

    Parameters
    ----------
    in_dim : int
        Input node feature dimension (default 32).
    hidden_dim : int
        Hidden layer width (default 128).
    num_attack_classes : int
        Number of attack-type classes (default 10).
    edge_dim : int
        Edge feature dimension (default 4).
    dropout : float
        Dropout rate (default 0.3).

    Outputs
    -------
    binary_logits : Tensor [N, 2]
        Benign (0) vs Malicious (1).
    attack_logits : Tensor [N, num_attack_classes]
        Per-class attack type logits.
    """

    def __init__(
        self,
        in_dim: int = INPUT_DIM,
        hidden_dim: int = HIDDEN_DIM,
        num_attack_classes: int = NUM_ATTACK_CLASSES,
        edge_dim: int = EDGE_DIM,
        dropout: float = DROPOUT,
    ) -> None:
        super().__init__()

        # Input projection
        self.input_proj = nn.Linear(in_dim, hidden_dim)

        # 3 GAT blocks
        self.gat1 = GATBlock(hidden_dim, hidden_dim // NUM_HEADS_1, heads=NUM_HEADS_1, edge_dim=edge_dim, dropout=dropout)
        self.gat2 = GATBlock(hidden_dim, hidden_dim // NUM_HEADS_1, heads=NUM_HEADS_1, edge_dim=edge_dim, dropout=dropout)
        self.gat3 = GATBlock(hidden_dim, hidden_dim // NUM_HEADS_3, heads=NUM_HEADS_3, edge_dim=edge_dim, dropout=dropout, concat=True)

        gat3_out_dim = (hidden_dim // NUM_HEADS_3) * NUM_HEADS_3

        # Classification head — binary
        self.binary_head = nn.Sequential(
            nn.Linear(gat3_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 2),
        )

        # Classification head — attack type (multi-class)
        self.attack_head = nn.Sequential(
            nn.Linear(gat3_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_attack_classes),
        )

    def forward(
        self,
        x: Tensor,
        edge_index: Tensor,
        edge_attr: Optional[Tensor] = None,
        batch: Optional[Tensor] = None,
    ) -> Tuple[Tensor, Tensor]:
        """Forward pass.

        Parameters
        ----------
        x : Tensor [N, in_dim]
        edge_index : Tensor [2, E]
        edge_attr : Tensor [E, edge_dim], optional
        batch : Tensor [N], optional (for batched graphs)

        Returns
        -------
        binary_logits, attack_logits
        """
        x = F.elu(self.input_proj(x))
        x = self.gat1(x, edge_index, edge_attr)
        x = self.gat2(x, edge_index, edge_attr)
        x = self.gat3(x, edge_index, edge_attr)

        binary_logits = self.binary_head(x)
        attack_logits = self.attack_head(x)
        return binary_logits, attack_logits


# ──────────────────────────────────────────────
# Loss helper
# ──────────────────────────────────────────────

class ThreatDetectionLoss(nn.Module):
    """Combined weighted loss for binary + multi-class heads.

    Parameters
    ----------
    binary_weight : Tensor [2]
        Class weights for benign / malicious.
    attack_weight : Tensor [num_attack_classes]
        Class weights for each attack type.
    alpha : float
        Weighting factor for binary loss (default 0.4).
    """

    def __init__(
        self,
        binary_weight: Optional[Tensor] = None,
        attack_weight: Optional[Tensor] = None,
        alpha: float = 0.4,
    ) -> None:
        super().__init__()
        self.alpha = alpha
        self.binary_ce = nn.CrossEntropyLoss(weight=binary_weight)
        self.attack_ce = nn.CrossEntropyLoss(weight=attack_weight)

    def forward(
        self,
        binary_logits: Tensor,
        attack_logits: Tensor,
        binary_labels: Tensor,
        attack_labels: Tensor,
    ) -> Tuple[Tensor, Tensor, Tensor]:
        """Return (total_loss, binary_loss, attack_loss)."""
        b_loss = self.binary_ce(binary_logits, binary_labels)
        a_loss = self.attack_ce(attack_logits, attack_labels)
        total = self.alpha * b_loss + (1 - self.alpha) * a_loss
        return total, b_loss, a_loss


# ──────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────

@torch.no_grad()
def compute_metrics(
    binary_logits: Tensor,
    attack_logits: Tensor,
    binary_labels: Tensor,
    attack_labels: Tensor,
) -> dict:
    """Compute precision, recall, F1, and accuracy for both heads.

    Returns dict with keys like ``binary_accuracy``, ``attack_f1_macro``, etc.
    """
    from sklearn.metrics import (  # type: ignore[import-untyped]
        precision_recall_fscore_support,
        roc_auc_score,
        accuracy_score,
    )

    b_pred = binary_logits.argmax(dim=1).cpu().numpy()
    b_true = binary_labels.cpu().numpy()
    a_pred = attack_logits.argmax(dim=1).cpu().numpy()
    a_true = attack_labels.cpu().numpy()

    b_prec, b_rec, b_f1, _ = precision_recall_fscore_support(
        b_true, b_pred, average="binary", zero_division=0
    )
    a_prec, a_rec, a_f1, _ = precision_recall_fscore_support(
        a_true, a_pred, average="macro", zero_division=0
    )

    # ROC-AUC (binary)
    try:
        b_probs = F.softmax(binary_logits, dim=1)[:, 1].cpu().numpy()
        b_auc = roc_auc_score(b_true, b_probs)
    except ValueError:
        b_auc = 0.0

    return {
        "binary_accuracy": accuracy_score(b_true, b_pred),
        "binary_precision": b_prec,
        "binary_recall": b_rec,
        "binary_f1": b_f1,
        "binary_roc_auc": b_auc,
        "attack_accuracy": accuracy_score(a_true, a_pred),
        "attack_precision_macro": a_prec,
        "attack_recall_macro": a_rec,
        "attack_f1_macro": a_f1,
    }
