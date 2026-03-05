"""
CyberShield-X — ML Training Pipeline
Trains GNN and UEBA models, logs to MLflow, and saves checkpoints.

Usage:
    python -m ml_models.threat_detection.trainer
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import mlflow
import mlflow.pytorch
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split  # type: ignore[import-untyped]
from sklearn.preprocessing import LabelEncoder, StandardScaler  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    classification_report,
    confusion_matrix,
)
from torch_geometric.data import Data  # type: ignore[import-untyped]

from .gnn_model import ThreatDetectionGNN, ThreatDetectionLoss, compute_metrics, ATTACK_LABELS
from .ueba_model import (
    UEBAAutoencoder,
    IsolationForestDetector,
    DynamicThreshold,
    UEBAEnsembleDetector,
)

logger = logging.getLogger("cybershield.ml.trainer")

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = PROJECT_ROOT / "datasets"
SAVED_DIR = PROJECT_ROOT / "ml-models" / "saved"

NETWORK_CSV = DATASET_DIR / "network_intrusion.csv"
UEBA_CSV = DATASET_DIR / "ueba_behavior.csv"

# ──────────────────────────────────────────────
# Device
# ──────────────────────────────────────────────

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ╔════════════════════════════════════════════╗
# ║          GNN TRAINING                      ║
# ╚════════════════════════════════════════════╝

def _prepare_gnn_data(csv_path: Path):
    """Load network intrusion CSV and build PyG Data objects.

    Returns
    -------
    train_data, val_data, test_data, class_weights_binary, class_weights_attack
    """
    df = pd.read_csv(csv_path)
    logger.info("Loaded %d rows from %s", len(df), csv_path.name)

    # Encode attack type
    atk_encoder = LabelEncoder()
    df["attack_label"] = atk_encoder.fit_transform(df["attack_type"])
    binary_labels = df["is_attack"].astype(int).values
    attack_labels = df["attack_label"].values

    # Select numeric features for node embeddings
    feature_cols = [
        c for c in df.columns
        if df[c].dtype in ("float64", "int64", "float32", "int32")
        and c not in ("is_attack", "attack_label", "source_port", "destination_port")
    ][:32]  # limit to 32 features for input_dim

    scaler = StandardScaler()
    X = scaler.fit_transform(df[feature_cols].fillna(0).values).astype(np.float32)

    # Pad to 32 dims if needed
    if X.shape[1] < 32:
        X = np.pad(X, ((0, 0), (0, 32 - X.shape[1])))

    # Stratified split: 70/15/15
    idx = np.arange(len(df))
    idx_train, idx_temp, y_train_b, y_temp_b = train_test_split(
        idx, binary_labels, test_size=0.30, stratify=binary_labels, random_state=42
    )
    idx_val, idx_test, _, _ = train_test_split(
        idx_temp, y_temp_b, test_size=0.50, stratify=y_temp_b, random_state=42
    )

    def _build_pyg(indices):
        x = torch.tensor(X[indices], dtype=torch.float)
        bl = torch.tensor(binary_labels[indices], dtype=torch.long)
        al = torch.tensor(attack_labels[indices], dtype=torch.long)

        # Build k-NN graph (k=5) as proxy for network-entity graph
        from torch_geometric.nn import knn_graph  # type: ignore[import-untyped]
        edge_index = knn_graph(x, k=5, loop=False)
        # Edge features: pairwise differences on first 4 features
        src, dst = edge_index
        edge_attr = torch.abs(x[src, :4] - x[dst, :4])
        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr,
                    binary_y=bl, attack_y=al)

    train_data = _build_pyg(idx_train)
    val_data = _build_pyg(idx_val)
    test_data = _build_pyg(idx_test)

    # Class weights (inverse frequency)
    from sklearn.utils.class_weight import compute_class_weight  # type: ignore[import-untyped]
    bw = compute_class_weight("balanced", classes=np.array([0, 1]), y=binary_labels[idx_train])
    aw_classes = np.unique(attack_labels[idx_train])
    aw = compute_class_weight("balanced", classes=aw_classes, y=attack_labels[idx_train])
    # Pad if fewer classes than expected
    full_aw = np.ones(len(ATTACK_LABELS))
    for ci, w in zip(aw_classes, aw):
        if ci < len(full_aw):
            full_aw[ci] = w

    return (
        train_data.to(DEVICE),
        val_data.to(DEVICE),
        test_data.to(DEVICE),
        torch.tensor(bw, dtype=torch.float, device=DEVICE),
        torch.tensor(full_aw, dtype=torch.float, device=DEVICE),
    )


def train_gnn(
    epochs: int = 200,
    patience: int = 10,
    lr: float = 1e-3,
) -> ThreatDetectionGNN:
    """Train the GNN threat detection model.

    Returns the trained model.
    """
    logger.info("Preparing GNN data…")
    train_d, val_d, test_d, bw, aw = _prepare_gnn_data(NETWORK_CSV)

    model = ThreatDetectionGNN().to(DEVICE)
    criterion = ThreatDetectionLoss(binary_weight=bw, attack_weight=aw)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", patience=5, factor=0.5)

    best_val_loss = float("inf")
    epochs_no_improve = 0
    best_state = None

    mlflow.set_experiment("cybershield-gnn")
    with mlflow.start_run(run_name="gnn-training"):
        mlflow.log_params({"epochs": epochs, "patience": patience, "lr": lr})

        for epoch in range(1, epochs + 1):
            # ── Train ──
            model.train()
            optimizer.zero_grad()
            b_logits, a_logits = model(
                train_d.x, train_d.edge_index, train_d.edge_attr
            )
            loss, b_loss, a_loss = criterion(
                b_logits, a_logits, train_d.binary_y, train_d.attack_y
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            # ── Validate ──
            model.eval()
            with torch.no_grad():
                vb, va = model(val_d.x, val_d.edge_index, val_d.edge_attr)
                val_loss, _, _ = criterion(vb, va, val_d.binary_y, val_d.attack_y)
                val_metrics = compute_metrics(vb, va, val_d.binary_y, val_d.attack_y)

            scheduler.step(val_loss)

            mlflow.log_metrics(
                {
                    "train_loss": loss.item(),
                    "val_loss": val_loss.item(),
                    **{f"val_{k}": v for k, v in val_metrics.items()},
                },
                step=epoch,
            )

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "Epoch %03d | train_loss=%.4f | val_loss=%.4f | val_binary_f1=%.4f",
                    epoch, loss.item(), val_loss.item(), val_metrics["binary_f1"],
                )

            # Early stopping
            if val_loss.item() < best_val_loss:
                best_val_loss = val_loss.item()
                epochs_no_improve = 0
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    logger.info("Early stopping at epoch %d", epoch)
                    break

        # Load best checkpoint
        if best_state:
            model.load_state_dict(best_state)
            model.to(DEVICE)

        # ── Test ──
        model.eval()
        with torch.no_grad():
            tb, ta = model(test_d.x, test_d.edge_index, test_d.edge_attr)
            test_metrics = compute_metrics(tb, ta, test_d.binary_y, test_d.attack_y)

        mlflow.log_metrics({f"test_{k}": v for k, v in test_metrics.items()})

        # Classification report
        b_pred = tb.argmax(dim=1).cpu().numpy()
        a_pred = ta.argmax(dim=1).cpu().numpy()
        report = classification_report(
            test_d.binary_y.cpu().numpy(), b_pred, target_names=["BENIGN", "MALICIOUS"]
        )
        logger.info("Binary classification report:\n%s", report)

        cm = confusion_matrix(test_d.binary_y.cpu().numpy(), b_pred)
        logger.info("Confusion matrix:\n%s", cm)

        # Save model
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        save_path = SAVED_DIR / "gnn_threat_detection.pt"
        torch.save(model.state_dict(), save_path)
        mlflow.pytorch.log_model(model, "gnn_model")
        logger.info("GNN model saved to %s", save_path)

    return model


# ╔════════════════════════════════════════════╗
# ║          UEBA TRAINING                     ║
# ╚════════════════════════════════════════════╝

def _prepare_ueba_data(csv_path: Path):
    """Load UEBA CSV and prepare train/val/test splits.

    Returns
    -------
    X_train, X_val, X_test, y_train, y_val, y_test, scaler
    """
    df = pd.read_csv(csv_path)
    logger.info("Loaded %d rows from %s", len(df), csv_path.name)

    # Separate labels
    label_col = "threat_category" if "threat_category" in df.columns else "label"
    y = (df[label_col] != "CLEAN").astype(int).values

    # Numeric features only
    feature_cols = [
        c for c in df.columns
        if df[c].dtype in ("float64", "int64", "float32", "int32")
        and c not in ("is_threat",)
    ]
    X_raw = df[feature_cols].fillna(0).values.astype(np.float32)

    # Pad to 50 dims
    if X_raw.shape[1] < 50:
        X_raw = np.pad(X_raw, ((0, 0), (0, 50 - X_raw.shape[1])))
    elif X_raw.shape[1] > 50:
        X_raw = X_raw[:, :50]

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    # Stratified split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )

    return X_train, X_val, X_test, y_train, y_val, y_test, scaler


def train_ueba(
    epochs: int = 100,
    patience: int = 10,
    lr: float = 1e-3,
    batch_size: int = 128,
) -> UEBAEnsembleDetector:
    """Train UEBA autoencoder + Isolation Forest.

    Returns the ensemble detector.
    """
    logger.info("Preparing UEBA data…")
    X_train, X_val, X_test, y_train, y_val, y_test, scaler = _prepare_ueba_data(UEBA_CSV)

    # ── Train autoencoder on *normal* samples only ──
    X_train_normal = X_train[y_train == 0]
    train_tensor = torch.tensor(X_train_normal, dtype=torch.float, device=DEVICE)
    val_tensor = torch.tensor(X_val, dtype=torch.float, device=DEVICE)

    train_ds = TensorDataset(train_tensor, train_tensor)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    model = UEBAAutoencoder(input_dim=50).to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", patience=5, factor=0.5)
    criterion = nn.MSELoss()

    best_val_loss = float("inf")
    epochs_no_improve = 0
    best_state = None

    mlflow.set_experiment("cybershield-ueba")
    with mlflow.start_run(run_name="ueba-training"):
        mlflow.log_params({
            "epochs": epochs, "patience": patience, "lr": lr,
            "batch_size": batch_size, "train_normal_samples": len(X_train_normal),
        })

        for epoch in range(1, epochs + 1):
            model.train()
            epoch_loss = 0.0
            for batch_x, _ in train_loader:
                optimizer.zero_grad()
                recon, _ = model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
            epoch_loss /= len(train_tensor)

            # Validation
            model.eval()
            with torch.no_grad():
                val_recon, _ = model(val_tensor)
                val_loss = criterion(val_recon, val_tensor).item()

            scheduler.step(val_loss)
            mlflow.log_metrics(
                {"train_loss": epoch_loss, "val_loss": val_loss}, step=epoch
            )

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "UEBA Epoch %03d | train_loss=%.6f | val_loss=%.6f",
                    epoch, epoch_loss, val_loss,
                )

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                epochs_no_improve = 0
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    logger.info("UEBA early stopping at epoch %d", epoch)
                    break

        if best_state:
            model.load_state_dict(best_state)
            model.to(DEVICE)

        # ── Train Isolation Forest ──
        iso = IsolationForestDetector(contamination=0.05)
        iso.fit(X_train)

        # ── Build ensemble ──
        threshold = DynamicThreshold(window_size=1000, factor=3.0)
        ensemble = UEBAEnsembleDetector(
            autoencoder=model, iso_forest=iso, threshold=threshold
        )

        # ── Evaluate on test set ──
        test_tensor = torch.tensor(X_test, dtype=torch.float, device=DEVICE)
        results = ensemble.detect(test_tensor)
        predicted = results["is_anomaly"].astype(int)
        report = classification_report(
            y_test, predicted, target_names=["NORMAL", "ANOMALY"], zero_division=0
        )
        logger.info("UEBA test classification report:\n%s", report)

        from sklearn.metrics import precision_score, recall_score, f1_score  # type: ignore
        metrics = {
            "test_precision": precision_score(y_test, predicted, zero_division=0),
            "test_recall": recall_score(y_test, predicted, zero_division=0),
            "test_f1": f1_score(y_test, predicted, zero_division=0),
        }
        mlflow.log_metrics(metrics)

        # ── Save ──
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        ae_path = SAVED_DIR / "ueba_autoencoder.pt"
        torch.save(model.state_dict(), ae_path)
        mlflow.pytorch.log_model(model, "ueba_autoencoder")
        logger.info("UEBA autoencoder saved to %s", ae_path)

    return ensemble


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

def main() -> None:
    """Train both GNN and UEBA models."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    mlflow.set_tracking_uri("http://mlflow:5000")

    logger.info("═══ Training GNN Threat Detection ═══")
    train_gnn()

    logger.info("═══ Training UEBA Anomaly Detection ═══")
    train_ueba()

    logger.info("All models trained successfully.")


if __name__ == "__main__":
    main()
