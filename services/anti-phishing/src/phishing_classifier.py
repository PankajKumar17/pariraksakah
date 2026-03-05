"""
P07 — Phishing Classifier
Fine-tuned DistilBERT for email/message phishing detection.
Multi-label output: phishing, spear-phishing, BEC, legitimate.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("cybershield.antiphishing.classifier")

# ── Label schema ────────────────────────────────

PHISHING_LABELS = ["legitimate", "phishing", "spear_phishing", "bec"]
LABEL2ID = {l: i for i, l in enumerate(PHISHING_LABELS)}
ID2LABEL = {i: l for l, i in LABEL2ID.items()}


@dataclass
class ClassificationResult:
    label: str
    confidence: float
    probabilities: Dict[str, float]
    features_used: List[str]


class PhishingClassifier:
    """DistilBERT-based phishing classifier with confidence calibration."""

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.tokenizer = None
        self.model_path = model_path or "distilbert-base-uncased"
        self._loaded = False

    def load_model(self):
        """Lazy-load model to save memory at startup."""
        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_path,
                num_labels=len(PHISHING_LABELS),
                id2label=ID2LABEL,
                label2id=LABEL2ID,
            )
            self.model.eval()
            self._loaded = True
            logger.info("Phishing classifier loaded from %s", self.model_path)
        except Exception as e:
            logger.warning("Model load failed (%s), using heuristic fallback", e)
            self._loaded = False

    def _heuristic_classify(self, text: str) -> ClassificationResult:
        """Rule-based fallback when model is unavailable."""
        text_lower = text.lower()
        score = 0.0
        features = []

        urgency_words = ["urgent", "immediately", "suspended", "verify", "expire"]
        for w in urgency_words:
            if w in text_lower:
                score += 0.15
                features.append(f"urgency:{w}")

        credential_words = ["password", "ssn", "credit card", "account", "login"]
        for w in credential_words:
            if w in text_lower:
                score += 0.2
                features.append(f"credential_request:{w}")

        impersonation = ["ceo", "executive", "wire transfer", "invoice"]
        for w in impersonation:
            if w in text_lower:
                score += 0.15
                features.append(f"impersonation:{w}")

        if score > 0.6:
            label = "bec" if any("impersonation" in f for f in features) else "phishing"
        elif score > 0.3:
            label = "spear_phishing"
        else:
            label = "legitimate"

        probs = {l: 0.05 for l in PHISHING_LABELS}
        probs[label] = max(score, 0.5)
        total = sum(probs.values())
        probs = {k: v / total for k, v in probs.items()}

        return ClassificationResult(
            label=label, confidence=probs[label], probabilities=probs, features_used=features
        )

    def classify(self, text: str) -> ClassificationResult:
        """Classify an email/message as phishing, spear-phishing, BEC, or legit."""
        if not self._loaded:
            return self._heuristic_classify(text)

        import torch

        inputs = self.tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512, padding=True
        )
        with torch.no_grad():
            logits = self.model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).squeeze().numpy()
        idx = int(np.argmax(probs))

        prob_dict = {ID2LABEL[i]: float(probs[i]) for i in range(len(PHISHING_LABELS))}
        return ClassificationResult(
            label=ID2LABEL[idx],
            confidence=float(probs[idx]),
            probabilities=prob_dict,
            features_used=["distilbert_transformer"],
        )

    def classify_batch(self, texts: List[str]) -> List[ClassificationResult]:
        """Batch classification for throughput."""
        return [self.classify(t) for t in texts]


# ── Fine-tuning helper ──────────────────────────

def finetune_classifier(
    train_csv: str,
    output_dir: str = "ml-models/saved/phishing_classifier",
    epochs: int = 5,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
):
    """Fine-tune DistilBERT on a labelled phishing dataset CSV.

    CSV must have columns: text, label
    """
    import pandas as pd
    from datasets import Dataset
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    df = pd.read_csv(train_csv)
    df["label"] = df["label"].map(LABEL2ID)
    dataset = Dataset.from_pandas(df)
    splits = dataset.train_test_split(test_size=0.15, seed=42)

    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=512, padding="max_length")

    tokenized = splits.map(tokenize, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=len(PHISHING_LABELS),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=50,
    )

    trainer = Trainer(model=model, args=args, train_dataset=tokenized["train"], eval_dataset=tokenized["test"])
    trainer.train()
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info("Fine-tuned model saved to %s", output_dir)
