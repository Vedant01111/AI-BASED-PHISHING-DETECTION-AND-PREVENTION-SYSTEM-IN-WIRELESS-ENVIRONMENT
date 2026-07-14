"""Retrain the URL phishing classifier on the UCI Mohammad dataset.

Run from repo root:
    python api/web_phishing/train_model.py

Writes a fresh pickle/model.pkl compatible with whatever scikit-learn version
this script runs under. Re-run whenever sklearn major-version-bumps break
deserialization of the existing pickle.

Dataset: UCI Phishing Websites (Rami Mohammad, 2015), 11055 rows x 30 features
+ binary Result label. The 30 features match FeatureExtraction in views.py
1-to-1 (same order, same {-1, 0, 1} coding).
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
from scipy.io import arff
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = REPO_ROOT / "api" / "web_phishing" / "data" / "phishing.arff"
MODEL_PATH = REPO_ROOT / "pickle" / "model.pkl"


def load_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    data, _ = arff.loadarff(str(path))
    raw = np.asarray(data.tolist())
    arr = raw.astype(int)
    X, y = arr[:, :-1], arr[:, -1]
    return X, y


def main() -> int:
    if not DATA_PATH.exists():
        sys.stderr.write(
            f"Dataset not found at {DATA_PATH}. Download the UCI Mohammad ARFF "
            "to that location first.\n"
        )
        return 1

    X, y = load_dataset(DATA_PATH)
    print(f"Dataset: {X.shape[0]} rows x {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = GradientBoostingClassifier(
        n_estimators=200, max_depth=4, random_state=42
    )
    clf.fit(X_train, y_train)

    train_acc = accuracy_score(y_train, clf.predict(X_train))
    test_acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"Train accuracy: {train_acc:.4f}")
    print(f"Test  accuracy: {test_acc:.4f}")
    print(classification_report(y_test, clf.predict(X_test), digits=4))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as fh:
        pickle.dump(clf, fh)
    print(f"Wrote {MODEL_PATH} ({MODEL_PATH.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
