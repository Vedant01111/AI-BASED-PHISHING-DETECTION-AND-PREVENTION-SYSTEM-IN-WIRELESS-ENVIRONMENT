"""Train the shared email body classifier from spam_mails.csv.

Run from repo root:
    python api/email_phishing/train_model.py

Writes pickle/email_model.joblib (TF-IDF + LogisticRegression). joblib.dump
is used (not raw pickle) so retraining on a newer sklearn produces a model
the same library version can load back.
"""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "spam_mails.csv"
MODEL_PATH = REPO_ROOT / "pickle" / "email_model.joblib"


def main() -> int:
    if not CSV_PATH.exists():
        sys.stderr.write(f"Dataset not found at {CSV_PATH}\n")
        return 1

    df = pd.read_csv(CSV_PATH)
    df = df.dropna(subset=["Email Text", "Email Type"]).copy()
    df["Email Text"] = df["Email Text"].astype(str).str.strip()
    df = df[df["Email Text"].str.len() > 0]

    # CSV: 1 = legit, 0 = phishing. We want P(phishing) = 1, so invert.
    X = df["Email Text"].values
    y = (df["Email Type"].astype(int) == 0).astype(int).values

    print(f"Dataset: {len(X):,} rows. Phishing: {int(y.sum()):,}  Legit: {int((y == 0).sum()):,}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                max_features=50_000,
                min_df=2,
                sublinear_tf=True,
                lowercase=True,
                strip_accents="unicode",
            )),
            ("char", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                max_features=50_000,
                min_df=2,
                sublinear_tf=True,
                lowercase=True,
            )),
        ])),
        ("classifier", LogisticRegression(
            C=4.0,
            max_iter=1000,
            class_weight="balanced",
            solver="liblinear",
        )),
    ])
    pipeline.fit(X_train, y_train)

    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print(f"ROC-AUC : {roc_auc_score(y_test, proba):.4f}")
    print(classification_report(y_test, pred, target_names=["legit", "phishing"], digits=4))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    size_kb = MODEL_PATH.stat().st_size / 1024
    print(f"Wrote {MODEL_PATH} ({size_kb:,.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
