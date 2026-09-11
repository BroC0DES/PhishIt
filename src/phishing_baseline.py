"""
Phishing Email Detection — Phase 1 Baseline
============================================
Automatically combines all 7 CSVs and trains a Random Forest classifier.
"""

import re
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from imblearn.over_sampling import SMOTE


# ---------------------------------------------------------------------------
# STEP 1: LOAD AND COMBINE ALL 7 CSV FILES
# ---------------------------------------------------------------------------

def load_all(folder="."):
    files = [
        "CEAS_08.csv",
        "Enron.csv",
        "Ling.csv",
        "Nazario.csv",
        "Nigerian_Fraud.csv",
        "phishing_email.csv",
        "SpamAssasin.csv"
    ]

    dfs = []
    for f in files:
        path = f"{folder}/{f}"
        try:
            df = pd.read_csv(path, usecols=["subject", "body", "label"])
            df["source"] = f
            dfs.append(df)
            print(f"Loaded {f}: {len(df)} rows")
        except Exception as e:
            print(f"Skipped {f}: {e}")

    combined = pd.concat(dfs, ignore_index=True)
    combined["subject"] = combined["subject"].fillna("")
    combined["body"] = combined["body"].fillna("")
    combined["label"] = combined["label"].astype(int)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nTotal emails loaded: {len(combined)}")
    print(f"Legit (0): {(combined['label'] == 0).sum()}")
    print(f"Phishing (1): {(combined['label'] == 1).sum()}")
    return combined


# ---------------------------------------------------------------------------
# STEP 2: EXTRACT HAND-CRAFTED FEATURES
# ---------------------------------------------------------------------------

URGENCY_WORDS = [
    "urgent", "immediately", "verify now", "act now", "account suspended",
    "limited time", "expire", "click here now", "confirm your account",
    "unauthorized", "suspicious activity", "final notice",
]
GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear member"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")


def extract_features(df):
    feats = pd.DataFrame(index=df.index)
    full_text = (df["subject"] + " " + df["body"]).str.lower()

    feats["urgency_count"] = full_text.apply(
        lambda t: sum(t.count(w) for w in URGENCY_WORDS))
    feats["generic_greeting"] = full_text.apply(
        lambda t: int(any(g in t for g in GENERIC_GREETINGS)))

    def url_stats(t):
        urls = URL_REGEX.findall(t)
        shortened = sum(1 for u in urls if any(s in u for s in SHORTENER_DOMAINS))
        return len(urls), shortened

    url_results = full_text.apply(url_stats)
    feats["url_count"] = url_results.apply(lambda x: x[0])
    feats["shortened_url_count"] = url_results.apply(lambda x: x[1])

    feats["subject_length"] = df["subject"].apply(len)
    feats["subject_punct_ratio"] = df["subject"].apply(
        lambda s: sum(1 for c in s if c in "!?$%") / max(len(s), 1))

    return feats


# ---------------------------------------------------------------------------
# STEP 3: TFIDF + COMBINE + SMOTE + TRAIN + EVALUATE
# ---------------------------------------------------------------------------

def train_and_evaluate(df):
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df, df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    print("\nRunning TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english")
    train_tfidf = vectorizer.fit_transform(X_train_df["subject"] + " " + X_train_df["body"])
    test_tfidf = vectorizer.transform(X_test_df["subject"] + " " + X_test_df["body"])

    print("Extracting hand-crafted features...")
    train_hand = csr_matrix(extract_features(X_train_df).values.astype(float))
    test_hand = csr_matrix(extract_features(X_test_df).values.astype(float))

    X_train = hstack([train_tfidf, train_hand]).tocsr()
    X_test = hstack([test_tfidf, test_hand]).tocsr()

    print(f"\nBefore SMOTE: {np.bincount(y_train)}")
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
    print(f"After SMOTE:  {np.bincount(y_train_res)}")

    print("\nTraining Random Forest... (this takes 2-3 minutes)")
    clf = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)
    clf.fit(X_train_res, y_train_res)

    y_pred = clf.predict(X_test)

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn)
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")

    joblib.dump(clf, "phishing_model.joblib")
    joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
    print("\nSaved: phishing_model.joblib")
    print("Saved: tfidf_vectorizer.joblib")


# ---------------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    df = load_all(folder=".")
    train_and_evaluate(df)