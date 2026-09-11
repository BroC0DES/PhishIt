import joblib
import re
import numpy as np
from scipy.sparse import hstack, csr_matrix

model = joblib.load("phishing_model.joblib")
vectorizer = joblib.load("tfidf_vectorizer.joblib")

URGENCY_WORDS = ["urgent", "immediately", "verify now", "act now",
                 "account suspended", "limited time", "click here now",
                 "confirm your account", "unauthorized", "suspicious activity",
                 "final notice", "expire"]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear member"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")


def predict(subject, body):
    text = (subject + " " + body).lower()

    # TF-IDF on text
    tfidf = vectorizer.transform([subject + " " + body])

    # 6 hand-crafted features (must match training exactly)
    urgency_count = sum(text.count(w) for w in URGENCY_WORDS)
    generic_greeting = int(any(g in text for g in GENERIC_GREETINGS))
    urls = URL_REGEX.findall(text)
    url_count = len(urls)
    shortened_url_count = sum(1 for u in urls if any(s in u for s in SHORTENER_DOMAINS))
    subject_length = len(subject)
    subject_punct_ratio = sum(1 for c in subject if c in "!?$%") / max(len(subject), 1)

    hand_feats = csr_matrix(np.array([[
        urgency_count,
        generic_greeting,
        url_count,
        shortened_url_count,
        subject_length,
        subject_punct_ratio
    ]], dtype=float))

    # Combine TF-IDF + hand features (same as training)
    X = hstack([tfidf, hand_feats]).tocsr()

    prob = model.predict_proba(X)[0][1]

    return {
        "phishing_score": round(prob, 3),
        "verdict": "PHISHING" if prob > 0.5 else "LEGIT",
        "triggers": {
            "urgency_words_found": urgency_count,
            "urls_found": url_count,
            "generic_greeting": bool(generic_greeting)
        }
    }


# Test it
result = predict(
    subject="Urgent: Your account will be suspended",
    body="Click here immediately to verify your account or it will be deleted."
)
print(result)