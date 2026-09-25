import os
import json

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, ConfusionMatrixDisplay
)

from utils.preprocessing import preprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "phishing email.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "detector.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")
CONFUSION_PATH = os.path.join(BASE_DIR, "static", "img", "confusion_matrix.png")


def load_dataset():
    df = pd.read_csv(DATASET_PATH)

    df = df[["text", "label", "phishing_type"]]

    df = df.drop_duplicates(subset="text")
    df = df.dropna()

    return df


def clean_dataset(df):

    print("Cleaning email text...")

    df["clean_text"] = df["text"].apply(preprocess)

    return df


def create_features(df):

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))

    X = vectorizer.fit_transform(df["clean_text"])

    y = df["label"]

    return X, y, vectorizer


def train_models(X_train, y_train):

    models = {

        "Naive Bayes": MultinomialNB(),

        "Logistic Regression": LogisticRegression(max_iter=1000),

        # Calibrated so the SVM can also give a probability
        "Linear SVM": CalibratedClassifierCV(LinearSVC(), cv=3)

    }

    trained_models = {}

    for name, model in models.items():

        print(f"Training {name}...")

        model.fit(X_train, y_train)

        trained_models[name] = model

    return trained_models


def evaluate_models(models, X_test, y_test):

    results = {}

    best_f1 = -1

    best_name = None

    for name, model in models.items():

        predictions = model.predict(X_test)

        results[name] = {
            "accuracy": round(accuracy_score(y_test, predictions), 4),
            "precision": round(precision_score(y_test, predictions), 4),
            "recall": round(recall_score(y_test, predictions), 4),
            "f1": round(f1_score(y_test, predictions), 4),
        }

        print("=" * 50)

        print(name)

        print(classification_report(y_test, predictions, target_names=["Legitimate", "Phishing"]))

        # F1 balances missed phishing (recall) against false alarms (precision)
        if results[name]["f1"] > best_f1:

            best_f1 = results[name]["f1"]

            best_name = name

    return best_name, results


def feature_weights(model):
    """Per-word weight towards 'phishing', used to explain predictions."""

    if isinstance(model, MultinomialNB):
        return model.feature_log_prob_[1] - model.feature_log_prob_[0]

    if isinstance(model, CalibratedClassifierCV):
        return np.mean(
            [c.estimator.coef_[0] for c in model.calibrated_classifiers_], axis=0
        )

    return model.coef_[0]


def train_type_model(df, vectorizer):
    """Second model: which kind of phishing an email is."""

    phishing = df[df["label"] == 1]

    X = vectorizer.transform(phishing["clean_text"])

    y = phishing["phishing_type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = LogisticRegression(max_iter=2000)

    model.fit(X_train, y_train)

    accuracy = accuracy_score(y_test, model.predict(X_test))

    print(f"Phishing type model accuracy: {accuracy:.4f}")

    return model, round(accuracy, 4)


def save_confusion_matrix(model, X_test, y_test, name):

    os.makedirs(os.path.dirname(CONFUSION_PATH), exist_ok=True)

    matrix = confusion_matrix(y_test, model.predict(X_test))

    display = ConfusionMatrixDisplay(matrix, display_labels=["Legitimate", "Phishing"])

    fig, ax = plt.subplots(figsize=(4.5, 4))

    display.plot(ax=ax, cmap="Blues", colorbar=False)

    ax.set_title(f"Confusion matrix - {name}")

    fig.tight_layout()

    fig.savefig(CONFUSION_PATH, dpi=150)

    plt.close(fig)

    return matrix.tolist()


def main():

    df = load_dataset()

    df = clean_dataset(df)

    X, y, vectorizer = create_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    models = train_models(X_train, y_train)

    best_name, results = evaluate_models(models, X_test, y_test)

    best_model = models[best_name]

    print(f"\nBest model: {best_name}")

    type_model, type_accuracy = train_type_model(df, vectorizer)

    matrix = save_confusion_matrix(best_model, X_test, y_test, best_name)

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(
        {
            "model": best_model,
            "model_name": best_name,
            "vectorizer": vectorizer,
            "weights": feature_weights(best_model),
            "type_model": type_model,
            # Longest training email, used to warn about emails far outside that range
            "max_train_words": int(df["clean_text"].str.split().str.len().max()),
        },
        MODEL_PATH,
    )

    metrics = {
        "best_model": best_name,
        "models": results,
        "type_model_accuracy": type_accuracy,
        "confusion_matrix": matrix,
        "train_size": X_train.shape[0],
        "test_size": X_test.shape[0],
    }

    with open(METRICS_PATH, "w") as file:
        json.dump(metrics, file, indent=2)

    print("Model Saved Successfully")


if __name__ == "__main__":
    main()
