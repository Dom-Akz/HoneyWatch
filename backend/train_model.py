import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import argparse


DATA_FILE = "data/features.csv"
MODEL_FILE = "models/ddos_model.joblib"


# Load data from specified file or default file.
def load_data(data_file=None):
    if data_file is None:
        data_file = DATA_FILE

    if not os.path.exists(data_file):
        print(f"[!] Error: File not found: {data_file}")
        print(f"[*] Using default file: {DATA_FILE}")
        data_file = DATA_FILE

        if not os.path.exists(data_file):
            raise FileNotFoundError(
                f"No data file found. Please provide a valid CSV file."
            )

    df = pd.read_csv(data_file)
    print(f"[*] Loaded {len(df)} windows from {data_file}")
    df["label"] = ((df["pkts"] > 200) | (df["unique_srcs"] > 50)).astype(int)
    print("[*] Label distribution:\n", df["label"].value_counts())
    return df, data_file


def train_model(df):
    features = [
        "pkts",
        "bytes",
        "avg_pkt_size",
        "unique_srcs",
        "unique_dsts",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "entropy_src",
    ]
    X = df[features]
    y = df["label"]

    if len(df["label"].unique()) < 2 or df["label"].value_counts().min() < 2:
        print(
            "[!] Not enough samples per class — training on full dataset without test split"
        )
        X_train, X_test, y_train, y_test = X, X, y, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("\n[*] Evaluation:")
    print(classification_report(y_test, preds))

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    print(f"[*] Model saved to {MODEL_FILE}")
    return model


def main():
    parser = argparse.ArgumentParser(description="Train DDoS detection model")
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        default=None,
        help="Path to CSV file for training (default: data/features.csv)",
    )
    parser.add_argument(
        "--save",
        "-s",
        type=str,
        default="models/ddos_model.joblib",
        help=f"Path to save model (default: models/ddos_model.joblib)",
    )
    args = parser.parse_args()

    # Update global MODEL_FILE if custom save path provided
    global MODEL_FILE
    if args.save != MODEL_FILE:
        MODEL_FILE = args.save

    # Load data from specified file or default
    df, used_file = load_data(args.file)
    print(f"\n[*] Training model using: {used_file}")

    model = train_model(df)

    print("[*] Training complete.")


if __name__ == "__main__":
    main()
