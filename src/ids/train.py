import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (ConfusionMatrixDisplay, classification_report,
                             confusion_matrix)

# Columns our own flow extractor can also produce
FEATURES = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
            "sload", "dload", "sinpkt", "dinpkt", "smean", "dmean"]
PROTOS = ["tcp", "udp", "icmp", "other"]


def prep(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURES].copy()
    proto = df["proto"].str.lower()
    proto = proto.where(proto.isin(PROTOS[:-1]), "other")
    for p in PROTOS:
        X[f"proto_{p}"] = (proto == p).astype(int)
    return X


def main():
    os.makedirs("models", exist_ok=True)
    os.makedirs("docs", exist_ok=True)

    train = pd.read_csv("data/UNSW_NB15_training-set.csv")
    test = pd.read_csv("data/UNSW_NB15_testing-set.csv")
    X_train, y_train = prep(train), train["label"]
    X_test, y_test = prep(test), test["label"]
    print("Train:", X_train.shape, "Test:", X_test.shape)

    # --- Supervised: Random Forest ---
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    pred = rf.predict(X_test)
    print("\n=== Random Forest (supervised) ===")
    print(classification_report(y_test, pred, target_names=["normal", "attack"], digits=4))
    print(confusion_matrix(y_test, pred))

    ConfusionMatrixDisplay.from_predictions(
        y_test, pred, display_labels=["normal", "attack"], cmap="Blues")
    plt.title("Random Forest on UNSW-NB15 testing set")
    plt.savefig("docs/confusion_matrix_rf.png", dpi=150, bbox_inches="tight")
    plt.close()

    importances = pd.Series(rf.feature_importances_, index=X_train.columns)
    print("\nTop features:\n", importances.sort_values(ascending=False).head(10))

    # --- Unsupervised: Isolation Forest trained on normal flows only ---
    iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_train[y_train == 0])
    iso_pred = (iso.predict(X_test) == -1).astype(int)  # -1 = anomaly -> attack
    print("\n=== Isolation Forest (unsupervised) ===")
    print(classification_report(y_test, iso_pred, target_names=["normal", "attack"], digits=4))
    print(confusion_matrix(y_test, iso_pred))

    joblib.dump({"model": rf, "columns": list(X_train.columns)}, "models/rf.joblib")

    # --- Score our own captured flows, if flows.csv exists ---
    if os.path.exists("data/flows.csv"):
        mine = pd.read_csv("data/flows.csv")
        Xm = prep(mine)[X_train.columns]
        mine["attack_prob"] = rf.predict_proba(Xm)[:, 1]
        mine.to_csv("data/flows_scored.csv", index=False)
        flagged = (mine["attack_prob"] > 0.5).sum()
        print(f"\nYour capture: {len(mine)} flows, {flagged} flagged as attack (>0.5)")
        print(mine.sort_values("attack_prob", ascending=False).head(10)[
            ["src_ip", "dst_ip", "dst_port", "proto", "spkts", "dpkts", "sbytes", "attack_prob"]])


if __name__ == "__main__":
    main()