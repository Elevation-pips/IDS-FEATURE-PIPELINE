import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score

BASE = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload",
        "sinpkt", "dinpkt", "smean", "dmean"]
TTL = ["sttl", "dttl"]
PROTOS = ["tcp", "udp", "icmp", "other"]


def prep(df, cols):
    X = df[cols].copy()
    proto = df["proto"].str.lower()
    proto = proto.where(proto.isin(PROTOS[:-1]), "other")
    for p in PROTOS:
        X[f"proto_{p}"] = (proto == p).astype(int)
    return X


train = pd.read_csv("data/UNSW_NB15_training-set.csv")
test = pd.read_csv("data/UNSW_NB15_testing-set.csv")
mine = pd.read_csv("data/flows.csv")

for name, cols in [("with TTL", BASE + TTL), ("without TTL", BASE)]:
    Xtr, Xte = prep(train, cols), prep(test, cols)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                n_jobs=-1, random_state=42)
    rf.fit(Xtr, train["label"])
    pred = rf.predict(Xte)
    flagged = (rf.predict_proba(prep(mine, cols)[Xtr.columns])[:, 1] > 0.5).sum()
    print(f"\n{name}")
    print(f"  UNSW accuracy:        {accuracy_score(test['label'], pred):.4f}")
    print(f"  attack recall:        {recall_score(test['label'], pred, pos_label=1):.4f}")
    print(f"  normal recall:        {recall_score(test['label'], pred, pos_label=0):.4f}")
    print(f"  own flows flagged:    {flagged} of {len(mine)}")