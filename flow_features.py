import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

df = pd.read_csv("packet_features.csv").sort_values("time")

# ICMP/other packets have no ports; groupby would silently drop NaN keys
df["dst_port"] = df["dst_port"].fillna(-1)
df["tcp_flags"] = df["tcp_flags"].fillna(0).astype(int)

# TCP flag bits: FIN=1, SYN=2, RST=4, PSH=8, ACK=16
df["syn"] = ((df["tcp_flags"] & 0x02) > 0).astype(int)
df["fin"] = ((df["tcp_flags"] & 0x01) > 0).astype(int)
df["rst"] = ((df["tcp_flags"] & 0x04) > 0).astype(int)
df["ack"] = ((df["tcp_flags"] & 0x10) > 0).astype(int)

key = ["src_ip", "dst_ip", "dst_port", "protocol"]
df["iat"] = df.groupby(key)["time"].diff()  # gap between packets in the same flow

flows = df.groupby(key).agg(
    packet_count=("length", "size"),
    total_bytes=("length", "sum"),
    mean_len=("length", "mean"),
    std_len=("length", "std"),
    min_len=("length", "min"),
    max_len=("length", "max"),
    mean_iat=("iat", "mean"),
    mean_ttl=("ttl", "mean"),
    syn_count=("syn", "sum"),
    fin_count=("fin", "sum"),
    rst_count=("rst", "sum"),
    ack_count=("ack", "sum"),
    start=("time", "min"),
    end=("time", "max"),
).reset_index()

flows["duration"] = flows["end"] - flows["start"]
flows["pkts_per_sec"] = flows["packet_count"] / flows["duration"].clip(lower=1e-3)
flows["bytes_per_sec"] = flows["total_bytes"] / flows["duration"].clip(lower=1e-3)
flows = flows.drop(columns=["start", "end"]).fillna(0)

flows.to_csv("flow_features.csv", index=False)
print("Flows:", flows.shape)
print(flows.describe().T[["mean", "max"]])

# --- Anomaly detection (no labels needed) ---
features = [
    "packet_count", "total_bytes", "mean_len", "std_len", "min_len", "max_len",
    "mean_iat", "mean_ttl", "syn_count", "fin_count", "rst_count", "ack_count",
    "duration", "pkts_per_sec", "bytes_per_sec",
]
X = StandardScaler().fit_transform(flows[features])

model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
flows["anomaly"] = model.fit_predict(X)          # -1 = anomaly, 1 = normal
flows["score"] = model.decision_function(X)      # lower = more anomalous

print("\nFlagged as anomalous:", (flows["anomaly"] == -1).sum())
print(flows.sort_values("score").head(10)[
    ["src_ip", "dst_ip", "dst_port", "protocol", "packet_count", "total_bytes", "score"]
])

flows.to_csv("flow_features_scored.csv", index=False)