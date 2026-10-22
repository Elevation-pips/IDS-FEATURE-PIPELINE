import numpy as np
import pandas as pd

IDLE_TIMEOUT = 120.0  # seconds of silence before a new flow starts
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}


def build_flows(packets: pd.DataFrame, idle_timeout: float = IDLE_TIMEOUT) -> pd.DataFrame:
    df = packets.sort_values("time").reset_index(drop=True).copy()
    df["src_port"] = df["src_port"].fillna(-1).astype(int)
    df["dst_port"] = df["dst_port"].fillna(-1).astype(int)
    df["tcp_flags"] = df["tcp_flags"].fillna(0).astype(int)

    # Canonical key: the same for both directions of a connection
    df["src_ep"] = df["src_ip"] + ":" + df["src_port"].astype(str)
    df["dst_ep"] = df["dst_ip"] + ":" + df["dst_port"].astype(str)
    swap = df["src_ep"] < df["dst_ep"]
    df["ep_a"] = np.where(swap, df["src_ep"], df["dst_ep"])
    df["ep_b"] = np.where(swap, df["dst_ep"], df["src_ep"])
    pair = ["ep_a", "ep_b", "protocol"]

    # Split a pair into separate flows after a long idle gap
    gap = df.groupby(pair)["time"].diff()
    df["flow_seq"] = (gap > idle_timeout).groupby([df[c] for c in pair]).cumsum()
    flow_key = pair + ["flow_seq"]

    # Forward = same direction as the first packet of the flow
    first_ep = df.groupby(flow_key)["src_ep"].transform("first")
    df["fwd"] = df["src_ep"] == first_ep

    df["syn"] = ((df["tcp_flags"] & 0x02) > 0).astype(int)
    df["fin"] = ((df["tcp_flags"] & 0x01) > 0).astype(int)
    df["rst"] = ((df["tcp_flags"] & 0x04) > 0).astype(int)
    df["iat"] = df.groupby(flow_key + ["fwd"])["time"].diff()

    per_dir = df.groupby(flow_key + ["fwd"]).agg(
        pkts=("length", "size"),
        bytes=("length", "sum"),
        mean=("length", "mean"),
        ttl=("ttl", "mean"),
        inpkt=("iat", "mean"),
        syn=("syn", "sum"),
        fin=("fin", "sum"),
        rst=("rst", "sum"),
    )
    wide = per_dir.unstack("fwd")
    wide.columns = [f"{'s' if fwd else 'd'}{name}" for name, fwd in wide.columns]

    timing = df.groupby(flow_key)["time"].agg(start="min", end="max")
    first = df.groupby(flow_key)[["src_ip", "src_port", "dst_ip", "dst_port", "protocol"]].first()
    first = first.drop(columns="protocol", errors="ignore")

    flows = first.join(timing).join(wide).reset_index()
    flows = flows.drop(columns=["ep_a", "ep_b", "flow_seq"])
    flows = flows.fillna(0)

    flows["dur"] = flows["end"] - flows["start"]
    d = flows["dur"].clip(lower=1e-3)
    flows["spkts_total"] = flows["spkts"] + flows["dpkts"]
    flows["rate"] = (flows["spkts_total"] - 1).clip(lower=0) / d
    flows["sload"] = flows["sbytes"] * 8 / d
    flows["dload"] = flows["dbytes"] * 8 / d
    flows["sinpkt"] *= 1000  # UNSW reports milliseconds
    flows["dinpkt"] *= 1000
    flows["proto"] = flows["protocol"].map(PROTO_NAMES).fillna("other")
    return flows.drop(columns=["spkts_total", "end"])


if __name__ == "__main__":
    packets = pd.read_csv("data/packet_features.csv")
    flows = build_flows(packets)
    flows.to_csv("data/flows.csv", index=False)
    print("Flows:", flows.shape)
    print(flows.head())
    print(flows["proto"].value_counts())