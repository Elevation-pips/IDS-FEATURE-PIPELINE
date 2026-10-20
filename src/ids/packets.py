from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

packets = rdpcap("data/sample.pcapng")
rows = []

for pkt in packets:
    if IP not in pkt:
        continue
    row = {
        "time": float(pkt.time),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": pkt[IP].proto,
        "length": len(pkt),
        "ttl": pkt[IP].ttl,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
    }
    if TCP in pkt:
        row["src_port"] = pkt[TCP].sport
        row["dst_port"] = pkt[TCP].dport
        row["tcp_flags"] = int(pkt[TCP].flags)
    elif UDP in pkt:
        row["src_port"] = pkt[UDP].sport
        row["dst_port"] = pkt[UDP].dport
    rows.append(row)

df = pd.DataFrame(rows)
df.to_csv("data/packet_features.csv", index=False)
print(df.shape)
print(df.head())
print(df["protocol"].value_counts())
