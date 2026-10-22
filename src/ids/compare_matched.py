import pandas as pd

FEATURES = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload",
            "dload", "smean", "dmean"]

train = pd.read_csv("data/UNSW_NB15_training-set.csv")
mine = pd.read_csv("data/flows.csv")

def mid(df):
    pk = df["spkts"] + df["dpkts"]
    return df[(pk >= 10) & (pk <= 30)]

u_norm = mid(train[train["label"] == 0])
u_att = mid(train[train["label"] == 1])
m = mid(mine)
print(f"UNSW normal: {len(u_norm)} flows | UNSW attack: {len(u_att)} | yours: {len(m)}\n")

table = pd.DataFrame({
    "unsw_normal": u_norm[FEATURES].median(),
    "unsw_attack": u_att[FEATURES].median(),
    "my_flows": m[FEATURES].median(),
})
pd.set_option("display.float_format", "{:,.2f}".format)
print(table)
