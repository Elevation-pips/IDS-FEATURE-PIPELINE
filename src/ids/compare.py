import pandas as pd

FEATURES = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload",
            "dload", "sinpkt", "dinpkt", "smean", "dmean"]

train = pd.read_csv("data/UNSW_NB15_training-set.csv")
mine = pd.read_csv("data/flows.csv")

table = pd.DataFrame({
    "unsw_normal": train[train["label"] == 0][FEATURES].median(),
    "unsw_attack": train[train["label"] == 1][FEATURES].median(),
    "my_flows": mine[FEATURES].median(),
})
pd.set_option("display.float_format", "{:,.2f}".format)
print(table)