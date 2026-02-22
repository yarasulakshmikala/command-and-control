import pandas as pd
import numpy as np

np.random.seed(42)

rows = 1200

data = {
    "Flow Duration": np.random.randint(50000, 500000, rows),
    "Total Fwd Packets": np.random.randint(1, 20, rows),
    "Total Backward Packets": np.random.randint(1, 20, rows),
    "Flow Bytes/s": np.random.randint(100, 10000, rows),
    "Flow Packets/s": np.random.randint(10, 300, rows),
}

labels = []

for i in range(rows):
    if i < 800:
        labels.append("Benign")
    elif i < 950:
        labels.append("Bot")
    elif i < 1100:
        labels.append("Patator")
    else:
        labels.append("DDoS")

data["Label"] = labels

df = pd.DataFrame(data)
df.to_csv("CICIDS_large.csv", index=False)

print("✅ CICIDS_large.csv generated")