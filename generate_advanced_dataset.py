import pandas as pd
import numpy as np
from datetime import datetime, timedelta

np.random.seed(42)

rows = 1200

# Generate random flow data
data = {
    "Flow Duration": np.random.randint(50000, 500000, rows),
    "Total Fwd Packets": np.random.randint(1, 20, rows),
    "Total Backward Packets": np.random.randint(1, 20, rows),
    "Flow Bytes/s": np.random.randint(100, 10000, rows),
    "Flow Packets/s": np.random.randint(10, 300, rows),
    "Label": ["Benign"]*800 + ["Bot"]*150 + ["Patator"]*150 + ["DDoS"]*100,
    "Src IP": np.random.choice(
        ["192.168.1.10", "192.168.1.20", "10.0.0.5", "45.67.89.10", "185.143.223.12"], rows
    ),
    "Dst IP": np.random.choice(
        ["10.1.1.1", "10.1.1.2", "10.1.1.3"], rows
    ),
    "JA3": np.random.choice(
        ["72a589da586844d7f0818ce684948eea", "a0e9f5d64349fb13191bc781f81f42e1", "abcd1234ef567890"], rows
    )
}

# Generate Timestamps at 1-second intervals starting now
start_time = datetime.now()
timestamps = [start_time + timedelta(seconds=i*5) for i in range(rows)]
data["Timestamp"] = timestamps

# Create DataFrame
df = pd.DataFrame(data)

# Save CSV
df.to_csv("CICIDS_advanced_sample.csv", index=False)

print("✅ CICIDS_advanced_sample.csv generated with Timestamp, JA3, and IP columns")