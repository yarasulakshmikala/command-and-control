import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load dataset
df = pd.read_csv("CICIDS_large.csv")

features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s'
]

df = df[features + ['Label']].dropna()

# 🔹 Multi-attack mapping
def map_attack(label):
    if "Bot" in label:
        return "C2"
    elif "Patator" in label:
        return "BruteForce"
    elif label in ["Infiltration", "PortScan", "DDoS"]:
        return "MITM"
    else:
        return "Benign"

df["AttackType"] = df["Label"].apply(map_attack)

X = df[features]
y = df["AttackType"]

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train_scaled, y_train)

# Evaluate
y_pred = model.predict(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, output_dict=True)

print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred))

# 🔹 Save everything for dashboard
joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(accuracy, "accuracy.pkl")
joblib.dump(report, "report.pkl")
joblib.dump(features, "features.pkl")

print("✅ Multi-attack model trained and saved.")