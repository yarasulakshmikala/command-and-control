import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score
import seaborn as sns

st.set_page_config(page_title="SOC Multi-Attack Detection", layout="wide")
st.title("🛡 SOC Dashboard – Multi-Attack Detection")

# Load model, scaler, and features
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")
features = joblib.load("features.pkl")

uploaded_file = st.file_uploader("📂 Upload Network Traffic CSV", type=["csv"])

if uploaded_file:

    df = pd.read_csv(uploaded_file)
    df = df.dropna()

    # 🔴 Drop Label before prediction if present
    if "Label" in df.columns:
        df_features = df.drop("Label", axis=1)
    else:
        df_features = df.copy()

    # Check required columns
    missing_cols = [col for col in features if col not in df_features.columns]
    if missing_cols:
        st.error(f"❌ Missing required columns: {missing_cols}")
        st.stop()

    # Select features in correct order
    X = df_features[features]

    # Scale using trained scaler
    try:
        X_scaled = scaler.transform(X)
    except Exception as e:
        st.error(f"Scaling error: {e}")
        st.stop()

    # Predict
    predictions = model.predict(X_scaled)
    df["Prediction"] = predictions

    # 🔍 Debug – show first predictions
    st.write("🔍 Sample predictions:", predictions[:20])

    # ==============================
    # 📡 Beaconing Detection
    # ==============================
    st.subheader("📡 Beaconing Detection")

    beacon_df = df[
        (df["Flow Packets/s"] < 50) &
        (df["Flow Bytes/s"] < 1000) &
        (df["Flow Duration"] > 200000)
    ].copy()

    if "Timestamp" in beacon_df.columns:
        beacon_df["Timestamp"] = pd.to_datetime(beacon_df["Timestamp"], errors="coerce")

    if not beacon_df.empty:
        st.warning(f"⚠ Potential Beaconing Flows Detected: {len(beacon_df)}")
        fig_beacon, ax_beacon = plt.subplots()
        beacon_df["Flow Duration"].plot(kind="hist", bins=20, ax=ax_beacon)
        ax_beacon.set_title("Beaconing Flow Duration Pattern")
        st.pyplot(fig_beacon)
    else:
        st.success("✅ No beaconing behavior detected")

    # ==============================
    # ⏱ Beacon Interval Analysis
    # ==============================
    if "Timestamp" in beacon_df.columns and "Src IP" in beacon_df.columns:

        st.subheader("⏱ Beacon Interval Analysis & Suspicious IPs")

        beacon_df = beacon_df.dropna(subset=["Timestamp", "Src IP"])
        suspicious_ips = []
        all_intervals = pd.Series(dtype=float)

        for ip, group in beacon_df.groupby("Src IP"):
            times = group["Timestamp"].sort_values()
            if len(times) > 2:
                intervals = times.diff().dt.total_seconds().dropna()
                all_intervals = pd.concat([all_intervals, intervals])
                std_dev = intervals.std()

                if std_dev < 5 or std_dev > 300:
                    suspicious_ips.append((ip, std_dev))

        if not all_intervals.empty:
            fig_int, ax_int = plt.subplots()
            all_intervals.plot(ax=ax_int)
            ax_int.set_title("Beacon Interval Pattern (All IPs)")
            ax_int.set_ylabel("Interval (seconds)")
            st.pyplot(fig_int)
        else:
            st.info("Not enough beacon data for interval analysis")

        if suspicious_ips:
            st.warning(f"⚠ Suspicious beaconing detected from {len(suspicious_ips)} IPs")
            df_suspicious = pd.DataFrame(
                suspicious_ips, columns=["Src IP", "Interval Std Dev (s)"]
            )
            st.dataframe(df_suspicious)
        else:
            st.success("✅ No suspicious beacon intervals detected")

    # ==============================
    # 🔐 JA3 TLS Fingerprint Detection
    # ==============================
    if "JA3" in df.columns:

        st.subheader("🔐 JA3 Fingerprint Analysis")

        suspicious_ja3 = [
            "72a589da586844d7f0818ce684948eea",
            "a0e9f5d64349fb13191bc781f81f42e1"
        ]

        ja3_hits = df[df["JA3"].isin(suspicious_ja3)]

        if not ja3_hits.empty:
            st.error(f"⚠ Malicious JA3 fingerprints detected: {len(ja3_hits)}")
            st.dataframe(ja3_hits[["JA3"]].value_counts())
        else:
            st.success("✅ No known malicious JA3 fingerprints")

    # ==============================
    # 🌐 IP Reputation Check
    # ==============================
    if "Src IP" in df.columns:

        st.subheader("🌐 Threat Intelligence – IP Reputation")

        malicious_ips = [
            "185.143.223.12",
            "45.67.89.10",
            "192.168.1.200"
        ]

        bad_ip_hits = df[df["Src IP"].isin(malicious_ips)]

        if not bad_ip_hits.empty:
            st.error(f"⚠ Known malicious IPs detected: {len(bad_ip_hits)}")
            st.dataframe(bad_ip_hits[["Src IP"]].value_counts())
        else:
            st.success("✅ No known malicious IPs")

    # ==============================
    # 🕒 Beaconing Timeline
    # ==============================
    if "Timestamp" in beacon_df.columns:

        st.subheader("🕒 Beaconing Timeline")

        timeline = beacon_df.dropna(subset=["Timestamp"]).sort_values("Timestamp")

        if not timeline.empty:
            fig_time, ax_time = plt.subplots()
            ax_time.plot(timeline["Timestamp"], range(len(timeline)))
            ax_time.set_xlabel("Time")
            ax_time.set_ylabel("Beacon Event Count")
            st.pyplot(fig_time)
        else:
            st.info("No timestamp data for timeline")

    # ==============================
    # 🎯 Accuracy & Confusion Matrix
    # ==============================
    if "Label" in df.columns:

        def map_attack(label):
            if "Bot" in label:
                return "C2"
            elif "Patator" in label:
                return "BruteForce"
            elif label in ["Infiltration", "PortScan", "DDoS"]:
                return "MITM"
            else:
                return "Benign"

        y_true = df["Label"].apply(map_attack)
        acc = accuracy_score(y_true, predictions)
        st.subheader(f"🎯 Model Accuracy: {acc:.2f}")

        st.subheader("📉 Confusion Matrix")
        cm = confusion_matrix(y_true, predictions, labels=model.classes_)
        fig_cm, ax_cm = plt.subplots()
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=model.classes_,
            yticklabels=model.classes_,
            ax=ax_cm
        )
        ax_cm.set_xlabel("Predicted")
        ax_cm.set_ylabel("Actual")
        st.pyplot(fig_cm)

    # ==============================
    # 🚨 Detection Results
    # ==============================
    st.subheader("🚨 Detection Results")
    result_counts = df["Prediction"].value_counts()
    st.write(result_counts)

    fig, ax = plt.subplots()
    result_counts.plot(kind="bar", ax=ax)
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Count")
    st.pyplot(fig)

    # ==============================
    # 🔥 Heatmap of Malicious Flows
    # ==============================
    st.subheader("🔥 Malicious Traffic Heatmap")

    malicious_df = df[df["Prediction"] != "Benign"]

    if not malicious_df.empty:
        fig_hm, ax_hm = plt.subplots()
        sns.heatmap(malicious_df[features].corr(), cmap="Reds", ax=ax_hm)
        st.pyplot(fig_hm)
    else:
        st.info("No malicious traffic detected.")

    # ==============================
    # ⬇ Download Report
    # ==============================
    st.download_button(
        "⬇ Download SOC Detection Report",
        data=df.to_csv(index=False),
        file_name="SOC_detection_report.csv",
        mime="text/csv"
    )