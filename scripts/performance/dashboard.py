import streamlit as st
import pandas as pd
import plotly.express as px
import os

st.set_page_config(page_title="QoS Dashboard", layout="wide")

CSV_FILE = "qos_metrics.csv"

st.title("📶 Adaptive QoS Monitoring Dashboard")
st.markdown("Real-time visualization of CAKE queue activity per interface.")

# Check if file exists
if not os.path.exists(CSV_FILE):
    st.warning(f"`{CSV_FILE}` not found. Start the QoS Controller to generate metrics.")
    st.stop()

# Load and cache the data
@st.cache_data(ttl=5)
def load_data():
    df = pd.read_csv(CSV_FILE)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

df = load_data()

# Interface selector
interfaces = df['iface'].unique().tolist()
selected_iface = st.selectbox("Select Interface", interfaces)

# Filter for selected interface
df_iface = df[df['iface'] == selected_iface].sort_values('timestamp')

# Display metrics
latest = df_iface.iloc[-1] if not df_iface.empty else None

if latest is not None:
    st.subheader(f"🔧 Latest Metrics for `{selected_iface}`")
    cols = st.columns(4)
    for i in range(4):
        tin_pkts = latest.get(f"Tin{i}_pkts", 0)
        tin_bytes = latest.get(f"Tin{i}_bytes", 0)
        cols[i].metric(label=f"Tin {i} pkts", value=f"{tin_pkts}")
        cols[i].metric(label=f"Tin {i} bytes", value=f"{tin_bytes / 1024:.2f} KB")

# Plot packet trends
st.subheader("📊 Packet Count Over Time")
pkt_data = df_iface[[col for col in df_iface.columns if "pkts" in col]]
pkt_data["timestamp"] = df_iface["timestamp"]

pkt_chart = px.line(pkt_data, x="timestamp", y=[col for col in pkt_data.columns if "pkts" in col],
                    labels={"value": "Packets", "timestamp": "Time"}, title="CAKE Queue Packet Trends")
st.plotly_chart(pkt_chart, use_container_width=True)

# Plot byte trends
st.subheader("📈 Byte Count Over Time")
byte_data = df_iface[[col for col in df_iface.columns if "bytes" in col]]
byte_data["timestamp"] = df_iface["timestamp"]

byte_chart = px.line(byte_data, x="timestamp", y=[col for col in byte_data.columns if "bytes" in col],
                     labels={"value": "Bytes", "timestamp": "Time"}, title="CAKE Queue Byte Trends")
st.plotly_chart(byte_chart, use_container_width=True)

st.markdown("---")
st.markdown("💡 Tip: To simulate network changes, try rerunning your Mininet flows.")
