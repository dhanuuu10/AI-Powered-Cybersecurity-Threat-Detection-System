import streamlit as st
import pandas as pd
import plotly.express as px
from src.data_simulator import generate_labeled_dataset, generate_live_events
from src.detector import train_detector, evaluate_detector, predict_events, FEATURE_COLUMNS

st.set_page_config(page_title="AI Threat Detection SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered Cybersecurity Threat Detection System")
st.caption("Educational SOC-style analytics | Synthetic events only | No live network monitoring")

with st.sidebar:
    st.header("Control panel")
    seed = st.number_input("Simulation seed", min_value=1, max_value=99999, value=42, step=1)
    training_rows = st.slider("Synthetic training records", min_value=500, max_value=5000, value=2000, step=500)
    event_count = st.slider("Events to simulate", min_value=20, max_value=500, value=100, step=20)
    st.info("The default dataset is synthetic. Results demonstrate the workflow and are not evidence of real-world detection accuracy.")

@st.cache_resource
def get_model(rows, random_seed):
    data = generate_labeled_dataset(n=rows, seed=int(random_seed))
    model, X_test, y_test = train_detector(data)
    metrics = evaluate_detector(model, X_test, y_test)
    return model, metrics, data

model, metrics, training_data = get_model(int(training_rows), int(seed))
events = generate_live_events(n=int(event_count), seed=int(seed) + 100)
results = predict_events(model, events)
threats = results[results["prediction"] == "Potential Threat"]
alerts = int(len(threats))
rate = (alerts / len(results) * 100) if len(results) else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{len(results):,}")
c2.metric("Potential threats flagged", f"{alerts:,}")
c3.metric("Flagged event rate", f"{rate:.1f}%")
c4.metric("Model test accuracy", f"{metrics['accuracy']:.1%}")

st.subheader("Event overview")
left, right = st.columns(2)
with left:
    counts = results["prediction"].value_counts().rename_axis("Prediction").reset_index(name="Events")
    fig = px.pie(counts, names="Prediction", values="Events", title="Benign vs potential threat")
    st.plotly_chart(fig, use_container_width=True)
with right:
    if "event_type" in results.columns:
        by_type = results.groupby(["event_type", "prediction"]).size().reset_index(name="Events")
        fig = px.bar(by_type, x="event_type", y="Events", color="prediction", barmode="group",
                     title="Predictions by simulated event type")
        st.plotly_chart(fig, use_container_width=True)

st.subheader("Model evaluation on held-out synthetic data")
m1, m2, m3 = st.columns(3)
m1.metric("Precision (threat class)", f"{metrics['precision']:.1%}")
m2.metric("Recall (threat class)", f"{metrics['recall']:.1%}")
m3.metric("F1 score (threat class)", f"{metrics['f1']:.1%}")
st.write("These metrics describe a held-out split of the generated synthetic dataset. They should not be interpreted as performance on real enterprise traffic.")
st.code(metrics["classification_report"], language="text")

st.subheader("Security event table")
show_threats_only = st.checkbox("Show only potential threats", value=False)
display_df = threats if show_threats_only else results
st.dataframe(display_df, use_container_width=True, hide_index=True)
st.download_button(
    "Download analyzed events as CSV",
    data=results.to_csv(index=False).encode("utf-8"),
    file_name="analyzed_security_events.csv",
    mime="text/csv",
)

st.subheader("Analyze your own CSV")
st.write("For this starter version, uploaded CSV files must contain these numeric feature columns:")
st.code(", ".join(FEATURE_COLUMNS))
uploaded = st.file_uploader("Upload a CSV of feature records", type=["csv"])
if uploaded is not None:
    try:
        user_df = pd.read_csv(uploaded)
        missing = [col for col in FEATURE_COLUMNS if col not in user_df.columns]
        if missing:
            st.error("Missing required feature columns: " + ", ".join(missing))
        else:
            user_results = predict_events(model, user_df)
            st.success(f"Analyzed {len(user_results)} uploaded records.")
            st.dataframe(user_results, use_container_width=True, hide_index=True)
            st.download_button(
                "Download uploaded-file predictions",
                data=user_results.to_csv(index=False).encode("utf-8"),
                file_name="uploaded_file_predictions.csv",
                mime="text/csv",
            )
    except Exception as exc:
        st.error(f"Could not read the CSV: {exc}")

with st.expander("How to interpret this dashboard"):
    st.markdown("""
    - **Potential Threat** means the trained model considers the record similar to its synthetic threat examples.
    - **Benign** means the model classifies the record as similar to the benign examples.
    - A prediction is not proof of malicious activity. Analysts should validate alerts with context and additional telemetry.
    - This demo does not ingest packets, block traffic, or monitor a real network.
    """)
