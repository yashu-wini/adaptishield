# dashboard/app.py
"""
AdaptiShield Dashboard
Streamlit-based visualization for pipeline results and audit logs.
Run: streamlit run dashboard/app.py
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

st.set_page_config(
    page_title="AdaptiShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ─────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0a0e1a; }
    .stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 100%); }
    .metric-card {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .risk-critical { color: #ff4d4d; font-weight: bold; }
    .risk-high { color: #ff8c00; font-weight: bold; }
    .risk-medium { color: #ffd700; font-weight: bold; }
    .risk-low { color: #00ff88; font-weight: bold; }
    h1, h2, h3 { color: #00d4ff !important; }
</style>
""", unsafe_allow_html=True)


def main():
    st.title("🛡️ AdaptiShield — Privacy Intelligence Dashboard")
    st.markdown("*Context-Aware PII Detection & Adaptive Anonymization Framework*")
    st.divider()

    # Sidebar
    with st.sidebar:
        st.image("https://via.placeholder.com/200x60/00d4ff/0a0e1a?text=AdaptiShield", use_column_width=True)
        st.markdown("### Navigation")
        page = st.radio("", ["🔍 Analyze Document", "📊 Analytics", "📋 Audit Logs", "ℹ️ About"])

    if page == "🔍 Analyze Document":
        show_analysis_page()
    elif page == "📊 Analytics":
        show_analytics_page()
    elif page == "📋 Audit Logs":
        show_audit_logs_page()
    else:
        show_about_page()


def show_analysis_page():
    st.header("🔍 Document Analysis")

    col1, col2 = st.columns([1, 1])
    with col1:
        input_type = st.selectbox("Input Type", ["Text", "PDF", "DOCX", "CSV"])

    with col2:
        use_transformer = st.checkbox("Use Transformer Model (DeBERTa)", value=True)

    if input_type == "Text":
        text_input = st.text_area(
            "Enter text to analyze",
            placeholder="e.g. My name is Arjun Sharma, email: arjun@gmail.com, Aadhaar: 2345 6789 0123",
            height=200
        )

        sample_texts = {
            "Sample 1 - Personal Info": "Hello, I am Priya Mehta. You can reach me at priya.mehta@gmail.com or +91-9876543210. My Aadhaar is 2345 6789 0123 and PAN is ABCDE1234F.",
            "Sample 2 - Financial": "Please transfer Rs 50,000 to my account 1234567890123 at HDFC Bank (IFSC: HDFC0001234). UPI: priya@upi",
            "Sample 3 - Medical": "Patient: Dr. Ramesh Kumar, DOB: 15/03/1975, Diagnosis: Type 2 Diabetes. Prescription: Metformin 500mg. Contact: drramesh@hospital.com",
        }
        sample_choice = st.selectbox("Or load a sample", ["-- Choose --"] + list(sample_texts.keys()))
        if sample_choice != "-- Choose --":
            text_input = sample_texts[sample_choice]
            st.text_area("Loaded Sample", text_input, height=150, disabled=True)

        if st.button("🚀 Analyze", type="primary") and text_input:
            with st.spinner("Running AdaptiShield pipeline..."):
                result = run_pipeline(text_input, use_transformer=use_transformer)
            display_results(result)

    else:
        uploaded = st.file_uploader(
            f"Upload {input_type} file",
            type={"PDF": ["pdf"], "DOCX": ["docx"], "CSV": ["csv", "xlsx"]}[input_type]
        )
        if uploaded and st.button("🚀 Analyze File", type="primary"):
            with st.spinner(f"Processing {uploaded.name}..."):
                result = run_pipeline_file(uploaded, use_transformer=use_transformer)
            display_results(result)


def run_pipeline(text: str, use_transformer: bool = True) -> dict:
    """Run the AdaptiShield pipeline on text."""
    from pipeline import AdaptiShieldPipeline
    p = AdaptiShieldPipeline(use_transformer=use_transformer, use_spacy=False, encrypt_output=True)
    return p.process_text(text)


def run_pipeline_file(uploaded_file, use_transformer: bool = True) -> dict:
    from pipeline import AdaptiShieldPipeline
    p = AdaptiShieldPipeline(use_transformer=use_transformer, use_spacy=False, encrypt_output=True)
    return p.process_bytes(uploaded_file.read(), filename=uploaded_file.name)


def display_results(result: dict):
    st.divider()
    st.subheader("📊 Pipeline Results")

    risk = result["risk_analysis"]
    entities = result["entities"]

    # ── Risk Metrics Row ─────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    risk_color = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}.get(risk["risk_level"], "⚪")

    col1.metric("Risk Level", f"{risk_color} {risk['risk_level']}")
    col2.metric("Risk Score", f"{risk['risk_score']:.1f}")
    col3.metric("Entities Found", risk["entity_count"])
    col4.metric("Processing Time", f"{result['processing_time_ms']:.0f}ms")

    st.divider()

    # ── Entity Table ─────────────────────────────────
    if entities:
        st.subheader("🔎 Detected Entities")
        df = pd.DataFrame([{
            "Entity Type": e["entity_type"],
            "Original Value": e["original_value"],
            "Anonymized Value": e["anonymized_value"],
            "Strategy": e["strategy"],
            "Confidence": f"{e['confidence']*100:.1f}%",
            "Sensitivity": e["sensitivity_level"],
            "Score": e["effective_score"],
        } for e in entities])

        # Color code sensitivity
        def highlight_sensitivity(val):
            colors = {
                "CRITICAL": "background-color: #3d0000; color: #ff4d4d",
                "HIGH": "background-color: #2d1500; color: #ff8c00",
                "MEDIUM": "background-color: #2d2000; color: #ffd700",
                "LOW": "background-color: #002d0d; color: #00ff88",
            }
            return colors.get(val, "")

        styled_df = df.style.applymap(highlight_sensitivity, subset=["Sensitivity"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)

    st.divider()

    # ── Charts Row ───────────────────────────────────
    if entities:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Entity Distribution")
            entity_counts = {}
            for e in entities:
                entity_counts[e["entity_type"]] = entity_counts.get(e["entity_type"], 0) + 1
            fig = px.pie(
                values=list(entity_counts.values()),
                names=list(entity_counts.keys()),
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font=dict(color="white"))
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Confidence Scores")
            fig2 = px.bar(
                x=[e["entity_type"] for e in entities],
                y=[e["confidence"] for e in entities],
                color=[e["sensitivity_level"] for e in entities],
                color_discrete_map={"LOW": "#00ff88", "MEDIUM": "#ffd700", "HIGH": "#ff8c00", "CRITICAL": "#ff4d4d"}
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"), xaxis_title="Entity", yaxis_title="Confidence"
            )
            st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # ── Text Comparison ─────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📄 Original Text")
        st.text_area("", result.get("anonymized_text", "").replace(
            result.get("anonymized_text", ""), "** ORIGINAL NOT SHOWN FOR PRIVACY **"
        ), height=200, disabled=True)

    with col2:
        st.subheader("🔒 Anonymized Text")
        st.text_area("", result.get("anonymized_text", ""), height=200, disabled=True)

    # ── Encryption ───────────────────────────────────
    if result.get("encrypted_payload"):
        st.subheader("🔐 Encrypted Output (AES-256-GCM)")
        st.code(json.dumps(result["encrypted_payload"], indent=2), language="json")

    # ── Recommendations ─────────────────────────────
    st.subheader("💡 Recommendations")
    for rec in risk.get("recommendations", []):
        st.info(rec)


def show_analytics_page():
    st.header("📊 Analytics")
    st.info("Connect to PostgreSQL database for full analytics. Showing sample data.")

    # Sample analytics
    sample_data = {
        "DATE": ["2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05"],
        "Documents": [12, 19, 8, 24, 17],
        "PII Detected": [45, 78, 32, 91, 62],
        "High Risk": [3, 5, 1, 8, 4],
    }
    df = pd.DataFrame(sample_data)

    col1, col2 = st.columns(2)
    with col1:
        fig = px.line(df, x="DATE", y=["Documents", "PII Detected"],
                      title="Processing Volume Over Time",
                      color_discrete_sequence=["#00d4ff", "#ff4d4d"])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        entity_types = ["NAME", "EMAIL", "PHONE", "AADHAAR", "PAN", "CREDIT_CARD", "ADDRESS"]
        counts = [245, 189, 156, 43, 38, 12, 87]
        fig2 = px.bar(x=entity_types, y=counts,
                      title="Entity Type Distribution (All Time)",
                      color=counts, color_continuous_scale="Viridis")
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
        st.plotly_chart(fig2, use_container_width=True)


def show_audit_logs_page():
    st.header("📋 Audit Logs")
    from database.logger import AuditLogger
    audit = AuditLogger()
    logs = audit.get_recent_logs(limit=50)
    if logs:
        df = pd.DataFrame(logs)
        cols = [c for c in ["timestamp", "document_id", "document_name", "risk_level", "risk_score", "entity_count"] if c in df.columns]
        st.dataframe(df[cols] if cols else df, use_container_width=True)
    else:
        st.info("No logs found. Run the pipeline to generate audit logs.")


def show_about_page():
    st.header("ℹ️ About AdaptiShield")
    st.markdown("""
    ## Context-Aware Privacy Intelligence Framework

    **AdaptiShield** is an enterprise-grade AI-powered privacy protection system that detects,
    classifies, and anonymizes personally identifiable information (PII) in documents and text
    using a multi-stage intelligent pipeline.

    ### Pipeline Stages
    1. **Ingestion Engine** — PDF, DOCX, CSV, TXT parsing
    2. **Hybrid Detection** — Regex + Transformer (DeBERTa-v3) + spaCy NER
    3. **Context Validation** — Semantic analysis to reduce false positives
    4. **Sensitivity Engine** — Risk scoring with Indian PII compliance
    5. **Adaptive Anonymization** — MASK / TOKENIZE / REDACT based on risk
    6. **AES-256 Encryption** — Authenticated encryption of output
    7. **Audit Logging** — Full compliance trail in PostgreSQL

    ### Compliance
    - 🇮🇳 Indian DPDP Act (Digital Personal Data Protection Act)
    - 🏦 PCI-DSS (Payment Card Industry)
    - 🏥 HIPAA (Medical Data)
    - 🪪 UIDAI Aadhaar Guidelines
    """)


if __name__ == "__main__":
    main()
