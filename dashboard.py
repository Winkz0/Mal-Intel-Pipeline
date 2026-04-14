import streamlit as st
import sqlite3
import pandas as pd
import json
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent
DB_PATH = REPO_ROOT / "pipeline.db"
REPORTS_DIR = REPO_ROOT / "output" / "reports"
RULES_DIR = REPO_ROOT / "output" / "rules"

st.set_page_config(page_title="Mal-Intel Triage", layout="wide", initial_sidebar_state="expanded")

def load_db_data():
    """Fetch the current state of the pipeline queue."""
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM samples", conn)
    conn.close()
    return df

def update_status(sha256, new_status):
    """Update sample status directly from the dashboard."""
    from pipeline.utils.db import update_status as db_update
    db_update(sha256, new_status)
    st.rerun()

def main():
    st.sidebar.title("SOC Triage Queue")
    page = st.sidebar.radio("Navigation", ["Pipeline Status", "Rule & Synthesis Review"])

    df = load_db_data()

    if page == "Pipeline Status":
        st.title("Pipeline Status")
        
        if df.empty:
            st.warning("Database is empty. Run ingestion and acquisition first.")
            return

        # Top level metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Acquired", len(df[df['status'] == 'ACQUIRED']))
        col2.metric("Analyzed", len(df[df['status'] == 'ANALYZED']))
        col3.metric("Synthesized", len(df[df['status'] == 'SYNTHESIZED']))
        col4.metric("Reported", len(df[df['status'] == 'REPORTED']))
        col5.metric("Total Corpus", len(df))

        st.divider()
        
        # Data table with status styling
        st.subheader("Active Queue")
        
        # Sort by most recently acquired
        df_sorted = df.sort_values(by='acquired_at', ascending=False)
        st.dataframe(
            df_sorted[['sha256', 'family', 'status', 'acquired_at']], 
            use_container_width=True,
            hide_index=True
        )

    elif page == "Rule & Synthesis Review":
        st.title("Checkpoint Review")
        
        # Filter for items that have been synthesized but not yet fully approved/reported
        review_queue = df[df['status'] == 'SYNTHESIZED']['sha256'].tolist()
        
        if not review_queue:
            st.info("No samples currently pending review.")
            return
            
        selected_sha = st.sidebar.selectbox("Select Sample to Review", review_queue)
        
        if selected_sha:
            st.subheader(f"Reviewing: {selected_sha[:16]}...")
            
            # Load Synthesis JSON
            syn_path = REPORTS_DIR / f"{selected_sha}.synthesis.json"
            if syn_path.exists():
                with open(syn_path, 'r') as f:
                    syn_data = json.load(f)
                
                # Layout: 2 Columns for clean reading
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    st.markdown("### LLM Technical Summary")
                    st.write(syn_data.get("technical_report", {}).get("executive_summary", "No summary found."))
                    
                    st.markdown("### Key Indicators")
                    for ind in syn_data.get("technical_report", {}).get("key_indicators", []):
                        st.markdown(f"- {ind}")
                        
                with col2:
                    st.markdown("### Drafted YARA Rule")
                    yara_rule = syn_data.get("yara_rule", {}).get("rule_text", "No YARA rule generated.")
                    st.code(yara_rule, language="yara")
                    
                    st.markdown("### Drafted Sigma Rule")
                    sigma_rule = syn_data.get("sigma_rule", {}).get("rule_text", "No Sigma rule generated.")
                    st.code(sigma_rule, language="yaml")
            else:
                st.error("Synthesis file not found on disk.")

            st.divider()
            
            # Approval Actions
            st.markdown("### Actions")
            col_a, col_b, col_c = st.columns([1, 1, 8])
            with col_a:
                if st.button("✅ Approve (Push to Report)", type="primary"):
                    # This bridges to your report.py logic if you want to trigger it from here later,
                    # or just manually updates the DB so the CLI script skips it next time.
                    update_status(selected_sha, 'REPORTED')
            with col_b:
                if st.button("❌ Reject (Needs Revision)"):
                    update_status(selected_sha, 'ANALYZED') # Push back to analysis state

if __name__ == "__main__":
    main()