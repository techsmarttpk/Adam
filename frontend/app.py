import streamlit as st
import requests
import time
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="ADAM Adaptive Deception", layout="wide")

API_BASE_URL = "http://127.0.0.1:8000"

st.title("ADAM Adaptive Deception - Live Simulation")

st.markdown("""
Upload a malware sample to deterministically simulate its execution through the ADAM pipeline 
(Fusion Engine -> Policy Engine -> Deception Engine).
""")

uploaded_file = st.file_uploader("Upload Malware Sample", type=None)

if "session_id" not in st.session_state:
    st.session_state.session_id = None

if uploaded_file is not None:
    if st.button("Run Simulation"):
        with st.spinner("Uploading and starting simulation..."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
            response = requests.post(f"{API_BASE_URL}/sessions/simulate", files=files)
            if response.status_code == 200:
                st.session_state.session_id = response.json()["session_id"]
                st.success(f"Simulation started! Session ID: {st.session_state.session_id}")
            else:
                st.error("Failed to start simulation.")

if st.session_state.session_id:
    session_id = st.session_state.session_id
    
    # Auto-refresh loop
    placeholder = st.empty()
    
    # Check status
    is_running = True
    
    with placeholder.container():
        try:
            # Fetch session metadata
            sess_resp = requests.get(f"{API_BASE_URL}/sessions/{session_id}")
            if sess_resp.status_code == 200:
                sess_data = sess_resp.json()
                metadata = sess_data.get("metadata", {})
                events = sess_data.get("events", [])
                decisions = sess_data.get("decisions", [])
                mutations = sess_data.get("mutations", [])
                
                if metadata:
                    status = metadata.get("status")
                    if status in ["COMPLETED", "FAILED", "ABORTED", "PARTIAL"]:
                        is_running = False
                        
                    st.header("Session Summary")
                    col1, col2, col3, col4 = st.columns(4)
                    sample = metadata.get("sample", {})
                    col1.metric("File Name", sample.get("filename", "N/A"))
                    col2.metric("SHA-256", sample.get("sha256", "N/A")[:16] + "...")
                    col3.metric("Status", status)
                    metrics = metadata.get("metrics", {})
                    col4.metric("Semantic Events", metrics.get("semantic_events", 0))
                    
                    st.subheader("Semantic Events (Fusion)")
                    if events:
                        df_events = pd.DataFrame(events)
                        events_cols = [c for c in ["semantic_id", "intent", "confidence", "severity"] if c in df_events.columns]
                        st.dataframe(df_events[events_cols] if events_cols else df_events, use_container_width=True)
                    else:
                        st.info("No events detected yet.")
                        
                    st.subheader("Policy Decisions")
                    if decisions:
                        df_dec = pd.DataFrame(decisions)
                        dec_cols = [c for c in ["rule_id", "verdict", "action", "rationale"] if c in df_dec.columns]
                        st.dataframe(df_dec[dec_cols] if dec_cols else df_dec, use_container_width=True)
                    else:
                        st.info("No decisions made yet.")
                        
                    st.subheader("Deception Mutations")
                    if mutations:
                        df_mut = pd.DataFrame(mutations)
                        mut_cols = [c for c in ["status", "plausibility_score", "changes_made"] if c in df_mut.columns]
                        st.dataframe(df_mut[mut_cols] if mut_cols else df_mut, use_container_width=True)
                    else:
                        st.info("No mutations applied yet.")
                else:
                    st.warning("Loading session metadata...")
        except Exception as e:
            st.error(f"Error fetching data: {e}")
            is_running = False

    if is_running:
        time.sleep(2)
        st.rerun()
