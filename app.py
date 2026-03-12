import streamlit as st
import json
from audit import extract_s3_security_posture
from analyzer import analyze_posture
import os

st.set_page_config(page_title="CSPM Real-Time Auditing", layout="wide")

st.title("CSPM Real-Time Auditing")
st.markdown("### Generative AI-Driven Cloud Security Posture Management Prototype")

bucket_options = {
    "test-bucket-public": "Public Access Vulnerability (High Risk)",
    "test-bucket-unencrypted": "Missing Default Encryption (High Risk)",
    "test-bucket-no-mfa": "Missing Versioning MFA Delete (Medium Risk)",
    "test-bucket-secure": "Secure Configuration (Low Risk)"
}

bucket_name = st.selectbox(
    "Select Mock S3 Bucket Profile for Audit:",
    options=list(bucket_options.keys()),
    format_func=lambda x: f"{x} - {bucket_options[x]}"
)

if st.button("Run Security Audit"):
    with st.spinner("Extracting LocalStack S3 Evidence..."):
        evidence = extract_s3_security_posture(bucket_name)
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Extracted S3 Evidence")
        with st.expander("View Raw JSON", expanded=True):
            st.json(evidence, expanded=True)
            
    with col2:
        st.subheader("Generative AI Assessment")
        with st.spinner("Analyzing posture with GenAI..."):
            assessment = analyze_posture()
            
        risk_level = assessment.get("risk_level", "Unknown")
        
        if risk_level.lower() == "high":
            st.error(f"**Risk Level:** {risk_level}")
        elif risk_level.lower() == "medium":
            st.warning(f"**Risk Level:** {risk_level}")
        else:
            st.success(f"**Risk Level:** {risk_level}")
            
        st.markdown("**Explanation:**")
        st.info(assessment.get("explanation", "No explanation provided."))
        
        st.markdown("**Remediation Command:**")
        st.code(assessment.get("remediation_command", "# NA"), language="bash")
