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
    "test-bucket-secure": "Secure Configuration (Low Risk)",
    "test-bucket-complex-breach": "New/Unseen: Complex Data Exfiltration Scenario (Unknown Risk)"
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
            
    import time
    with col2:
        st.subheader("Generative AI Assessment")
        
        # Add visual delay for dramatic effect 
        with st.spinner("Initiating Generative AI Models..."):
            time.sleep(1)
            
        with st.spinner("Parsing JSON abstract syntax tree..."):
            time.sleep(1)
            
        with st.spinner("Generating Live Insight..."):
            assessment = analyze_posture()
            
        risk_level = assessment.get("risk_level", "Unknown")
        blast_info = assessment.get("blast_radius", {})
        impact_score = blast_info.get("impact_score", "Unknown")
        
        # Display Core Metrics
        metric_col1, metric_col2 = st.columns(2)
        with metric_col1:
            if risk_level.lower() == "high":
                st.error(f"**Security Risk Level:**\n\n### {risk_level}")
            elif risk_level.lower() == "medium":
                st.warning(f"**Security Risk Level:**\n\n### {risk_level}")
            else:
                st.success(f"**Security Risk Level:**\n\n### {risk_level}")
                
        with metric_col2:
            if impact_score.lower() == "high":
                st.error(f"**Business Impact Score:**\n\n### {impact_score}")
            elif impact_score.lower() == "medium":
                st.warning(f"**Business Impact Score:**\n\n### {impact_score}")
            else:
                st.info(f"**Business Impact Score:**\n\n### {impact_score}")
                
        # Display Detailed Narrative with Typing Effect
        st.markdown("**AI Explanation:**")
        explanation = assessment.get("explanation", "No explanation provided.")
        
        # Generator function for typing effect
        def stream_data():
            for word in explanation.split(" "):
                yield word + " "
                time.sleep(0.04)
                
        st.write_stream(stream_data)
        
        st.markdown("**Affected Downstream Services:**")
        services = blast_info.get("affected_downstream_services", [])
        if services:
            st.write(", ".join(services))
        else:
            st.write("None identified.")
            
        # Display Zero-Trust Validation Block
        st.markdown("---")
        st.subheader("Zero-Trust Validation (Actor-Critic Pipeline)")
        
        critic = assessment.get("critic_validation", {})
        is_safe = critic.get("is_safe", False)
        
        if is_safe:
            st.success("Critic LLM Validation: **SAFE**")
        else:
            st.error("Critic LLM Validation: **UNSAFE (Execution Prevented)**")
            
        st.markdown(f"**Critic Reasoning:** {critic.get('critic_reason', '')}")
        
        st.markdown("**Cryptographic Signature (HMAC-SHA256):**")
        st.code(assessment.get("cryptographic_signature", ""), language="text")
        
        # Conditional Display of Executable Command
        if is_safe and assessment.get("cryptographic_signature") != "UNSIGNED_UNSAFE_SCRIPT":
            st.markdown("### Approved Remediation Command")
            st.code(assessment.get("remediation_command", "# NA"), language="bash")
        else:
            st.error("Remediation command withheld due to safety enforcement.")
