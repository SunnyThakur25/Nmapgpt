import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import subprocess
import logging
import re
from datetime import datetime
from typing import Dict, Any
from app.parser import NmapParser
from app.ai_engine import AIEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set page config first
st.set_page_config(page_title="NmapGPT", layout="wide")

# Custom CSS for classic style
st.markdown("""
    <style>
    .main { background-color: #f0f2f6; }
    .stButton>button { background-color: #4CAF50; color: white; border-radius: 5px; }
    .stTextInput>div>div>input { border: 1px solid #ccc; border-radius: 5px; }
    .stSelectbox>div>div>select { border: 1px solid #ccc; border-radius: 5px; }
    .sidebar .sidebar-content { background-color: #e0e0e0; }
    .reportview-container .main .block-container { padding: 2rem; }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'xml_file' not in st.session_state:
    st.session_state['xml_file'] = None
if 'scan_history' not in st.session_state:
    st.session_state['scan_history'] = []

# Sidebar for settings
with st.sidebar:
    st.header("Settings")
    model_provider = st.selectbox("Model Provider", ["huggingface", "openai", "deepseek", "grok"], key="model_provider")
    model_name = st.text_input("Model Name", value="deepseek/deepseek-coder-6.7b-instruct", key="model_name")
    output_file = st.text_input("Output File", value="outputs/analysis_report.txt", key="output_file")
    
    st.subheader("Recent Scans")
    for scan in st.session_state['scan_history'][:5]:
        if st.button(f"{scan['time']}: {scan['target']}", key=f"scan_{scan['file']}"):
            st.session_state['xml_file'] = scan['file']
            st.experimental_rerun()

# Main content
st.title("NmapGPT: AI-Driven Network Scan Analysis")
st.markdown("Perform Nmap scans, upload XML results, and analyze with AI for vulnerabilities and exploits.")

# Action selection
col1, col2 = st.columns([3, 1])
with col1:
    option = st.selectbox("Choose Action", ["Run Nmap Scan", "Upload XML"], key="action")
with col2:
    st.write("")  # Spacer

# Run Nmap Scan
if option == "Run Nmap Scan":
    with st.container():
        st.subheader("Run Nmap Scan")
        target = st.text_input("Target IP or Range (e.g., 192.168.1.1 or 192.168.1.0/24)", key="target")
        options = st.text_input("Nmap Options", value="-sV -O -T4", key="options", help="e.g., -sV for service version, -O for OS detection")
        
        # Input validation
        valid_target = target and re.match(r'^[\w\./-]+$', target)
        valid_options = options and re.match(r'^[\w\s\-]*$', options)
        
        if not valid_target:
            st.warning("Enter a valid IP or range (e.g., 192.168.1.1 or 192.168.1.0/24).")
        elif not valid_options:
            st.warning("Enter valid Nmap options (e.g., -sV -O).")
        elif st.button("Run Scan", key="run_scan"):
            with st.spinner("Running Nmap scan..."):
                try:
                    output_file = f"outputs/scans/scan_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    cmd = ["nmap"] + options.split() + ["-oX", output_file, target]
                    st.write(f"Executing: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0 and os.path.exists(output_file):
                        st.success(f"Scan completed! XML saved to: {output_file}")
                        st.session_state['xml_file'] = output_file
                        st.session_state['scan_history'].append({
                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'target': target,
                            'file': output_file
                        })
                        
                        # Preview scan results
                        with st.expander("Preview Scan Results"):
                            parser = NmapParser(output_file)
                            services = parser.parse()
                            for host, data in services.items():
                                st.write(f"**Host: {host}**")
                                for port, info in data['ports'].items():
                                    st.write(f"- Port: {port}/{info['protocol']}, Service: {info['service']}, Version: {info['version']}")
                                if data['os'].get('name'):
                                    st.write(f"- OS: {data['os']['name']} ({data['os']['accuracy']}%)")
                    else:
                        st.error(f"Scan failed: {result.stderr}")
                        logger.error(f"Nmap scan failed: {result.stderr}")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                    logger.error(f"Nmap scan error: {str(e)}")

# Upload XML
elif option == "Upload XML":
    with st.container():
        st.subheader("Upload Nmap XML")
        uploaded_file = st.file_uploader("Choose Nmap XML file", type=["xml"], key="upload_xml")
        if uploaded_file:
            try:
                xml_path = f"outputs/scans/{uploaded_file.name}"
                os.makedirs(os.path.dirname(xml_path), exist_ok=True)
                with open(xml_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.success(f"File uploaded: {xml_path}")
                st.session_state['xml_file'] = xml_path
                
                # Preview uploaded XML
                with st.expander("Preview Uploaded XML"):
                    parser = NmapParser(xml_path)
                    services = parser.parse()
                    for host, data in services.items():
                        st.write(f"**Host: {host}**")
                        for port, info in data['ports'].items():
                            st.write(f"- Port: {port}/{info['protocol']}, Service: {info['service']}, Version: {info['version']}")
                        if data['os'].get('name'):
                            st.write(f"- OS: {data['os']['name']} ({data['os']['accuracy']}%)")
            except Exception as e:
                st.error(f"Error processing XML: {str(e)}")
                logger.error(f"XML upload error: {str(e)}")

# AI Analysis
if st.session_state['xml_file']:
    with st.container():
        st.subheader("Analyze Scan with AI")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"Selected XML: {st.session_state['xml_file']}")
        with col2:
            if st.button("Analyze with AI", key="analyze_ai"):
                with st.spinner("Analyzing with AI..."):
                    try:
                        parser = NmapParser(st.session_state['xml_file'])
                        services = parser.parse()
                        
                        ai_engine = AIEngine(model_provider=model_provider, model_name=model_name)
                        analysis = ai_engine.suggest_exploits(services)
                        
                        os.makedirs(os.path.dirname(output_file), exist_ok=True)
                        with open(output_file, 'w') as f:
                            f.write(analysis)
                        
                        st.success(f"Analysis saved to: {output_file}")
                        with st.expander("View Analysis"):
                            st.markdown(analysis)
                    except Exception as e:
                        st.error(f"Analysis failed: {str(e)}. Check model provider, credentials, or model availability.")
                        logger.error(f"AI analysis error: {str(e)}")

# Footer
st.markdown("---")
st.markdown("**NmapGPT** | Built for AI-driven pentesting | Ensure scans are authorized.")
