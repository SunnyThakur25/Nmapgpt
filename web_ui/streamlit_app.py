import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
from app.parser import parse_nmap_xml
from app.ai_engine import AIEngine
from tempfile import NamedTemporaryFile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """
    Streamlit web interface for NmapGPT.
    """
    st.set_page_config(page_title="NmapGPT", page_icon="🔍", layout="wide")
    st.title("NmapGPT: AI-Driven Nmap Scan Analysis")
    st.markdown("Upload an Nmap XML file to analyze services and get exploit suggestions.")

    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        model_provider = st.selectbox("AI Model Provider", ["huggingface", "openai", "deepseek", "grok"], index=0)
        model_name = st.text_input("Model Name", value="distilgpt2")
        prompt_template = st.text_input("Prompt Template Path", value="models/prompts/exploit_suggestion.txt")

    # File uploader
    uploaded_file = st.file_uploader("Upload Nmap XML File", type=["xml"], accept_multiple_files=False)

    if uploaded_file:
        try:
            # Save uploaded file temporarily
            with NamedTemporaryFile(delete=False, suffix=".xml") as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_file_path = tmp_file.name

            # Parse XML
            st.subheader("Parsed Scan Results")
            logger.info(f"Parsing uploaded file: {uploaded_file.name}")
            services = parse_nmap_xml(tmp_file_path)
            st.json(services)

            # Validate prompt template
            if not os.path.exists(prompt_template):
                st.error(f"Prompt template not found: {prompt_template}")
                logger.error(f"Prompt template not found: {prompt_template}")
                return

            # Analyze button
            if st.button("Analyze with AI"):
                with st.spinner("Running AI analysis..."):
                    try:
                        # Initialize AI engine
                        ai_engine = AIEngine(model_provider=model_provider, model_name=model_name)
                        
                        # Run analysis
                        logger.info("Starting AI analysis")
                        analysis = ai_engine.suggest_exploits(services, prompt_template)
                        
                        # Display results
                        st.subheader("AI Analysis Results")
                        st.text_area("Exploit Suggestions", analysis, height=400)
                        
                        # Option to download results
                        st.download_button(
                            label="Download Analysis",
                            data=analysis,
                            file_name="analysis_report.txt",
                            mime="text/plain"
                        )
                        
                        logger.info("Analysis completed successfully")
                    
                    except Exception as e:
                        st.error(f"Error during AI analysis: {str(e)}")
                        logger.error(f"AI analysis error: {str(e)}")
                    
                    finally:
                        os.unlink(tmp_file_path)
                        logger.info(f"Cleaned up temporary file: {tmp_file_path}")
        
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")
            logger.error(f"File processing error: {str(e)}")
    
    else:
        st.info("Please upload an Nmap XML file to begin.")

if __name__ == "__main__":
    main()