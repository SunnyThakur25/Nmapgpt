# NmapGPT

An AI-powered Nmap wrapper that reads XML scans and recommends exploits.
NmapGPT
NmapGPT is an AI-driven network scanning and analysis tool that integrates Nmap with advanced AI models to perform vulnerability assessments, suggest exploits, and recommend mitigations. Built for pentesters and cybersecurity professionals, it automates Nmap scan parsing and leverages models like deepseek/deepseek-coder-6.7b-instruct for detailed analysis. The project supports local and cloud deployments (AWS SageMaker, Oracle Cloud, GitHub Codespaces) with a user-friendly Streamlit web interface.
Recent Changes (June 2025)
This section outlines all updates made to NmapGPT to enhance functionality, fix errors, and improve the user experience.
1. AI Engine Enhancements (ai_engine.py)

Hugging Face Token Support: Added HF_TOKEN loading from .env for gated models (e.g., meta-llama/Llama-3-8b-instruct). Public models like deepseek/deepseek-coder-6.7b-instruct skip token usage to avoid 401 Unauthorized errors.

Multi-Provider Support: Retained compatibility with Hugging Face, OpenAI, DeepSeek, and Grok. Fixed DeepSeek 400 Bad Request by setting stream: False.
Default Model: Set deepseek/deepseek-coder-6.7b-instruct (~12GB VRAM) for cybersecurity-focused analysis, replacing distilgpt2.

Error Handling: Improved logging (DEBUG level) for debugging issues like 403 Forbidden (xAI API).

2. Nmap Scanning Module (nmap_ai_wrapper.py)
```
Integrated Nmap Scanning: Added --scan, --target, and --options CLI arguments to run Nmap scans, save XMLs to outputs/scans/, and analyze results. 
Automatic XML Naming: Generates unique filenames (e.g., scan_192.168.1.1.xml).
Security: Uses subprocess.run for safe command execution.
```
3.# Streamlit GUI Improvements (streamlit_app.py)

Classic Design: Implemented a professional layout with sidebar settings, wide main panel, and custom CSS for a clean, neutral aesthetic. 
New Features:
Scan History: Displays last 5 scans in sidebar with clickable buttons to reload XMLs.
Result Previews: Added expanders to preview scan and upload results.
Progress Indicators: Spinners for Nmap scans and AI analysis.


Error Fixes:
Resolved ModuleNotFoundError: No module named 'app.parser' by ensuring app/parser.py and app/__init__.py exist and adding sys.path.append.
Fixed StreamlitSetPageConfigMustBeFirstCommandError by moving st.set_page_config() before other Streamlit commands.


Security: Replaced shell=True in subprocess.run with list-based commands and added regex-based input validation for target and options.
Usability: Enhanced error feedback for AI analysis failures (e.g., invalid credentials).

4. Parser Module (parser.py)

Nmap XML Parsing: Created NmapParser to extract hosts, ports, services, and OS details from Nmap XMLs. 
Robustness: Added error handling and logging for parsing issues.

5. Project Structure Updates

New Directory: Added outputs/scans/ for storing Nmap XMLs.
Prompt Template: Ensured models/prompts/exploit_suggestion.txt exists for AI analysis, detailing CVEs, exploits, and mitigations.
File Verification: Confirmed presence of app/__init__.py, .env, and .gitignore.

6. Cloud and Local Setup

Local Setup (C:\Users\folder\NmapGPT_Project\NmapGPT):
Fixed import errors with sys.path adjustments.
Installed Nmap and dependencies (requirements.txt).
Tested Streamlit UI on http://localhost:8501.


AWS SageMaker:
Configured GPU instances (e.g., ml.g4dn.xlarge) for deepseek/deepseek-coder-6.7b-instruct.
Installed Nmap and dependencies.
Run Streamlit on port 8501 via Studio proxy.






7. Error Resolutions

Hugging Face 401 Unauthorized: Fixed by skipping HF_TOKEN for public models and validating tokens for gated models.
xAI 403 Forbidden: Suggested API key validation and payload checks.
DeepSeek 400 Bad Request: Resolved with stream: False in API calls.
ModuleNotFoundError: Ensured app/parser.py and app/__init__.py exist.
Streamlit Config Error: Moved st.set_page_config() to the top.

Installation
Prerequisites

Python 3.8+
Nmap
Cloud environment (optional): AWS SageMaker, Oracle Cloud, GitHub Codespaces

Steps

Clone Repository:
```
git clone https://github.com/SunnyThakur25/NmapGPT.git
cd NmapGPT
```

Install Dependencies:
```
pip install -r requirements.txt
pip install accelerate huggingface_hub
```

Install Nmap:

Windows: Download from nmap.org and add to PATH.
Linux:sudo apt-get update
sudo apt-get install -y nmap




Configure .env:
```
echo "OPENAI_API_KEY=sk-xxxx" >> .env
echo "DEEPSEEK_API_KEY=sk-xxxx" >> .env
echo "XAI_API_KEY=sk-xxxx" >> .env
echo "HF_TOKEN=hf_xxxx" >> .env  # Optional for gated models
chmod 600 .env
```

Run Streamlit UI:
```
streamlit run web_ui/streamlit_app.py
```
```
Access: http://localhost:8501 (local) or SageMaker proxy (port 8501).
```

Run CLI:
```
python app/nmap_ai_wrapper.py --scan --target 192.168.1.1 --options "-sV -O" --model-provider huggingface --model-name deepseek/deepseek-coder-6.7b-instruct
```


Usage
```
Streamlit UI:
Run Scan: Enter target (e.g., 192.168.1.1) and options (e.g., -sV -O). Results save to outputs/scans/.
Upload XML: Upload Nmap XML for analysis.
Analyze: Select model provider and name, view results in expandable sections.
```

CLI: Run scans and analyze XMLs directly.
Cloud: Deploy on SageMaker for GPU support or Oracle/Codespaces for lightweight testing.

Security Notes

Scan only authorized targets to comply with legal and ethical guidelines.
Secure .env with API keys and tokens.
Validate inputs to prevent command injection.

Future Improvements

Integrate CVE database for real-time vulnerability lookup.
Fine-tune models with custom datasets (e.g., darkknight25/redteam_manualcommands).
Add advanced Nmap scripting support.
Enhance GUI with model status checks and analysis summaries.

Contributing
Contributions are welcome! Please submit issues or pull requests to GitHub repository.
License
MIT License. See LICENSE for details.
Contact
For support, contact sunny48445@gmail.com or raise an issue on GitHub.
Last Updated: June 2, 2025


# screen shots

![nmap 1](https://github.com/user-attachments/assets/6fe448b8-2371-4406-ba9c-0cd61b68ee24)
![nmap3](https://github.com/user-attachments/assets/4f63b127-f0a9-40e8-b292-79a071891ddb)
![nmap2](https://github.com/user-attachments/assets/401f16ec-d782-46b0-955d-6d2e77a5d15f)


