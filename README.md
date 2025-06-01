# NmapGPT

An AI-powered Nmap wrapper that reads XML scans and recommends exploits.
NmapGPT

NmapGPT is an AI-driven tool for analyzing Nmap scan results, providing vulnerability and exploit suggestions using multiple AI providers (Hugging Face, OpenAI, DeepSeek, Grok).
Setup

    Prerequisites:
        Python 3.8+
        Virtual environment recommended
        API keys for OpenAI, DeepSeek, or Grok (optional)
    Install Dependencies:
    bash
```
python -m venv venv
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate    # Windows
pip install -r requirements.txt
Configure API Keys (optional for cloud providers): Create .env in the project root:
text
OPENAI_API_KEY=your_openai_api_key
DEEPSEEK_API_KEY=your_deepseek_api_key
XAI_API_KEY=your_xai_api_key
```
Prepare Nmap XML: Generate with:
```

    nmap -sV -O -oX examples/scan.xml <target>
```
Usage
CLI

Run:
bash
python app/nmap_ai_wrapper.py --input examples/scan.xml --output outputs/report.txt --model-provider huggingface --model-name distilgpt2

Options:
```
    --model-provider: huggingface, openai, deepseek, grok
    --model-name: e.g., distilgpt2, gpt-3.5-turbo, deepseek-chat, grok
```
Web UI

Run:
```
streamlit run web_ui/streamlit_app.py

    Access at http://localhost:8501
    Upload XML, select provider/model, click "Analyze with AI"
```

Testing

Run unit tests:
```
python -m unittest tests/test_parser.py
```
Notes

    Hugging Face: Uses lightweight distilgpt2 by default. Try mistral for better results (requires GPU).
    Security: Keep .env secure.
    Troubleshooting: Check logs, verify XML format, ensure API keys are valid.

License

MIT
