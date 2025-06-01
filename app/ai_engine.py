import logging
import os
from typing import Dict, Any, Optional
import requests
from transformers import pipeline
import torch
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class AIEngine:
    """
    Handles AI-based analysis of Nmap scan results with support for multiple providers.
    """
    def __init__(self, model_provider: str = "huggingface", model_name: str = "distilgpt2"):
        """
        Initialize AI engine with specified provider and model.

        Args:
            model_provider (str): AI provider ('huggingface', 'openai', 'deepseek', 'grok')
            model_name (str): Model name (e.g., 'distilgpt2', 'gpt-3.5-turbo', 'grok')

        Raises:
            ValueError: If provider or credentials are invalid
        """
        self.model_provider = model_provider.lower()
        self.model_name = model_name
        self.api_key = {
            'openai': os.getenv("OPENAI_API_KEY"),
            'deepseek': os.getenv("DEEPSEEK_API_KEY"),
            'grok': os.getenv("XAI_API_KEY")
        }

        if self.model_provider == "huggingface":
            logger.info(f"Initializing Hugging Face model: {model_name}")
            try:
                # Use PyTorch for lightweight models (distilgpt2, mistral)
                self.model = pipeline('text-generation', model=model_name, framework='pt',
                                    device=0 if torch.cuda.is_available() else -1)
            except Exception as e:
                logger.error(f"Failed to load Hugging Face model: {str(e)}")
                raise

        elif self.model_provider in ["openai", "deepseek", "grok"]:
            if not self.api_key.get(self.model_provider):
                logger.error(f"{self.model_provider.upper()} API key not found in .env")
                raise ValueError(f"{self.model_provider.upper()} API key required")
        else:
            logger.error(f"Unsupported model provider: {self.model_provider}")
            raise ValueError(f"Unsupported model provider: {self.model_provider}")

    def load_prompt_template(self, template_path: str) -> str:
        """
        Load prompt template from file.

        Args:
            template_path (str): Path to prompt template file

        Returns:
            str: Prompt template content

        Raises:
            FileNotFoundError: If template file doesn't exist
        """
        try:
            with open(template_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Prompt template not found: {template_path}")
            raise

    def format_services(self, services: Dict[str, Any]) -> str:
        """
        Format Nmap parsed data into a string for the prompt.

        Args:
            services (Dict): Parsed Nmap data {host: {ports: {port: {service, version}}}}

        Returns:
            str: Formatted string of services
        """
        formatted = []
        for host, data in services.items():
            formatted.append(f"Host: {host}")
            for port, info in data['ports'].items():
                formatted.append(f"  Port: {port}/{info['protocol']}, Service: {info['service']}, "
                               f"Version: {info['version']}, State: {info['state']}")
            if data['os'].get('name'):
                formatted.append(f"  OS: {data['os']['name']} (Accuracy: {data['os']['accuracy']}%)")
        return "\n".join(formatted)

    def analyze_services(self, services: Dict[str, Any], prompt_template_path: str) -> str:
        """
        Analyze Nmap services using the specified AI model.

        Args:
            services (Dict): Parsed Nmap data
            prompt_template_path (str): Path to prompt template

        Returns:
            str: AI-generated analysis

        Raises:
            Exception: For API or model errors
        """
        try:
            services_str = self.format_services(services)
            prompt = self.load_prompt_template(prompt_template_path).format(services=services_str)
            logger.info(f"Generating AI analysis with {self.model_provider} ({self.model_name})")

            if self.model_provider == "huggingface":
                # Lightweight Hugging Face models (e.g., distilgpt2, mistral)
                result = self.model(prompt, max_length=500, num_return_sequences=1,
                                 do_sample=True, temperature=0.7)[0]['generated_text']
                return result.strip()

            elif self.model_provider == "openai":
                headers = {"Authorization": f"Bearer {self.api_key['openai']}", "Content-Type": "application/json"}
                payload = {
                    "model": self.model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.7
                }
                response = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                return response.json()['choices'][0]['message']['content'].strip()

            elif self.model_provider == "deepseek":
                headers = {"Authorization": f"Bearer {self.api_key['deepseek']}", "Content-Type": "application/json"}
                payload = {
                    "model": self.model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.7
                }
                response = requests.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                return response.json()['choices'][0]['message']['content'].strip()

            elif self.model_provider == "grok":
                headers = {"Authorization": f"Bearer {self.api_key['grok']}", "Content-Type": "application/json"}
                payload = {
                    "model": self.model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.7
                }
                response = requests.post(
                    "https://api.x.ai/v1/chat/completions",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                return response.json()['choices'][0]['message']['content'].strip()

        except Exception as e:
            logger.error(f"Error during {self.model_provider} analysis: {str(e)}")
            raise

    def suggest_exploits(self, services: Dict[str, Any], prompt_template_path: str = "models/prompts/exploit_suggestion.txt") -> str:
        """
        Public method to analyze services and suggest exploits.

        Args:
            services (Dict): Parsed Nmap data
            prompt_template_path (str): Path to prompt template

        Returns:
            str: Exploit suggestions
        """
        return self.analyze_services(services, prompt_template_path)