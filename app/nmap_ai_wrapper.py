#!/usr/bin/env python3
"""
NmapGPT CLI - AI-powered Nmap scan analysis tool
"""

import argparse
import logging
import os
import sys
from typing import Dict, Any

from app.parser import parse_nmap_xml
from app.ai_engine import AIEngine

class NmapGPTCLI:
    """Main CLI application class for NmapGPT."""
    
    def __init__(self):
        self.configure_logging()
        self.args = self.parse_arguments()
        
    @staticmethod
    def configure_logging() -> None:
        """Set up basic logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('nmapgpt.log'),
                logging.StreamHandler()
            ]
        )
        logger = logging.getLogger(__name__)
        logger.info("Logging configured")

    def parse_arguments(self) -> argparse.Namespace:
        """Parse and validate command line arguments."""
        parser = argparse.ArgumentParser(
            description="NmapGPT: AI-driven Nmap scan analysis",
            epilog="Example: nmapgpt --input scan.xml --output report.txt"
        )
        
        parser.add_argument(
            "-i", "--input",
            required=True,
            help="Path to Nmap XML input file"
        )
        
        parser.add_argument(
            "-o", "--output",
            default="outputs/analysis_report.txt",
            help="Path to output report file"
        )
        
        parser.add_argument(
            "-p", "--model-provider",
            default="huggingface",
            choices=["huggingface", "openai", "deepseek", "grok"],
            help="AI model provider"
        )
        
        parser.add_argument(
            "-m", "--model-name",
            default="distilgpt2",
            help="Model name (e.g., distilgpt2, gpt-3.5-turbo)"
        )
        
        parser.add_argument(
            "-t", "--prompt-template",
            default="models/prompts/exploit_suggestion.txt",
            help="Path to prompt template file"
        )
        
        return parser.parse_args()

    def validate_file(self, file_path: str, extension: str) -> bool:
        """Validate file existence and extension."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        if not file_path.lower().endswith(extension.lower()):
            raise ValueError(f"File must have {extension} extension")
            
        return True

    def ensure_output_dir(self, output_path: str) -> None:
        """Ensure output directory exists."""
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            logging.info(f"Created output directory: {output_dir}")

    def run_analysis(self) -> None:
        """Execute the complete analysis workflow."""
        try:
            # Validate inputs
            self.validate_file(self.args.input, ".xml")
            self.validate_file(self.args.prompt_template, ".txt")
            self.ensure_output_dir(self.args.output)

            # Process scan file
            logging.info(f"Processing input file: {self.args.input}")
            services = parse_nmap_xml(self.args.input)
            
            if not services:
                logging.warning("No valid data parsed from XML")
                sys.exit(1)

            # Initialize and run AI analysis
            ai_engine = AIEngine(
                model_provider=self.args.model_provider,
                model_name=self.args.model_name
            )
            
            logging.info("Starting AI analysis")
            analysis = ai_engine.suggest_exploits(
                services,
                self.args.prompt_template
            )

            # Save results
            with open(self.args.output, 'w') as f:
                f.write(analysis)
                
            logging.info(f"Analysis saved to: {self.args.output}")
            print(f"\n[+] Analysis completed successfully!")
            print(f"    Results saved to: {self.args.output}")

        except Exception as e:
            logging.exception("Analysis failed")
            print(f"\n[!] Error: {str(e)}", file=sys.stderr)
            sys.exit(1)

def main():
    """Entry point for the CLI application."""
    cli = NmapGPTCLI()
    cli.run_analysis()

if __name__ == "__main__":
    main()