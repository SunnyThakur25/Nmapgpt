import argparse
import os
import subprocess
import logging
from app.parser import NmapParser
from app.ai_engine import AIEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_nmap_scan(target: str, options: str, output_file: str) -> str:
    """
    Run Nmap scan and save results as XML.

    Args:
        target (str): Target IP or range (e.g., '192.168.1.1' or '192.168.1.0/24')
        options (str): Nmap options (e.g., '-sV -O')
        output_file (str): Path to save XML output

    Returns:
        str: Path to generated XML file
    """
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Construct Nmap command
        cmd = f"nmap {options} -oX {output_file} {target}"
        logger.info(f"Running Nmap command: {cmd}")
        
        # Execute Nmap
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Nmap scan failed: {result.stderr}")
            raise RuntimeError(f"Nmap scan failed: {result.stderr}")
        
        if not os.path.exists(output_file):
            logger.error(f"Nmap output file not created: {output_file}")
            raise FileNotFoundError(f"Nmap output file not created: {output_file}")
        
        logger.info(f"Nmap scan completed, XML saved to: {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error running Nmap scan: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description="NmapGPT: AI-driven Nmap scan analysis")
    parser.add_argument("--scan", action="store_true", help="Run Nmap scan")
    parser.add_argument("--target", type=str, help="Target IP or range for Nmap scan")
    parser.add_argument("--options", type=str, default="-sV -O", help="Nmap scan options (default: -sV -O)")
    parser.add_argument("--input", type=str, help="Input Nmap XML file for analysis")
    parser.add_argument("--output", type=str, default="outputs/analysis_report.txt", help="Output file for AI analysis")
    parser.add_argument("--model-provider", type=str, default="huggingface", help="AI model provider (huggingface, openai, deepseek, grok)")
    parser.add_argument("--model-name", type=str, default="deepseek/deepseek-coder-6.7b-instruct", help="AI model name")
    parser.add_argument("--prompt-template", type=str, default="models/prompts/exploit_suggestion.txt", help="Prompt template path")
    
    args = parser.parse_args()

    try:
        xml_file = args.input
        
        # Run Nmap scan if --scan is specified
        if args.scan:
            if not args.target:
                raise ValueError("Target required for Nmap scan (--target)")
            xml_file = f"outputs/scans/scan_{args.target.replace('/', '_')}.xml"
            xml_file = run_nmap_scan(args.target, args.options, xml_file)
        
        if not xml_file:
            raise ValueError("Input XML file or scan required")

        # Parse Nmap XML
        logger.info(f"Parsing Nmap XML: {xml_file}")
        parser = NmapParser(xml_file)
        services = parser.parse()

        # Initialize AI engine
        logger.info(f"Initializing AI engine with {args.model_provider} ({args.model_name})")
        ai_engine = AIEngine(model_provider=args.model_provider, model_name=args.model_name)

        # Analyze services
        logger.info("Analyzing services with AI")
        analysis = ai_engine.suggest_exploits(services, args.prompt_template)

        # Save analysis
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w') as f:
            f.write(analysis)
        logger.info(f"Analysis saved to: {args.output}")

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
