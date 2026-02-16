import yaml
import logging
import argparse
import sys
import os

# Clean imports thanks to your __init__.py files
from src.core import CISPdfParser, Reporter
from src.drivers import OracleDriver

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("CCE")

def load_config(path: str) -> dict:
    """Safely loads the YAML configuration file."""
    if not os.path.exists(path):
        logger.critical(f"Configuration file not found at: {path}")
        sys.exit(1)
    
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.critical(f"Error parsing YAML config: {e}")
        sys.exit(1)

def get_driver(config: dict):
    """
    Factory method to instantiate the correct driver based on config.
    This makes the tool scalable to other targets (Linux, Docker, etc).
    """
    driver_type = config['target'].get('driver', '').lower()
    
    if driver_type == 'oracle':
        # Pass the specific target configuration to the driver
        return OracleDriver(config['target'])
    
    # Future expansions placeholders
    # elif driver_type == 'linux':
    #     return LinuxDriver(config['target'])
    # elif driver_type == 'docker':
    #     return DockerDriver(config['target'])
    
    else:
        raise ValueError(f"Unsupported driver type in config: '{driver_type}'")

def main():
    # 1. Parse CLI Arguments
    parser = argparse.ArgumentParser(description="CIS Compliance Engine (Enterprise Edition)")
    parser.add_argument('-c', '--config', default='config/config.yaml', help="Path to configuration file")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose debug logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # 2. Load Configuration
    cfg = load_config(args.config)
    
    # 3. Parse Benchmark Rules
    pdf_path = cfg['audit'].get('benchmark_pdf')
    if not pdf_path or not os.path.exists(pdf_path):
        logger.critical(f"Benchmark PDF not found: {pdf_path}")
        sys.exit(1)
        
    try:
        engine = CISPdfParser(pdf_path)
        rules = engine.parse()
        logger.info(f"Successfully loaded {len(rules)} audit rules from PDF.")
    except Exception as e:
        logger.critical(f"Failed to parse PDF: {e}")
        sys.exit(1)

    # 4. Initialize Audit Driver
    driver = None
    try:
        driver = get_driver(cfg)
        driver.connect()
    except Exception as e:
        logger.critical(f"Driver initialization failed: {e}")
        sys.exit(1)

    # 5. Execution Loop
    audit_results = []
    print("\n" + "="*60)
    print(f"🚀 STARTING AUDIT: {cfg['target']['host']}")
    print("="*60 + "\n")
    
    try:
        for rule in rules:
            print(f"Checking {rule['id']}...", end="\r")
            
            # Default state
            rule_result = "PASS"
            rule_checks = []

            # If no checks were extracted, mark as Manual/Skipped
            if not rule.get('checks'):
                rule_result = "MANUAL"
            
            else:
                for check in rule['checks']:
                    # Execute the check using the abstract driver
                    res = driver.execute_check(check['type'], check['cmd'])
                    
                    check_record = {
                        'cmd': check['cmd'],
                        'output': res.get('output', ''),
                        'status': res.get('status', 'ERROR')
                    }
                    rule_checks.append(check_record)
                    
                    # Any single failure fails the whole rule
                    if res.get('status') in ['FAIL', 'ERROR']:
                        rule_result = "FAIL"

            # Store Result
            audit_results.append({
                "id": rule['id'],
                "title": rule['title'],
                "description": rule.get('description', ''),