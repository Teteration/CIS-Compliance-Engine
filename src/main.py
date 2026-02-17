import yaml
import logging
import argparse
import sys
import os
import re
import warnings
from datetime import datetime
from cryptography.utils import CryptographyDeprecationWarning
from colorama import init, Fore, Style

# Suppress Warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from src.core.parser import CISPdfParser
from src.core.reporter import Reporter
from src.drivers.oracle import OracleDriver

# Init Colorama
init(autoreset=True)

# Configure Logging (Silent for internal libraries)
logging.basicConfig(level=logging.CRITICAL)

def load_config(path):
    if not os.path.exists(path):
        print(f"[!] Config file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)

def get_driver(config):
    driver_name = config['target']['driver']
    if driver_name == 'oracle':
        return OracleDriver(config['target'])
    else:
        raise ValueError(f"Unsupported driver: {driver_name}")

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def clean_output(raw):
    """Clean up the DB output for the log line"""
    s = str(raw).replace("\n", " ").strip()
    if "DPY" in s: return "Error"
    if "No rows" in s: return "Empty"
    # Convert [('VALUE',)] to just VALUE
    s = s.replace("[('", "").replace("',)]", "").replace("')]", "")
    return s[:50] # Truncate if too long

def clean_title(title):
    # Remove trailing page numbers (e.g. "....... 15")
    t = re.sub(r'\.+\s*\d+$', '', title)
    # Remove duplicate (Automated) tags
    t = t.replace("(Automated)", "").replace("()", "").strip()
    return t

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='config/config.yaml')
    args = parser.parse_args()

    cfg = load_config(args.config)
    
    # 1. Parse Rules
    pdf_path = cfg['audit']['benchmark_pdf']
    if not os.path.exists(pdf_path):
        print(f"[!] PDF not found: {pdf_path}")
        sys.exit(1)
        
    print(f"[*] Parsing PDF...", end="\r")
    engine = CISPdfParser(pdf_path)
    rules = engine.parse()
    print(f"\n[+] Loaded {len(rules)} Unique Rules.")

    # 2. Init Driver
    try:
        driver = get_driver(cfg)
        driver.connect()
    except Exception as e:
        print(f"[!] Driver Init Failed: {e}")
        sys.exit(1)

    # 3. Execution
    audit_results = []
    print("\n" + "="*140)
    # Added NO. column and increased TITLE width
    print(f"{'NO.':<4} {'TIME':<9} {'TYPE':<7} {'ID':<8} {'STATUS':<7} {'TITLE':<60} {'RESULT'}")
    print("="*140)
    
    for idx, rule in enumerate(rules, 1):
        rule_result = "PASS"
        rule_checks = []
        found_result = "None"
        clean_t = clean_title(rule['title'])
        
        # Determine Type
        if not rule.get('checks'):
            rule_result = "MANUAL"
            check_type = "MANUAL"
        else:
            check_type = "AUTO"
            for check in rule['checks']:
                res = driver.execute_check(check['type'], check['cmd'])
                
                check_record = {
                    'cmd': check['cmd'],
                    'output': res['output'],
                    'status': res['status']
                }
                rule_checks.append(check_record)
                
                if res['status'] in ['FAIL', 'ERROR']:
                    rule_result = "FAIL"
                    found_result = clean_output(res['output'])
                elif rule_result == "PASS":
                    # If passing, capture the output too (e.g. "TRUE")
                    found_result = clean_output(res['output'])

        # --- THE LOGGING LINE ---
        # Color coding
        if rule_result == "FAIL": color = Fore.RED
        elif rule_result == "MANUAL": color = Fore.YELLOW
        else: color = Fore.GREEN
        
        # Format: [NO] [TIME] [TYPE] [ID] [STATUS] [TITLE] [RESULT]
        print(f"{Style.DIM}{idx:<4}{get_time()}{Style.RESET_ALL} "
              f"{check_type:<7} "
              f"{rule['id']:<8} "
              f"{color}{rule_result:<7}{Style.RESET_ALL} "
              f"{clean_t:<60} "
              f"{found_result}")

        audit_results.append({
            "id": rule['id'],
            "title": clean_t,
            "result": rule_result,
            "checks": rule_checks
        })

    # 4. Report
    reporter = Reporter(cfg['reporting']['output_dir'])
    report_file = reporter.generate(audit_results, cfg['target']['host'])
    
    print("\n" + "="*140)
    print(f"[+] Report generated: {report_file}")
    driver.disconnect()

if __name__ == "__main__":
    main()