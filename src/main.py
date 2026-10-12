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
from src.core.cache import RulesCache
from src.core.reporter import Reporter

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
        from src.drivers.oracle import OracleDriver
        return OracleDriver(config['target'])
    elif driver_name in ('sqlserver', 'mssql'):
        from src.drivers.sqlserver import SQLServerDriver
        return SQLServerDriver(config['target'])
    else:
        raise ValueError(f"Unsupported driver: {driver_name}")

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def aggregate_status(checks):
    statuses = {check['status'] for check in checks}
    for status in ('FAIL', 'ERROR', 'SKIPPED', 'MANUAL'):
        if status in statuses:
            return status
    return 'PASS' if statuses == {'PASS'} else 'ERROR'

def clean_output(raw):
    """Clean up the DB output for the log line"""
    s = str(raw).replace("\n", " ").strip()
    if "DPY" in s: return "Error"
    if "No rows" in s: return "Empty"
    # Convert [('VALUE',)] to just VALUE
    s = s.replace("[('", "").replace("',)]", "").replace("')]", "")
    return s[:50] # Truncate if too long

def clean_title(title):
    t = re.sub(r'\.+\s*\d+$', '', title)
    # Remove duplicate (Automated) tags
    t = t.replace("(Automated)", "").replace("()", "").strip()
    return t

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='config/config.yaml')
    parser.add_argument('--refresh-rules', action='store_true', help='Re-extract the PDF and refresh its cached rules')
    args = parser.parse_args()

    cfg = load_config(args.config)
    
    # 1. Parse Rules
    pdf_path = cfg['audit']['benchmark_pdf']
    if not os.path.exists(pdf_path):
        print(f"[!] PDF not found: {pdf_path}")
        sys.exit(1)
        
    print(f"[*] Parsing PDF...", end="\r")
    engine = CISPdfParser(pdf_path, vendor=cfg['target']['driver'])
    try:
        cache_path = cfg['audit'].get('rules_cache', '.cache/rules.json')
        rules = RulesCache(cache_path).load_or_parse(engine, refresh=args.refresh_rules) if cache_path else engine.parse()
    except ValueError as exc:
        print(f'\n[!] Invalid benchmark: {exc}')
        sys.exit(1)
    print(f"\n[+] Loaded {len(rules)} Unique Rules.")

    # 2. Init Driver
    driver = None
    try:
        driver = get_driver(cfg)
        driver.connect()
    except Exception as e:
        if driver is not None:
            driver.disconnect()
        print(f"[!] Driver Init Failed: {e}")
        sys.exit(1)

    try:
        run_audit(cfg, rules, driver)
    finally:
        driver.disconnect()


def run_audit(cfg, rules, driver):
    # 3. Execution
    audit_results = []
    # Use one shared width for the header and every row, without truncating titles.
    title_width = max(100, max((len(clean_title(rule['title'])) for rule in rules), default=0))
    header = f"{'NO.':<4} {'TIME':<9} {'TYPE':<7} {'ID':<8} {'STATUS':<7} {'TITLE':<{title_width}} {'RESULT'}"
    separator = '=' * (len(header) - len('RESULT') + 50)
    print("\n" + separator)
    print(header)
    print(separator)
    
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
                check = dict(check)
                overrides = cfg['audit'].get('expectations', {}).get(rule['id'])
                if overrides:
                    if len(rule['checks']) != 1:
                        res = {'status': 'MANUAL', 'output': 'Expectation override requires exactly one check; review multi-query control'}
                    else:
                        check['expectation'] = overrides
                        res = driver.execute_policy(check)
                else:
                    res = driver.execute_policy(check)
                
                check_record = {
                    'cmd': check['cmd'],
                    'type': check['type'],
                    'output': res['output'],
                    'status': res['status']
                }
                rule_checks.append(check_record)
                
            rule_result = aggregate_status(rule_checks)
            relevant = next((c for c in rule_checks if c['status'] == rule_result), rule_checks[-1])
            found_result = clean_output(relevant['output'])

        # --- THE LOGGING LINE ---
        # Color coding
        if rule_result in ("FAIL", "ERROR"): color = Fore.RED
        elif rule_result in ("MANUAL", "SKIPPED"): color = Fore.YELLOW
        else: color = Fore.GREEN
        
        # Format: [NO] [TIME] [TYPE] [ID] [STATUS] [TITLE] [RESULT]
        print(f"{Style.DIM}{idx:<4} {get_time():<9}{Style.RESET_ALL} "
              f"{check_type:<7} "
              f"{rule['id']:<8} "
              f"{color}{rule_result:<7}{Style.RESET_ALL} "
              f"{clean_t:<{title_width}} "
              f"{found_result}")

        audit_results.append({
            "id": rule['id'],
            "title": clean_t,
            "result": rule_result,
            "audit_text": rule.get('audit_text', ''),
            "checks": rule_checks
        })

    # 4. Report
    reporter = Reporter(cfg['reporting']['output_dir'])
    report_file = reporter.generate(audit_results, cfg['target']['host'])
    
    print("\n" + separator)
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main()