import pdfplumber
import re
import json
import oracledb
import paramiko
import os
import getpass
import sys
import time

# ================= CONFIGURATION =================
PDF_FILENAME = ""
JSON_FILENAME = ""
REPORT_FILENAME = ""

# --- Database Configuration ---
DB_HOST = ""
DB_PORT = 1521
DB_SERVICE = ""
DB_USER = ""
DB_PASSWORD = ""

# --- SSH Configuration ---
SSH_HOST = ""
SSH_USER = ""
SSH_PORT = 22

# ================= PART 1: EXTRACTOR =================

def fix_ocr_typos(text):
    text = re.sub(r'VSSYSTEM', 'V$SYSTEM', text, flags=re.IGNORECASE)
    text = re.sub(r'VSPDBS', 'V$PDBS', text, flags=re.IGNORECASE)
    text = re.sub(r'VDATABASE', 'V$DATABASE', text, flags=re.IGNORECASE)
    text = re.sub(r'VINSTANCE', 'V$INSTANCE', text, flags=re.IGNORECASE)
    text = re.sub(r'\$ ORACLE', '$ORACLE', text)
    return text

def extract_benchmark_data(pdf_path):
    audit_rules = []
    
    # Matches "1.1 Ensure..."
    title_pattern = re.compile(r"^\s*(\d+\.\d+(\.\d+)*)\s+(Ensure.*)")
    
    # Matches SQL
    sql_pattern = re.compile(r"((?:SELECT|WITH)\s+[\s\S]+?)(?:;|(?=\n\s*(?:Lack|To assess|Remediation|Audit:|Note:)))", re.IGNORECASE)
    
    print(f"[*] Parsing PDF structure from: {pdf_path}...")
    
    full_text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            total_pages = len(pdf.pages)
            for i, page in enumerate(pdf.pages):
                # Simple progress bar
                print(f"    Processing page {i+1}/{total_pages}...", end="\r")
                page_text = page.extract_text(layout=False)
                if page_text:
                    full_text += page_text + "\n"
        print("\n[+] PDF Text Extraction Complete.")
    except FileNotFoundError:
        print(f"[-] CRITICAL: File {pdf_path} not found.")
        sys.exit(1)

    full_text = fix_ocr_typos(full_text)
    lines = full_text.split('\n')
    
    current_rule = {}
    
    # State flags
    state = "SEARCHING"
    audit_buffer = ""
    desc_buffer = ""
    rationale_buffer = ""
    
    print("[*] Analyzing text for Rules and Checks...")
    
    for line in lines:
        line = line.strip()
        if not line: continue

        match = title_pattern.match(line)
        if match:
            if current_rule:
                process_buffer(current_rule, audit_buffer, sql_pattern)
                if current_rule['description'] or current_rule['checks']:
                    audit_rules.append(current_rule)
            
            current_rule = {
                "id": match.group(1),
                "title": match.group(3),
                "description": "",
                "rationale": "",
                "checks": []
            }
            state = "SEARCHING"
            audit_buffer = ""
            desc_buffer = ""
            rationale_buffer = ""
            continue

        # Filters
        if "CIS Controls" in line or "Page" in line and len(line) < 10:
            continue

        # State Machine
        if line.startswith("Description:"):
            state = "DESCRIPTION"
            continue
        elif line.startswith("Rationale:"):
            state = "RATIONALE"
            continue
        elif line.startswith("Audit:"):
            state = "AUDIT"
            continue
        elif any(line.startswith(x) for x in ["Remediation:", "Impact:", "References:", "Default Value:"]):
            state = "SEARCHING"
            continue

        if state == "DESCRIPTION":
            desc_buffer += line + " "
            current_rule['description'] = desc_buffer.strip()
        elif state == "RATIONALE":
            rationale_buffer += line + " "
            current_rule['rationale'] = rationale_buffer.strip()
        elif state == "AUDIT":
            audit_buffer += line + "\n"

    if current_rule:
        process_buffer(current_rule, audit_buffer, sql_pattern)
        audit_rules.append(current_rule)

    print(f"[+] Found {len(audit_rules)} potential rules.")
    return audit_rules

def process_buffer(rule_dict, buffer_text, sql_regex):
    # SQL
    sqls = sql_regex.findall(buffer_text)
    for q in sqls:
        if isinstance(q, tuple): q = q[0]
        clean_q = re.sub(r'\s+', ' ', q).strip()
        rule_dict['checks'].append({'type': 'sql', 'cmd': clean_q})

    # Shell
    lines = buffer_text.split('\n')
    for line in lines:
        line = line.strip()
        if re.match(r'^(grep|find|ls|opatch)\s+', line):
            if "%ORACLE_HOME%" in line or "find /I" in line or "find / I" in line:
                continue
            rule_dict['checks'].append({'type': 'shell', 'cmd': line})

# ================= PART 2: RUNNER =================

def run_audit(rules):
    print("\n" + "="*50)
    print("STARTING AUDIT EXECUTION")
    print("="*50)
    
    # --- SSH ---
    print(f"\n[*] Connecting to OS via SSH ({SSH_USER}@{SSH_HOST})...")
    ssh_password = getpass.getpass(f"    Enter SSH Password for {SSH_USER}: ")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=ssh_password)
        print("    [+] SSH Connection Established.")
    except Exception as e:
        print(f"    [-] SSH Connection Failed: {e}")
        return

    # --- DB ---
    print(f"\n[*] Connecting to DB via Oracle Net ({DB_USER}@{DB_SERVICE})...")
    conn = None
    cursor = None
    try:
        dsn = f"{DB_HOST}:{DB_PORT}/{DB_SERVICE}"
        conn = oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=dsn)
        cursor = conn.cursor()
        print(f"    [+] DB Connection Established.")
    except oracledb.Error as e:
        print(f"    [-] DB Connection Failed: {e}")

    # Stats
    total_checked = 0
    passed = 0
    failed = 0
    manual = 0

    with open(REPORT_FILENAME, "w") as f:
        f.write(f"CIS Benchmark Audit Report\n")
        f.write(f"Target: {DB_HOST} | Service: {DB_SERVICE}\n")
        f.write("="*80 + "\n\n")

        for rule in rules:
            rid = rule['id']
            title = rule['title']
            checks = rule.get('checks', [])

            if not checks:
                manual += 1
                # print(f"[SKIP] Rule {rid}: Manual check required") 
                continue

            total_checked += 1
            rule_failed = False
            
            # === VERBOSE LOGGING ===
            print(f"\n[+] Rule {rid}: {title[:60]}...") 
            
            output_buffer = f"{title}\n"
            if rule['description']: output_buffer += f"Desc: {rule['description'][:200]}...\n"
            output_buffer += "-"*40 + "\n"

            for check in checks:
                cmd = check['cmd']
                ctype = check['type']

                if ctype == 'sql':
                    if cursor:
                        print(f"    [*] SQL Check: {cmd[:50]}...")
                        try:
                            cursor.execute(cmd.rstrip(';'))
                            rows = cursor.fetchall()
                            if rows:
                                rule_failed = True
                                print(f"        [X] FAIL: {len(rows)} rows returned.")
                                output_buffer += f"  [FAIL] SQL: {cmd[:60]}...\n"
                                output_buffer += f"         Out: {str(rows)[:200]}\n"
                            else:
                                print(f"        [✓] PASS")
                                output_buffer += f"  [PASS] SQL: {cmd[:60]}...\n"
                        except Exception as e:
                            print(f"        [!] ERROR: {e}")
                            output_buffer += f"  [ERROR] SQL: {e}\n"
                            rule_failed = True
                    else:
                        print(f"        [!] SKIPPED (No DB Conn)")

                elif ctype == 'shell':
                    print(f"    [*] Shell Check: {cmd[:50]}...")
                    cmd = cmd.replace('$ ', '$').replace('% ', '%')
                    try:
                        full_cmd = f"source ~/.bash_profile 2>/dev/null; {cmd}"
                        stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=5)
                        out = stdout.read().decode().strip()
                        
                        if out:
                            rule_failed = True
                            print(f"        [X] FAIL: Output found.")
                            output_buffer += f"  [FAIL] Shell: {cmd}\n"
                            output_buffer += f"         Out: {out}\n"
                        else:
                            print(f"        [✓] PASS")
                            output_buffer += f"  [PASS] Shell: {cmd}\n"
                    except Exception as e:
                        print(f"        [!] ERROR: {e}")
                        output_buffer += f"  [ERROR] SSH: {e}\n"

            if rule_failed:
                failed += 1
                f.write(output_buffer + "Result: FAIL\n")
            else:
                passed += 1
                f.write(output_buffer + "Result: PASS\n")
            
            f.write("="*80 + "\n\n")

        score = (passed / total_checked * 100) if total_checked > 0 else 0
        summary = f"""
        ==================================================
        COMPLIANCE SUMMARY
        ==================================================
        Total Automated Rules Checked: {total_checked}
        Passed: {passed}
        Failed: {failed}
        Manual Checks Skipped: {manual}
        
        FINAL SCORE: {score:.2f}%
        ==================================================
        """
        f.write(summary)
        print("\n" + summary)

    print(f"[+] Full details saved to {REPORT_FILENAME}")
    if conn: conn.close()
    ssh.close()

if __name__ == "__main__":
    # Always regenerate JSON to ensure clean state
    if os.path.exists(JSON_FILENAME):
        os.remove(JSON_FILENAME)
    
    data = extract_benchmark_data(PDF_FILENAME)
    with open(JSON_FILENAME, 'w') as jf:
        json.dump(data, jf, indent=4)
        
    run_audit(data)