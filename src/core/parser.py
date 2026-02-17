import pdfplumber
import re
import logging
import sys

logger = logging.getLogger(__name__)

class CISPdfParser:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path

    def parse(self):
        full_text = self._extract_text()
        logger.info("\nProcessing extracted text...")
        full_text = self._fix_ocr(full_text)
        return self._extract_rules(full_text)

    def _extract_text(self):
        text = ""
        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                total_pages = len(pdf.pages)
                print(f"[INFO] Opening PDF with {total_pages} pages...")
                
                for i, page in enumerate(pdf.pages):
                    sys.stdout.write(f"\r[INFO] Parsing Page {i+1}/{total_pages}...")
                    sys.stdout.flush()
                    
                    page_content = page.extract_text(layout=False)
                    if page_content:
                        text += page_content + "\n"
                print("") 
        except Exception as e:
            logger.critical(f"Failed to open PDF: {e}")
            sys.exit(1)
        return text

    def _fix_ocr(self, text):
        replacements = {
            'VSSYSTEM': 'V$SYSTEM', 'VSPDBS': 'V$PDBS',
            'VDATABASE': 'V$DATABASE', '$ ORACLE': '$ORACLE'
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def _extract_rules(self, text):
        # Use a Dictionary to prevent duplicates (TOC vs Body)
        # Key: Rule ID (e.g., "1.1"), Value: Rule Object
        rules_map = {}
        
        rule_pattern = re.compile(r"^\s*(\d+\.\d+(\.\d+)*)\s+(Ensure.*)")
        sql_pattern = re.compile(r"((?:SELECT|WITH)\s+[\s\S]+?)(?:;|(?=\n\s*(?:Lack|To assess|Remediation|Audit:|Note:)))", re.IGNORECASE)
        
        lines = text.split('\n')
        current_rule = None
        audit_buffer = ""

        for line in lines:
            line = line.strip()
            if not line: continue

            # Stop at Appendix
            if line.startswith("7 Appendix") and "..." not in line:
                break

            match = rule_pattern.match(line)
            if match:
                # 1. Save Previous Rule
                if current_rule:
                    self._process_checks(current_rule, audit_buffer, sql_pattern)
                    
                    # LOGIC: Only save if it has checks OR if it's a new ID we haven't seen.
                    # If we already have this ID and the new one has no checks, ignore it.
                    # If we already have this ID (from TOC) and now we found checks, OVERWRITE it.
                    
                    r_id = current_rule['id']
                    
                    # If this is the first time seeing this ID, save it.
                    if r_id not in rules_map:
                        rules_map[r_id] = current_rule
                    else:
                        # If we already saw it (likely TOC), but now we found checks, Update it!
                        if current_rule['checks']:
                            rules_map[r_id] = current_rule
                
                # 2. Start New Rule
                current_rule = {'id': match.group(1), 'title': match.group(3), 'checks': []}
                audit_buffer = ""
                continue

            if line.startswith("Audit:"):
                audit_buffer = line + "\n"
            elif any(line.startswith(x) for x in ["Remediation:", "Impact:"]):
                continue
            elif current_rule:
                audit_buffer += line + " "

        # Save Last Rule
        if current_rule:
            self._process_checks(current_rule, audit_buffer, sql_pattern)
            r_id = current_rule['id']
            if current_rule['checks'] or r_id not in rules_map:
                rules_map[r_id] = current_rule
                
        # Return list sorted by ID
        return list(rules_map.values())

    def _process_checks(self, rule, text, sql_regex):
        sqls = sql_regex.findall(text)
        for q in sqls:
            if isinstance(q, tuple): q = q[0]
            clean_q = q.strip()
            if clean_q.upper().startswith("SELECT") or clean_q.upper().startswith("WITH"):
                rule['checks'].append({'type': 'sql', 'cmd': clean_q})

        words = text.split(' ')
        for i, word in enumerate(words):
            if word in ['grep', 'find', 'ls', 'opatch']:
                cmd = " ".join(words[i:i+15]).replace("Windows environment:", "")
                if "%ORACLE_HOME%" not in cmd and "find /I" not in cmd:
                    rule['checks'].append({'type': 'shell', 'cmd': cmd})
                break