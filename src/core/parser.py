import pdfplumber
import re
import logging
import sys

logger = logging.getLogger(__name__)

class CISPdfParser:
    def __init__(self, pdf_path, vendor='oracle'):
        self.pdf_path = pdf_path
        self.vendor = vendor

    def parse(self):
        full_text = self._extract_text()
        header = full_text[:10000].lower()
        if self.vendor == 'oracle' and 'sql server' in header and 'benchmark' in header:
            raise ValueError('SQL Server benchmark cannot be used with the Oracle driver')
        if self.vendor in ('sqlserver', 'mssql') and 'oracle database' in header and 'benchmark' in header:
            raise ValueError('Oracle benchmark cannot be used with the SQL Server driver')
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
        in_audit = False

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
                    r_id = current_rule['id']
                    
                    # If this is the first time seeing this ID, save it.
                    if r_id not in rules_map:
                        rules_map[r_id] = current_rule
                    else:
                        # If we already saw it (likely TOC), but now we found checks, Update it!
                        if current_rule['audit_text']:
                            rules_map[r_id] = current_rule
                
                # 2. Start New Rule
                current_rule = {'id': match.group(1), 'title': match.group(3), 'checks': []}
                audit_buffer = ""
                in_audit = False
                continue

            if line.startswith("Audit:"):
                in_audit = True
                audit_buffer = line[len('Audit:'):] + "\n"
            elif any(line.startswith(x) for x in ["Remediation:", "Impact:", "Default Value:", "References:", "CIS Controls:"]):
                in_audit = False
            elif current_rule and in_audit:
                if not re.match(r'^Page\s+\d+', line):
                    audit_buffer += line + "\n"

        # Save Last Rule
        if current_rule:
            self._process_checks(current_rule, audit_buffer, sql_pattern)
            r_id = current_rule['id']
            if current_rule['audit_text'] or r_id not in rules_map:
                rules_map[r_id] = current_rule
                
        # Return list sorted by ID
        def parse_id(rid):
            try: return tuple(map(int, rid.split('.')))
            except: return (0,)
        return sorted(rules_map.values(), key=lambda x: parse_id(x['id']))

    def _process_checks(self, rule, text, sql_regex):
        rule['audit_text'] = text.strip()
        sqls = sql_regex.findall(text)
        for q in sqls:
            if isinstance(q, tuple): q = q[0]
            clean_q = q.strip()
            if clean_q.upper().startswith("SELECT") or clean_q.upper().startswith("WITH"):
                check = {'type': 'sql', 'cmd': clean_q}
                if self.vendor in ('sqlserver', 'mssql'):
                    # Narrow inference only: configuration values explicitly specified by audit prose.
                    expected = re.search(r'Both\s+value\s+columns\s+must\s+show\s+([01])\b', text, re.I)
                    if expected and 'sys.configurations' in clean_q.lower() and all(c in clean_q.lower() for c in ('value_configured', 'value_in_use')):
                        value = int(expected.group(1))
                        check['expectation'] = {'mode': 'columns_equal', 'columns': {'value_configured': value, 'value_in_use': value}}
                rule['checks'].append(check)

        # Preserve command lines rather than appending arbitrary prose words.
        for line in text.splitlines():
            cmd = re.sub(r'^\$\s+', '', line.strip())
            if re.match(r'^(grep|find|ls|opatch)\s+', cmd):
                if '%ORACLE_HOME%' not in cmd and not cmd.startswith('find /I'):
                    rule['checks'].append({'type': 'shell', 'cmd': cmd})