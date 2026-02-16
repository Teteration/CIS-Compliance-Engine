import pdfplumber
import re
import logging

logger = logging.getLogger(__name__)

class CISPdfParser:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.rules = []

    def parse(self):
        logger.info(f"Parsing PDF: {self.pdf_path}")
        full_text = self._extract_text()
        full_text = self._fix_ocr(full_text)
        return self._extract_rules(full_text)

    def _extract_text(self):
        text = ""
        with pdfplumber.open(self.pdf_path) as pdf:
            for page in pdf.pages:
                text += (page.extract_text(layout=False) or "") + "\n"
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
        rules = []
        # Regex: ID + Title containing "Ensure"
        rule_pattern = re.compile(r"^\s*(\d+\.\d+(\.\d+)*)\s+(Ensure.*)")
        sql_pattern = re.compile(r"((?:SELECT|WITH)\s+[\s\S]+?)(?:;|(?=\n\s*(?:Lack|To assess|Remediation|Audit:|Note:)))", re.IGNORECASE)
        
        lines = text.split('\n')
        current_rule = None
        audit_buffer = ""
        
        for line in lines:
            line = line.strip()
            if not line: continue

            match = rule_pattern.match(line)
            if match:
                if current_rule:
                    self._process_checks(current_rule, audit_buffer, sql_pattern)
                    # Filter out empty/garbage rules
                    if current_rule['checks']:
                        rules.append(current_rule)
                
                current_rule = {'id': match.group(1), 'title': match.group(3), 'checks': []}
                audit_buffer = ""
                continue

            if line.startswith("Audit:"):
                # Start capturing audit text
                audit_buffer = line + "\n"
            elif any(line.startswith(x) for x in ["Remediation:", "Impact:"]):
                # Stop capturing
                continue
            elif current_rule:
                audit_buffer += line + " "

        if current_rule:
            self._process_checks(current_rule, audit_buffer, sql_pattern)
            if current_rule['checks']:
                rules.append(current_rule)
                
        return rules

    def _process_checks(self, rule, text, sql_regex):
        # SQL Checks
        sqls = sql_regex.findall(text)
        for q in sqls:
            if isinstance(q, tuple): q = q[0]
            rule['checks'].append({'type': 'sql', 'cmd': q.strip()})

        # Shell Checks (Heuristic)
        words = text.split(' ')
        for i, word in enumerate(words):
            if word in ['grep', 'find', 'ls', 'opatch']:
                cmd = " ".join(words[i:i+15]).replace("Windows environment:", "")
                if "%ORACLE_HOME%" not in cmd and "find /I" not in cmd:
                    rule['checks'].append({'type': 'shell', 'cmd': cmd})
                break