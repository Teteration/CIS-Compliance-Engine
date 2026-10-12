import pdfplumber
import re
import logging
import sys
from .sqlserver_checks import (REGISTRY_CHECKS, SQLSERVER_EXPECTATIONS,
                               SQLSERVER_SPECIAL_CHECKS, registry_check_name)

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
        # Page footers can appear inside SQL that spans multiple PDF pages.
        # Remove only standalone known footer lines, not SQL string literals.
        text = re.sub(r'^[ \t]*Internal Only[ \t]*-[ \t]*General[ \t]*\r?$',
                      '', text, flags=re.MULTILINE | re.IGNORECASE)
        # Use a Dictionary to prevent duplicates (TOC vs Body)
        # Key: Rule ID (e.g., "1.1"), Value: Rule Object
        rules_map = {}
        
        rule_pattern = re.compile(r"^\s*(\d+\.\d+(\.\d+)*)\s+(Ensure.*)")
        # SQL begins on a command line. WITH must introduce a CTE, not audit
        # prose such as "with this recommendation, the output ...".
        identifier = r'(?:[A-Za-z_][\w$#]*|"[^"\n]+"|\[[^\]\n]+\])'
        cte_start = rf'WITH\s+{identifier}(?:\s*\([^()]*\))?\s+AS\s*\('
        sql_pattern = re.compile(
            rf'^[ \t]*((?:SELECT\b\s+|{cte_start})[\s\S]+?)'
            r'(?:;|(?=\n\s*(?:Lack|To assess|Remediation|Audit:|Note:))|\Z)',
            re.IGNORECASE | re.MULTILINE)
        
        lines = text.split('\n')
        current_rule = None
        audit_buffer = ""
        in_audit = False
        in_title = False
        in_controls_table = False
        title_end = re.compile(r'\((?:Automated|Manual)\)|\.{3,}', re.I)
        section_heading = re.compile(
            r'^(?:Profile Applicability|Description|Rationale|Impact|Audit|Remediation|'
            r'Default Value|References|CIS Controls|Additional Information):', re.I)

        for line_index, line in enumerate(lines):
            line = line.strip()
            if not line: continue

            if line.startswith('CIS Controls:'):
                in_controls_table = True
                in_title = False
                in_audit = False
                continue

            # Stop at Appendix
            if line.startswith("7 Appendix") and "..." not in line:
                break

            match = rule_pattern.match(line)
            if match and in_controls_table:
                # CIS framework mapping rows also use IDs and "Ensure" but are
                # not benchmark recommendations. Real body headings are followed
                # by Profile Applicability, including wrapped headings.
                following = lines[line_index + 1:line_index + 13]
                has_profile = False
                for candidate in following:
                    if rule_pattern.match(candidate.strip()):
                        break
                    if candidate.strip().startswith('Profile Applicability:'):
                        has_profile = True
                        break
                if not has_profile:
                    continue
                in_controls_table = False
            elif in_controls_table:
                continue
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
                in_title = not bool(title_end.search(current_rule['title']))
                audit_buffer = ""
                in_audit = False
                continue

            if current_rule and in_title:
                if section_heading.match(line) or re.match(r'^\d+(?:\.\d+)*\s+', line):
                    in_title = False
                elif re.match(r'^Page\s+\d+', line):
                    continue
                else:
                    # Wrapped PDF heading lines form one display/report title.
                    current_rule['title'] += ' ' + line
                    in_title = not bool(title_end.search(line))
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
        assessment = re.search(r'\((Automated|Manual)\)', rule['title'], re.I)
        rule['assessment_type'] = assessment.group(1).upper() if assessment else 'UNKNOWN'
        special_signatures = {
            '3.2': r'DATABASE_PRINCIPAL_ID\s*\(\s*[\'\"]guest[\'\"]\s*\)',
            '3.3': r'EXEC\s+sp_change_users_login',
            '3.4': r'authentication_type\s*=\s*2',
            '5.3': r'EXEC\s+xp_loginconfig\s+[\'\"]audit level[\'\"]',
        }
        if (self.vendor in ('sqlserver', 'mssql') and rule['id'] in SQLSERVER_SPECIAL_CHECKS
                and re.search(special_signatures[rule['id']], text, re.I)):
            definition = SQLSERVER_SPECIAL_CHECKS[rule['id']]
            rule['checks'].append({'type': 'sqlserver_special', 'cmd': definition['source'],
                                   'operation': definition['operation']})
            return
        if self.vendor in ('sqlserver', 'mssql') and re.search(r'^\s*DECLARE\s+@', text, re.I | re.M):
            # Never run the trailing SELECT without its variable initialization.
            # Preserve the batch as evidence; EXEC remains subject to manual review.
            batch = re.search(r'^\s*DECLARE\s+@[\s\S]*?^\s*SELECT\b[\s\S]*?;', text, re.I | re.M)
            command = batch.group().strip() if batch else text.strip()
            name = registry_check_name(command)
            if name and text.count('DECLARE') + text.count('declare') == 1:
                rule['checks'].append({'type': 'sqlserver_registry', 'cmd': command,
                                      'operation': name,
                                      'expectation': dict(REGISTRY_CHECKS[name]['expectation'])})
            else:
                rule['checks'].append({'type': 'manual', 'cmd': command})
            return
        sqls = sql_regex.findall(text)
        for q in sqls:
            if isinstance(q, tuple): q = q[0]
            clean_q = q.strip()
            if clean_q.upper().startswith("SELECT") or clean_q.upper().startswith("WITH"):
                check = {'type': 'sql', 'cmd': clean_q}
                if self.vendor in ('sqlserver', 'mssql'):
                    if (re.search(r'^\s*USE\s+\[?msdb\]?\s*;?\s*$', text, re.I | re.M)
                            and re.fullmatch(
                                r'SELECT\s+sp\.name\s+AS\s+proxyname\s+'
                                r'FROM\s+dbo\.sysproxylogin\s+spl\s+'
                                r'JOIN\s+sys\.database_principals\s+dp\s+'
                                r'ON\s+dp\.sid\s*=\s*spl\.sid\s+'
                                r'JOIN\s+sysproxies\s+sp\s+'
                                r'ON\s+sp\.proxy_id\s*=\s*spl\.proxy_id\s+'
                                r"WHERE\s+principal_id\s*=\s*USER_ID\('public'\)", clean_q, re.I)):
                        # Qualify every table; do not change the connection database.
                        # Resolve public by name in msdb, not USER_ID in master.
                        check['cmd'] = (
                            'SELECT sp.name AS proxyname FROM msdb.dbo.sysproxylogin spl '
                            'JOIN msdb.sys.database_principals dp ON dp.sid = spl.sid '
                            'JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id '
                            "WHERE dp.name = 'public'")
                        if re.search(r'This query should not return any rows', text, re.I):
                            check['expectation'] = {'mode': 'empty_rows'}
                    # Narrow inference only: configuration values explicitly specified by audit prose.
                    expected = re.search(r'Both\s+value\s+columns\s+must\s+show\s+([01])\b', text, re.I)
                    if expected and 'sys.configurations' in clean_q.lower() and all(c in clean_q.lower() for c in ('value_configured', 'value_in_use')):
                        value = int(expected.group(1))
                        check['expectation'] = {'mode': 'columns_equal', 'columns': {'value_configured': value, 'value_in_use': value}}
                    # Benchmark-specific expectations are reviewed constants,
                    # used only for their exact control IDs in this benchmark.
                    if rule['id'] in SQLSERVER_EXPECTATIONS:
                        check['expectation'] = dict(SQLSERVER_EXPECTATIONS[rule['id']])
                rule['checks'].append(check)

        # Preserve command lines rather than appending arbitrary prose words.
        for line in text.splitlines():
            cmd = re.sub(r'^\$\s+', '', line.strip())
            if re.match(r'^(grep|find|ls|opatch)\s+', cmd):
                if '%ORACLE_HOME%' not in cmd and not cmd.startswith('find /I'):
                    rule['checks'].append({'type': 'shell', 'cmd': cmd})