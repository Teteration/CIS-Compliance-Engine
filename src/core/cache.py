import hashlib
import json
import os
from pathlib import Path
import tempfile


class RulesCache:
    """JSON cache of extracted policies, never credentials or audit results."""

    VERSION = 1

    def __init__(self, path):
        self.path = Path(path)

    @staticmethod
    def _digest(path):
        digest = hashlib.sha256()
        with open(path, 'rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _valid_rules(rules):
        if not isinstance(rules, list):
            return False
        for rule in rules:
            if not isinstance(rule, dict):
                return False
            if not all(isinstance(rule.get(key), str) for key in ('id', 'title', 'audit_text')):
                return False
            if not isinstance(rule.get('checks'), list):
                return False
            for check in rule['checks']:
                if not isinstance(check, dict) or not all(isinstance(check.get(key), str) for key in ('type', 'cmd')):
                    return False
                if 'expectation' in check and not isinstance(check['expectation'], dict):
                    return False
        return True

    def load_or_parse(self, parser, refresh=False):
        from . import parser as parser_module
        identity = {
            'pdf_sha256': self._digest(parser.pdf_path),
            'vendor': 'sqlserver' if parser.vendor == 'mssql' else parser.vendor,
            'parser_sha256': self._digest(parser_module.__file__),
        }
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        entries = {}
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(data, dict) and data.get('version') == self.VERSION and isinstance(data.get('entries'), dict):
                entries = data['entries']
        except (OSError, ValueError, UnicodeError):
            pass
        entry = entries.get(key)
        if not refresh and isinstance(entry, dict) and entry.get('identity') == identity and self._valid_rules(entry.get('rules')):
            print(f'[+] Rules loaded from cache: {self.path}')
            return entry['rules']

        print('[*] Rules cache miss; extracting PDF...' if not refresh else '[*] Refreshing rules cache...')
        rules = parser.parse()
        if not self._valid_rules(rules):
            raise ValueError('Parser returned invalid rules; cache not saved')
        entries[key] = {'identity': identity, 'rules': rules}
        temporary_path = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic replacement prevents readers from observing a partial JSON file.
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.path.parent,
                                             prefix=self.path.name + '.', suffix='.tmp', delete=False) as temporary:
                temporary_path = temporary.name
                json.dump({'version': self.VERSION, 'entries': entries}, temporary, ensure_ascii=False, indent=2)
            os.replace(temporary_path, self.path)
            print(f'[+] Rules cached: {self.path}')
        except OSError as exc:
            print(f'[!] Cannot save rules cache; continuing with extracted rules: {exc}')
        finally:
            if temporary_path is not None and os.path.exists(temporary_path):
                os.unlink(temporary_path)
        return rules