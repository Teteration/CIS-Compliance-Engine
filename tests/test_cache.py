import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.cache import RulesCache
from src.core.parser import CISPdfParser


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.pdf = self.root / 'benchmark.pdf'
        self.pdf.write_bytes(b'document one')
        self.path = self.root / 'nested' / 'rules.json'
        self.cache = RulesCache(self.path)
        self.parser = CISPdfParser(str(self.pdf))
        self.rules = [{'id': '1.1', 'title': 'Ensure test', 'audit_text': 'SELECT 1;',
                       'checks': [{'type': 'sql', 'cmd': 'SELECT 1'}]}]
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)

    def test_first_run_saves_second_run_does_not_parse(self):
        with patch.object(self.parser, 'parse', return_value=self.rules) as parse:
            self.assertEqual(self.cache.load_or_parse(self.parser), self.rules)
            self.assertEqual(self.cache.load_or_parse(self.parser), self.rules)
            parse.assert_called_once()
        self.assertEqual(json.loads(self.path.read_text())['version'], RulesCache.VERSION)

    def test_changed_document_and_vendor_keep_separate_entries(self):
        with patch.object(self.parser, 'parse', return_value=self.rules) as parse:
            self.cache.load_or_parse(self.parser)
            self.pdf.write_bytes(b'document two')
            self.cache.load_or_parse(self.parser)
            self.parser.vendor = 'sqlserver'
            self.cache.load_or_parse(self.parser)
            self.parser.vendor = 'mssql'
            self.cache.load_or_parse(self.parser)
            self.assertEqual(parse.call_count, 3)
        self.assertEqual(len(json.loads(self.path.read_text())['entries']), 3)

    def test_refresh_and_deleted_cache_reparse(self):
        with patch.object(self.parser, 'parse', return_value=self.rules) as parse:
            self.cache.load_or_parse(self.parser)
            self.cache.load_or_parse(self.parser, refresh=True)
            self.path.unlink()
            self.cache.load_or_parse(self.parser)
            self.assertEqual(parse.call_count, 3)

    def test_corrupt_or_incompatible_cache_rebuilt(self):
        self.path.parent.mkdir()
        for content in ('invalid JSON', '[]', '{"version": 999, "entries": {}}'):
            with self.subTest(content=content):
                self.path.write_text(content)
                with patch.object(self.parser, 'parse', return_value=self.rules) as parse:
                    self.cache.load_or_parse(self.parser)
                    parse.assert_called_once()

    def test_invalid_cached_rules_rebuilt(self):
        with patch.object(self.parser, 'parse', return_value=self.rules):
            self.cache.load_or_parse(self.parser)
        data = json.loads(self.path.read_text())
        next(iter(data['entries'].values()))['rules'] = [{'id': '1.1'}]
        self.path.write_text(json.dumps(data))
        with patch.object(self.parser, 'parse', return_value=self.rules) as parse:
            self.cache.load_or_parse(self.parser)
            parse.assert_called_once()

    def test_parser_source_change_invalidates_entry(self):
        original = self.cache._digest
        with patch.object(self.parser, 'parse', return_value=self.rules):
            self.cache.load_or_parse(self.parser)
        with patch.object(self.cache, '_digest', side_effect=lambda p: original(p) if str(p) == str(self.pdf) else 'new-parser'), \
                patch.object(self.parser, 'parse', return_value=self.rules) as parse:
            self.cache.load_or_parse(self.parser)
            parse.assert_called_once()

    def test_write_failure_still_returns_rules(self):
        self.path.parent.mkdir()
        self.path.mkdir()
        with patch.object(self.parser, 'parse', return_value=self.rules):
            self.assertEqual(self.cache.load_or_parse(self.parser), self.rules)
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])

    def test_failed_extraction_is_not_cached(self):
        with patch.object(self.parser, 'parse', side_effect=ValueError('wrong benchmark')):
            with self.assertRaises(ValueError):
                self.cache.load_or_parse(self.parser)
        self.assertFalse(self.path.exists())


if __name__ == '__main__':
    unittest.main()