import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.core.metadata import collect_metadata
from src.core.reporter import Reporter


class MetadataTests(unittest.TestCase):
    def test_database_identity_and_pdf_cover(self):
        for vendor in ('oracle', 'sqlserver'):
            with self.subTest(vendor=vendor):
                driver = Mock()
                driver.conn.version = '19.3.0.0.0'
                cursor = driver.conn.cursor.return_value
                cursor.fetchone.return_value = ('testdb', '14.0.3550.4')
                page = Mock()
                page.extract_text.return_value = 'CIS Microsoft SQL Server 2017\nBenchmark\nv1.3.0'
                with patch('src.core.metadata.pdfplumber.open') as pdf:
                    pdf.return_value.__enter__.return_value.pages = [page]
                    result = collect_metadata({'target': {'driver': vendor},
                                               'audit': {'benchmark_pdf': '/tmp/renamed.pdf'}}, driver)
                self.assertEqual(result['database']['name'], 'testdb')
                self.assertEqual(result['database']['version'],
                                 '19.3.0.0.0' if vendor == 'oracle' else '14.0.3550.4')
                self.assertEqual(result['benchmark']['version'], '1.3.0')
                self.assertEqual(result['benchmark']['name'], 'CIS Microsoft SQL Server 2017 Benchmark')
                cursor.close.assert_called_once()

    def test_unavailable_metadata_does_not_abort(self):
        driver = Mock()
        driver.conn.cursor.side_effect = RuntimeError('unavailable')
        result = collect_metadata({'target': {'driver': 'sqlserver'}, 'audit': {}}, driver)
        self.assertEqual(result['database']['version'], 'Unknown')
        self.assertEqual(result['benchmark']['version'], 'Unknown')

    def test_metadata_in_all_reports(self):
        metadata = {'database': {'product': 'Oracle Database', 'name': 'TEST', 'version': '19.3'},
                    'benchmark': {'name': 'CIS Oracle Database Benchmark', 'version': '1.0.0'}}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(output):
            path = Reporter(tmp).generate([], 'offline', metadata)
            text = Path(path).read_text()
            data = json.loads(next(Path(tmp).glob('*.json')).read_text())
        self.assertEqual(data['summary']['database'], metadata['database'])
        self.assertEqual(data['summary']['benchmark'], metadata['benchmark'])
        for value in ('TEST', '19.3', 'CIS Oracle Database Benchmark', '1.0.0'):
            self.assertIn(value, text)
            self.assertIn(value, output.getvalue())