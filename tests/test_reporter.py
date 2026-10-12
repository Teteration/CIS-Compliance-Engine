import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from colorama import Fore, Style

from src.core.reporter import Reporter


class ReporterTests(unittest.TestCase):
    def test_summary_colors_do_not_leak_into_reports(self):
        results = [{'id': '1.1', 'title': 'Ensure setting', 'result': 'FAIL',
                    'assessment_type': 'AUTOMATED', 'checks': []}]
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(output):
            Reporter(tmp).generate(results, 'offline')
            for path in Path(tmp).iterdir():
                self.assertNotIn('\x1b', path.read_text())
                self.assertNotIn('\\u001b', path.read_text())
        text = output.getvalue()
        self.assertNotIn('not parser accuracy', text)
        self.assertIn(Fore.LIGHTCYAN_EX, text)
        self.assertIn(Fore.LIGHTRED_EX + '1' + Style.RESET_ALL, text)
        self.assertIn('Automation completion:', text)
        self.assertNotIn('Evaluated Only', text)
        self.assertIn('Of 1 total controls, 1 were evaluated: 0 passed, 1 failed', text)

    def test_score_explanation_for_mixed_and_empty_results(self):
        for statuses in (['PASS', 'FAIL', 'ERROR', 'SKIPPED', 'MANUAL'], [], ['MANUAL']):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as tmp:
                results = [{'id': str(i), 'title': 'Check', 'result': status, 'checks': []}
                           for i, status in enumerate(statuses)]
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    path = Reporter(tmp).generate(results, 'offline')
                for text in (output.getvalue(), Path(path).read_text()):
                    if 'PASS' in statuses:
                        self.assertIn('Of 5 total controls, 2 were evaluated: 1 passed, 1 failed; '
                                      '3 had no PASS/FAIL verdict '
                                      '(1 ERROR, 1 MANUAL, 1 SKIPPED).', text)
                        self.assertIn('Score = 1 passed / 2 evaluated controls.', text)
                    else:
                        self.assertIn(f'Of {len(statuses)} total controls, 0 were evaluated:', text)
                        self.assertIn('Score is N/A because no controls have a PASS/FAIL verdict.', text)

    def test_report_flattens_field_newlines_without_mutating_input(self):
        results = [{'id': '1.1', 'title': 'Ensure\nsetting', 'result': 'MANUAL',
                    'assessment_type': 'MANUAL', 'audit_text': 'First\r\nsecond\rthird',
                    'checks': [{'cmd': 'SELECT\n1', 'type': 'sql',
                                'status': 'MANUAL', 'output': 'line1\nline2'}]}]
        original = copy.deepcopy(results)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            txt_path = Reporter(tmp).generate(results, 'test\nhost')
            report = json.loads(next(Path(tmp).glob('*.json')).read_text())
            text = Path(txt_path).read_text()
        rule = report['results'][0]
        self.assertEqual(rule['title'], 'Ensure setting')
        self.assertEqual(rule['audit_text'], 'First second third')
        self.assertEqual(rule['checks'][0]['cmd'], 'SELECT 1')
        self.assertEqual(rule['checks'][0]['output'], 'line1 line2')
        self.assertEqual(report['summary']['target'], 'test host')
        self.assertIn('   Out: line1 line2\n', text)
        self.assertIn('   Audit procedure: First second third\n', text)
        self.assertIn('   Cmd: SELECT 1...\n', text)
        self.assertEqual(results, original)

    def test_literal_backslashes_and_nonstring_values_are_preserved(self):
        value = {'path': r'C:\new\report', 'count': 2, 'empty': None,
                 'rows': [('first\nsecond', True)]}
        flattened = Reporter._single_line_values(value)
        self.assertEqual(flattened['path'], value['path'])
        self.assertEqual(flattened['count'], 2)
        self.assertIsNone(flattened['empty'])
        self.assertEqual(flattened['rows'], [['first second', True]])