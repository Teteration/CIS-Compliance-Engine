import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.core.parser import CISPdfParser
from src.core.sqlserver_checks import REGISTRY_CHECKS
from src.drivers.sqlserver import SQLServerDriver
from src.main import run_audit


class RegistryTests(unittest.TestCase):
    def test_registry_pass_fail_and_invalid_values(self):
        for name, cases in {
            'hide_instance': [(1, 'PASS'), (0, 'FAIL'), (None, 'ERROR')],
            'error_log_count': [(12, 'PASS'), (20, 'PASS'), (11, 'FAIL'), (-1, 'FAIL')],
        }.items():
            definition = REGISTRY_CHECKS[name]
            text = '1.1 Ensure setting (Automated)\nAudit:\n' + definition['source'] + '\nRemediation:\n'
            rule = CISPdfParser('unused', 'sqlserver')._extract_rules(text)[0]
            self.assertEqual(rule['assessment_type'], 'AUTOMATED')
            check = rule['checks'][0]
            self.assertEqual(check['type'], 'sqlserver_registry')
            for value, status in cases:
                with self.subTest(name=name, value=value):
                    driver = SQLServerDriver({}); driver.cursor = Mock()
                    driver.cursor.description = [('value',)]
                    driver.cursor.fetchall.return_value = [(value,)]
                    self.assertEqual(driver.execute_policy(check)['status'], status)
                    driver.cursor.execute.assert_called_once_with('SET NOCOUNT ON;\n' + definition['source'])

    def test_registry_rejects_modified_commands(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        for command in ('EXEC evil', REGISTRY_CHECKS['hide_instance']['source'] + ' DROP TABLE x;'):
            result = driver.execute_policy({'type': 'sqlserver_registry', 'operation': 'hide_instance', 'cmd': command})
            self.assertEqual(result['status'], 'SKIPPED')
        driver.cursor.execute.assert_not_called()

    def test_registry_missing_results_and_permissions(self):
        check = {'type': 'sqlserver_registry', 'operation': 'hide_instance',
                 'cmd': REGISTRY_CHECKS['hide_instance']['source']}
        driver = SQLServerDriver({}); driver.cursor = Mock()
        driver.cursor.description = None
        driver.cursor.nextset.return_value = None
        self.assertEqual(driver.execute_policy(check)['status'], 'ERROR')
        driver.cursor.execute.side_effect = RuntimeError('permission denied')
        self.assertIn('permission denied', driver.execute_policy(check)['output'])

    def test_source_type_is_independent_of_execution_result(self):
        rules = [
            {'id': '1.1', 'title': 'Ensure automatic', 'assessment_type': 'AUTOMATED',
             'checks': [{'type': 'sql', 'cmd': 'SELECT 1'}]},
            {'id': '1.2', 'title': 'Ensure manual', 'assessment_type': 'MANUAL',
             'checks': [{'type': 'sql', 'cmd': 'SELECT 2'}]},
        ]
        driver = Mock()
        driver.execute_policy.return_value = {'status': 'MANUAL', 'output': 'No expectation'}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            run_audit({'audit': {}, 'target': {'host': 'offline'}, 'reporting': {'output_dir': tmp}}, rules, driver)
            report = json.loads(next(Path(tmp).glob('*.json')).read_text())
        self.assertEqual([r['result'] for r in report['results']], ['SKIPPED', 'MANUAL'])
        self.assertEqual(report['summary']['stats']['automated'], 1)
        self.assertEqual(report['summary']['stats']['declared_manual'], 1)
        self.assertEqual(report['summary']['automation_completion'], '0.00%')
        driver.execute_policy.assert_called_once()