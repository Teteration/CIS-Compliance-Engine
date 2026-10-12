import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.core.parser import CISPdfParser
from src.drivers.oracle import OracleDriver
from src.drivers.sqlserver import SQLServerDriver
from src.main import aggregate_status, get_driver, run_audit, main


class AuditTests(unittest.TestCase):
    def test_long_titles_keep_result_column_aligned(self):
        for title_length in (80, 160):
            with self.subTest(title_length=title_length), tempfile.TemporaryDirectory() as tmp:
                titles = ['Ensure short title', 'Ensure ' + 'x' * title_length]
                rules = [{'id': f'1.{idx}', 'title': title,
                          'checks': [{'type': 'sql', 'cmd': 'SELECT 1'}]}
                         for idx, title in enumerate(titles, 1)]
                driver = Mock()
                driver.execute_policy.return_value = {'status': 'PASS', 'output': 'RESULT_MARKER'}
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    run_audit({'audit': {}, 'target': {'host': 'offline'},
                               'reporting': {'output_dir': tmp}}, rules, driver)
                lines = re.sub(r'\x1b\[[0-9;]*m', '', output.getvalue()).splitlines()
                header = next(line for line in lines if line.startswith('NO.'))
                rows = [line for line in lines if 'RESULT_MARKER' in line]
                self.assertEqual(len(rows), 2)
                for row, title in zip(rows, titles):
                    self.assertIn(title, row)
                    self.assertEqual(row.index('RESULT_MARKER'), header.index('RESULT'))

    def test_statuses(self):
        for status in ('PASS', 'FAIL', 'ERROR', 'SKIPPED', 'MANUAL'):
            self.assertEqual(aggregate_status([{'status': status}]), status)
        self.assertEqual(aggregate_status([{'status': 'PASS'}, {'status': 'SKIPPED'}]), 'SKIPPED')

    def test_driver_selection(self):
        self.assertIsInstance(get_driver({'target': {'driver': 'sqlserver'}}), SQLServerDriver)
        self.assertIsInstance(get_driver({'target': {'driver': 'oracle'}}), OracleDriver)

    def test_oracle_without_ssh(self):
        driver = OracleDriver({'host': 'offline', 'connection': {
            'port': 1521, 'service_name': 'test', 'user': 'audit', 'password': 'test'}})
        with patch('src.drivers.oracle.oracledb.connect') as connect, patch('paramiko.SSHClient') as ssh:
            driver.connect()
            connect.assert_called_once()
            ssh.assert_not_called()
            self.assertEqual(driver.execute_check('shell', 'grep test file')['status'], 'SKIPPED')
            driver.disconnect()

    def test_ssh_failure_does_not_break_database(self):
        driver = SQLServerDriver({'host': 'offline', 'ssh': {'enabled': True, 'user': 'audit'}})
        client = Mock(); client.connect.side_effect = OSError('unreachable')
        with patch('paramiko.SSHClient', return_value=client):
            driver.connect_optional_ssh()
        self.assertIsNone(driver.ssh)
        self.assertIn('unreachable', driver.ssh_reason)
        client.close.assert_called_once()

    def test_sqlserver_connection(self):
        driver = SQLServerDriver({'host': 'offline', 'connection': {'user': 'audit', 'password': 'a;}b'}})
        module = Mock()
        with patch('src.drivers.sqlserver.importlib.import_module', return_value=module):
            driver.connect()
        args = module.connect.call_args
        self.assertIn('PWD={a;}}b}', args.args[0])
        self.assertIn('Encrypt={yes}', args.args[0])
        self.assertEqual(args.kwargs['timeout'], 10)
        driver.disconnect()

    def test_parser_only_audit_and_expected_columns(self):
        text = '''2.1 Ensure setting (Automated)
Audit:
SELECT name, CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations WHERE name = 'example';
Both value columns must show 0.
Remediation:
SELECT secret FROM remediation;
'''
        rule = CISPdfParser('unused', 'sqlserver')._extract_rules(text)[0]
        self.assertEqual(len(rule['checks']), 1)
        self.assertNotIn('remediation', rule['checks'][0]['cmd'])
        self.assertEqual(rule['checks'][0]['expectation']['columns']['value_in_use'], 0)

    def test_sqlserver_values_and_unknown_expectation(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        driver.cursor.description = [('name',), ('value_configured',), ('value_in_use',)]
        check = {'type': 'sql', 'cmd': 'SELECT name, value FROM sys.configurations',
                 'expectation': {'mode': 'columns_equal', 'columns': {'value_configured': 0, 'value_in_use': 0}}}
        for row, expected in [(('setting', 0, 0), 'PASS'), (('setting', 0, 1), 'FAIL')]:
            driver.cursor.fetchall.return_value = [row]
            self.assertEqual(driver.execute_policy(check)['status'], expected)
        self.assertEqual(driver.execute_check('sql', check['cmd'])['status'], 'MANUAL')
        driver.cursor.fetchall.return_value = []
        self.assertEqual(driver.execute_policy(check)['status'], 'MANUAL')

    def test_writes_are_not_executed(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        for sql in ('EXEC sp_configure', 'SELECT 1; DROP TABLE x', 'SELECT * INTO x FROM y'):
            self.assertEqual(driver.execute_check('sql', sql)['status'], 'MANUAL')
        driver.cursor.execute.assert_not_called()

    def test_shell_errors_are_not_passed(self):
        driver = SQLServerDriver({}); driver.ssh = Mock()
        stdout = Mock(); stdout.read.return_value = b''; stdout.channel.recv_exit_status.return_value = 127
        stderr = Mock(); stderr.read.return_value = b'command not found'
        driver.ssh.exec_command.return_value = (None, stdout, stderr)
        self.assertEqual(driver.execute_check('shell', 'grep test file')['status'], 'ERROR')

    def test_report_and_skipped_integration(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            driver = Mock(); driver.execute_policy.return_value = {'status': 'SKIPPED', 'output': 'SSH disabled'}
            run_audit({'audit': {}, 'target': {'host': 'offline'}, 'reporting': {'output_dir': tmp}},
                      [{'id': '1.1', 'title': 'Ensure sample', 'checks': [{'type': 'shell', 'cmd': 'grep test file'}]}], driver)
            report = json.loads(next(Path(tmp).glob('*.json')).read_text())
            self.assertEqual(report['results'][0]['result'], 'SKIPPED')
            self.assertEqual(report['summary']['score'], 'N/A')
            self.assertEqual(report['summary']['coverage'], '0.00%')

    def test_benchmark_mismatch(self):
        parser = CISPdfParser('unused', 'oracle')
        with patch.object(parser, '_extract_text', return_value='CIS Microsoft SQL Server Benchmark'):
            with self.assertRaises(ValueError):
                parser.parse()

    def test_cleanup_on_execution_error(self):
        cfg = {'target': {'driver': 'sqlserver'}, 'audit': {'benchmark_pdf': 'unused', 'rules_cache': None}}
        driver = Mock()
        with patch('src.main.load_config', return_value=cfg), \
                patch('src.main.os.path.exists', return_value=True), \
                patch('src.main.CISPdfParser') as parser, \
                patch('src.main.get_driver', return_value=driver), \
                patch('src.main.run_audit', side_effect=RuntimeError('test')), \
                patch('sys.argv', ['test']), contextlib.redirect_stdout(io.StringIO()):
            parser.return_value.parse.return_value = []
            with self.assertRaises(RuntimeError):
                main()
        driver.disconnect.assert_called_once()

    def test_successful_ssh_runs_extra_checks(self):
        driver = SQLServerDriver({'host': 'offline', 'ssh': {'enabled': True, 'user': 'audit'}})
        client = Mock()
        stdout = Mock(); stdout.read.return_value = b'evidence'; stdout.channel.recv_exit_status.return_value = 0
        stderr = Mock(); stderr.read.return_value = b''
        client.exec_command.return_value = (None, stdout, stderr)
        with patch('paramiko.SSHClient', return_value=client):
            driver.connect_optional_ssh()
        result = driver.execute_check('shell', 'ls /opt/oracle')
        self.assertEqual(result['status'], 'MANUAL')
        self.assertEqual(result['output'], 'evidence')
        client.exec_command.assert_called_once()


if __name__ == '__main__':
    unittest.main()