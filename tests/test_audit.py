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
    def test_only_status_column_is_colored(self):
        for status, color in [('PASS', '\x1b[92m'), ('FAIL', '\x1b[91m'),
                              ('ERROR', '\x1b[91m'), ('MANUAL', '\x1b[93m'),
                              ('SKIPPED', '\x1b[94m')]:
            with self.subTest(status=status), patch('src.main.Reporter'):
                rules = [{'id': '1.1', 'title': 'Ensure test',
                          'checks': [{'type': 'sql', 'cmd': 'SELECT 1'}]}]
                driver = Mock()
                driver.execute_policy.return_value = {'status': status, 'output': 'test result'}
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    run_audit({'audit': {}, 'target': {'host': 'offline'},
                               'reporting': {'output_dir': 'unused'}}, rules, driver)
                row = next(line for line in output.getvalue().splitlines() if line.startswith('1 '))
                self.assertEqual(re.findall(r'\x1b\[[0-9;]*m', row), [color, '\x1b[0m'])
                prefix, colored = row.split(color)
                status_text, suffix = colored.split('\x1b[0m')
                self.assertEqual(status_text, f'{status:<7}')
                self.assertIn('UNKNOWN', prefix)
                self.assertTrue(suffix.startswith(' Ensure test'))
                self.assertTrue(suffix.endswith('test result'))

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
                self.assertEqual(header.index('RESULT') - header.index('TITLE'),
                                 min(100, max(map(len, titles))) + 4)
                for row, title in zip(rows, titles):
                    self.assertIn(title[:100], row)
                    self.assertEqual(row.index('RESULT_MARKER'), header.index('RESULT'))

    def test_terminal_limits_preserve_full_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            title = 'Ensure ' + 'x' * 160
            rules = [{'id': '1.1', 'title': title,
                      'checks': [{'type': 'sql', 'cmd': 'SELECT 1'}]}]
            result = 'DPY diagnostic: ' + 'long output value; ' * 20 + 'END_OF_RESULT'
            driver = Mock()
            driver.execute_policy.return_value = {'status': 'ERROR', 'output': result}
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch('src.main.Reporter') as reporter:
                run_audit({'audit': {}, 'target': {'host': 'offline'},
                           'reporting': {'output_dir': tmp}}, rules, driver)
            lines = re.sub(r'\x1b\[[0-9;]*m', '', output.getvalue()).splitlines()
            header = next(line for line in lines if line.startswith('NO.'))
            offset = header.index('RESULT')
            start = next(idx for idx, line in enumerate(lines) if line.startswith('1 '))
            rows = []
            for line in lines[start:]:
                if not line:
                    break
                rows.append(line)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][offset:], result[:70])
            self.assertEqual(rows[0][offset - 4:offset], ' ' * 4)
            self.assertEqual(rows[0][header.index('TITLE'):offset - 4], title[:100])
            report_rules = reporter.return_value.generate.call_args.args[0]
            self.assertEqual(report_rules[0]['title'], title)
            self.assertEqual(report_rules[0]['checks'][0]['output'], result)

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
            connect.assert_called_once_with(user='audit', password='test', dsn='offline:1521/test')
            ssh.assert_not_called()
            self.assertEqual(driver.execute_check('shell', 'grep test file')['status'], 'SKIPPED')
            driver.disconnect()

    def test_oracle_sysdba_connection(self):
        from src.drivers.oracle import oracledb
        driver = OracleDriver({'host': 'offline', 'connection': {
            'port': 1521, 'service_name': 'test', 'user': 'sys',
            'mode': 'SYSDBA', 'password_env': 'CCE_ORACLE_PASSWORD'}})
        with patch.dict('os.environ', {'CCE_ORACLE_PASSWORD': 'test'}), patch('src.drivers.oracle.oracledb.connect') as connect:
            driver.connect()
            connect.assert_called_once_with(user='sys', password='test',
                                            dsn='offline:1521/test', mode=oracledb.AUTH_MODE_SYSDBA)
            driver.disconnect()

    def test_oracle_invalid_auth_configuration(self):
        for settings in ({'mode': 'invalid', 'user': 'sys'},
                         {'mode': 'normal', 'user': 'sys as sysdba'}):
            with self.subTest(settings=settings), patch('src.drivers.oracle.oracledb.connect') as connect:
                driver = OracleDriver({'host': 'offline', 'connection': {
                    'port': 1521, 'service_name': 'test', 'password': 'test', **settings}})
                with self.assertRaises(ValueError):
                    driver.connect()
                connect.assert_not_called()

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

    def test_multiline_rule_titles(self):
        # Wrapped titles still work independently of SQL extraction.
        text = '''6.2 Ensure 'CLR Assembly Permission Set' is set to
'SAFE_ACCESS' for All CLR Assemblies (Automated)
Profile Applicability:
Level 1 - Database Engine
Description:
Description must not become part of the title.
Audit:
SELECT name FROM sys.assemblies;
Remediation:
Review assemblies.
7.1 Ensure encryption
uses a supported
algorithm (Manual)
Description:
Another description.
Audit:
Review manually.
'''
        rules = CISPdfParser('unused', 'sqlserver')._extract_rules(text)
        self.assertEqual(rules[0]['title'], "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Automated)")
        self.assertEqual(len(rules[0]['checks']), 1)
        self.assertEqual(rules[1]['title'], 'Ensure encryption uses a supported algorithm (Manual)')

    def test_untagged_title_stops_at_section_heading(self):
        text = '1.1 Ensure setting\nDescription:\nNot title text.\nAudit:\nSELECT 1;\n'
        rule = CISPdfParser('unused')._extract_rules(text)[0]
        self.assertEqual(rule['title'], 'Ensure setting')
        self.assertEqual(len(rule['checks']), 1)

    def test_audit_prose_with_is_not_sql(self):
        text = '''2.1.4 Ensure setting (Automated)
Audit:
SELECT value FROM v$parameter WHERE name = 'example';
To comply
with this recommendation, the output of this command should be NULL.
Note:
Review the evidence.
Remediation:
Review manually.
'''
        rule = CISPdfParser('unused')._extract_rules(text)[0]
        self.assertEqual([check['cmd'] for check in rule['checks']],
                         ["SELECT value FROM v$parameter WHERE name = 'example'"])
        self.assertIn('with this recommendation', rule['audit_text'])

    def test_trailing_select_comma_from_pdf_is_removed(self):
        text = '''4.2 Ensure no custom maintained users exist (Automated)
Audit:
SELECT CON_ID_TO_CON_NAME(C.CON_ID) AS CONTAINERNAME, USERNAME,
FROM CDB_USERS C
WHERE ORACLE_MAINTAINED = 'Y';
Remediation:
Review manually.
'''
        rule = CISPdfParser('unused', 'oracle')._extract_rules(text)[0]
        self.assertEqual(rule['checks'][0]['cmd'],
                         "SELECT CON_ID_TO_CON_NAME(C.CON_ID) AS CONTAINERNAME, USERNAME FROM CDB_USERS C\nWHERE ORACLE_MAINTAINED = 'Y'")

    def test_pdf_footer_removed_from_multiline_sql(self):
        text = '''3.3 Ensure setting (Automated)
Audit:
WITH permitted (name) AS (
SELECT name FROM CDB_PROFILES
Internal Only - General
WHERE profile = 'DEFAULT'
), additional AS (SELECT name FROM CDB_USERS)
SELECT * FROM permitted
  Internal Only - General
UNION SELECT * FROM additional;
Remediation:
Review manually.
'''
        for vendor in ('oracle', 'sqlserver'):
            with self.subTest(vendor=vendor):
                rule = CISPdfParser('unused', vendor)._extract_rules(text)[0]
                self.assertEqual(len(rule['checks']), 1)
                self.assertTrue(rule['checks'][0]['cmd'].startswith('WITH permitted'))
                self.assertIn('UNION SELECT * FROM additional', rule['checks'][0]['cmd'])
                self.assertNotIn('Internal Only - General', rule['audit_text'])
                self.assertNotIn('Internal Only - General', rule['checks'][0]['cmd'])

    def test_sql_keywords_in_prose_do_not_start_queries(self):
        text = '''1.1 Ensure setting (Automated)
Audit:
Review with this recommendation and SELECT the relevant setting;
SELECT 'Internal Only - General' AS label FROM dual;
Remediation:
Review manually.
'''
        rule = CISPdfParser('unused')._extract_rules(text)[0]
        self.assertEqual([check['cmd'] for check in rule['checks']],
                         ["SELECT 'Internal Only - General' AS label FROM dual"])

    def test_cis_mapping_rows_are_not_benchmark_rules(self):
        text = '''6.1 Ensure first setting (Manual)
Profile Applicability:
Level 1
Audit:
Review manually.
CIS Controls:
18.2 Ensure Explicit Error Checking is Performed
v7 For in-house developed software, ensure explicit checking.
9.2 Ensure Only Approved Ports
v7 Are Running
6.2 Ensure 'CLR Assembly Permission Set' is set to
'SAFE_ACCESS' for All CLR Assemblies (Automated)
Profile Applicability:
Level 1
Audit:
SELECT name FROM sys.assemblies;
'''
        rules = CISPdfParser('unused', 'sqlserver')._extract_rules(text)
        self.assertEqual([rule['id'] for rule in rules], ['6.1', '6.2'])
        self.assertIn("'SAFE_ACCESS' for All CLR Assemblies", rules[1]['title'])

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

    def test_sqlserver_reviewed_expectations(self):
        text = '''2.9 Ensure setting (Automated)
Audit:
SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;
No rows should be returned.
Remediation:
Review manually.
2.11 Ensure non-standard port (Automated)
Audit:
SELECT count(*) FROM sys.dm_server_registry WHERE value_data = '1433';
A value of 0 implies a pass.
Remediation:
Review manually.
4.3 Ensure policy (Automated)
Audit:
SELECT name, is_disabled FROM sys.sql_logins WHERE is_policy_checked = 0;
Remediation:
Review manually.
6.2 Ensure assemblies (Automated)
Audit:
SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1;
All the returned assemblies should show SAFE_ACCESS in the permission_set_desc column.
Remediation:
Review manually.
7.5 Ensure TDE (Automated)
Audit:
SELECT database_id, name, is_encrypted FROM sys.databases
WHERE database_id > 4 AND is_encrypted != 1
'''
        rules = CISPdfParser('unused', 'sqlserver')._extract_rules(text)
        checks = {rule['id']: rule['checks'][0] for rule in rules}
        self.assertEqual(checks['2.9']['expectation'], {'mode': 'empty_rows'})
        self.assertEqual(checks['2.11']['expectation'], {'mode': 'scalar_equal', 'value': 0})
        self.assertEqual(checks['4.3']['expectation'], {'mode': 'all_rows_equal', 'columns': {'is_disabled': 1}})
        self.assertEqual(checks['6.2']['expectation'], {'mode': 'all_rows_equal', 'columns': {'permission_set_desc': 'SAFE_ACCESS'}})
        self.assertEqual(checks['7.5']['expectation'], {'mode': 'empty_rows'})

    def test_sqlserver_extended_expectation_evaluation(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        cases = [
            ({'mode': 'all_rows_equal', 'columns': {'is_disabled': 1}}, [('name',), ('is_disabled',)], [], 'PASS'),
            ({'mode': 'all_rows_equal', 'columns': {'is_disabled': 1}}, [('name',), ('is_disabled',)], [('login', 1)], 'PASS'),
            ({'mode': 'all_rows_equal', 'columns': {'is_disabled': 1}}, [('name',), ('is_disabled',)], [('login', 0)], 'FAIL'),
            ({'mode': 'no_column_value', 'column': 'name', 'value': 'sa'}, [('name',)], [('renamed_sa',)], 'PASS'),
            ({'mode': 'no_column_value', 'column': 'name', 'value': 'sa'}, [('name',)], [('sa',)], 'FAIL'),
            ({'mode': 'all_scalar_equal', 'value': 'TRUE'}, [('encrypt_option',)], [('TRUE',)], 'PASS'),
            ({'mode': 'all_scalar_equal', 'value': 'TRUE'}, [('encrypt_option',)], [('FALSE',)], 'FAIL'),
        ]
        for expectation, description, rows, status in cases:
            with self.subTest(expectation=expectation, rows=rows):
                driver.cursor.description = description
                driver.cursor.fetchall.return_value = rows
                self.assertEqual(driver.execute_policy({'type': 'sql', 'cmd': 'SELECT 1', 'expectation': expectation})['status'], status)

    def test_sqlserver_audit_groups_expectation(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        driver.cursor.description = [('audit enabled',), ('audit specification enabled',),
                                     ('audit_action_name',), ('audited_result',)]
        check = {'type': 'sql', 'cmd': 'SELECT 1', 'expectation': {
            'mode': 'audit_groups',
            'groups': ('AUDIT_CHANGE_GROUP', 'FAILED_LOGIN_GROUP', 'SUCCESSFUL_LOGIN_GROUP'),
            'columns': {'audit enabled': 'Y', 'audit specification enabled': 'Y'},
        }}
        valid = [('Y', 'Y', group, 'SUCCESS AND FAILURE') for group in check['expectation']['groups']]
        for rows, status in ((valid, 'PASS'), (valid[:-1], 'FAIL'),
                             (valid[:-1] + [('N', 'Y', 'SUCCESSFUL_LOGIN_GROUP', 'SUCCESS AND FAILURE')], 'FAIL')):
            driver.cursor.fetchall.return_value = rows
            self.assertEqual(driver.execute_policy(check)['status'], status)

    def test_sqlserver_special_checks_are_extracted_and_allowlisted(self):
        text = '''3.2 Ensure guest permission (Automated)
Audit:
SELECT * FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest');
3.3 Ensure orphaned users (Automated)
Audit:
EXEC sp_change_users_login @Action='Report';
3.4 Ensure contained users (Automated)
Audit:
SELECT * FROM sys.database_principals WHERE authentication_type = 2;
5.3 Ensure login auditing (Automated)
Audit:
EXEC xp_loginconfig 'audit level';
'''
        rules = CISPdfParser('unused', 'sqlserver')._extract_rules(text)
        self.assertEqual([rule['checks'][0]['type'] for rule in rules], ['sqlserver_special'] * 4)
        self.assertEqual([rule['checks'][0]['operation'] for rule in rules],
                         ['guest_connect', 'orphaned_users', 'contained_sql_authentication', 'login_auditing'])
        driver = SQLServerDriver({}); driver.cursor = Mock()
        self.assertEqual(driver.execute_policy({'type': 'sqlserver_special', 'cmd': 'SELECT 1',
                                                'operation': 'guest_connect'})['status'], 'SKIPPED')
        driver.cursor.execute.assert_not_called()

    def test_sqlserver_special_database_checks(self):
        driver = SQLServerDriver({}); cursor = driver.cursor = Mock()
        check = CISPdfParser('unused', 'sqlserver')._extract_rules('''3.2 Ensure guest permission (Automated)
Audit:
SELECT * FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest');
''')[0]['checks'][0]
        cursor.fetchall.side_effect = [[('appdb',), ('otherdb',)], [], []]
        self.assertEqual(driver.execute_policy(check)['status'], 'PASS')
        self.assertEqual(cursor.execute.call_args_list[1].args[0], 'USE [appdb]')
        self.assertIn('FROM sys.database_permissions', cursor.execute.call_args_list[2].args[0])
        self.assertEqual(cursor.execute.call_args_list[3].args[0], 'USE [otherdb]')
        self.assertIn('FROM sys.database_permissions', cursor.execute.call_args_list[4].args[0])
        self.assertEqual(cursor.execute.call_args_list[5].args[0], 'USE [master]')

        cursor.reset_mock(); cursor.fetchall.side_effect = [[('appdb',)], [('guest', 'CONNECT', 'GRANT')]]
        result = driver.execute_policy(check)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn("('appdb', 'guest', 'CONNECT', 'GRANT')", result['output'])

        cursor.reset_mock(); cursor.fetchall.side_effect = [[('rdsadmin',)], [('guest', 'CONNECT', 'GRANT')]]
        self.assertEqual(driver.execute_policy(check)['status'], 'PASS')

    def test_sqlserver_tde_query_stops_before_expected_result_prose(self):
        rule = CISPdfParser('unused', 'sqlserver')._extract_rules('''7.5 Ensure TDE (Automated)
Audit:
SELECT database_id, name, is_encrypted FROM sys.databases
WHERE database_id > 4 AND is_encrypted != 1
The query should return no rows
''')[0]
        check = rule['checks'][0]
        self.assertEqual(check['cmd'], 'SELECT database_id, name, is_encrypted FROM sys.databases\nWHERE database_id > 4 AND is_encrypted != 1')
        self.assertEqual(check['expectation'], {'mode': 'empty_rows'})

    def test_sqlserver_login_auditing_special_check(self):
        driver = SQLServerDriver({}); cursor = driver.cursor = Mock()
        check = CISPdfParser('unused', 'sqlserver')._extract_rules('''5.3 Ensure login auditing (Automated)
Audit:
EXEC xp_loginconfig 'audit level';
''')[0]['checks'][0]
        cursor.description = [('name',), ('config_value',)]
        for rows, status in (([('audit level', 'failure')], 'PASS'),
                             ([('audit level', 'all')], 'PASS'),
                             ([('audit level', 'none')], 'FAIL')):
            cursor.fetchall.return_value = rows
            cursor.nextset.return_value = False
            self.assertEqual(driver.execute_policy(check)['status'], status)
        self.assertIn("EXEC xp_loginconfig 'audit level'", cursor.execute.call_args.args[0])

    def test_writes_are_not_executed(self):
        driver = SQLServerDriver({}); driver.cursor = Mock()
        for sql in ('EXEC sp_configure', 'SELECT 1; DROP TABLE x', 'SELECT * INTO x FROM y'):
            self.assertEqual(driver.execute_check('sql', sql)['status'], 'MANUAL')
        driver.cursor.execute.assert_not_called()

    def test_sqlserver_report_error_regressions(self):
        for variable in ('getValue', 'NumErrorLogs'):
            with self.subTest(variable=variable):
                text = (f'2.12 Ensure registry setting (Automated)\nAudit:\n'
                        f'DECLARE @{variable} INT;\n'
                        f'EXEC master.sys.xp_instance_regread @{variable} OUTPUT;\n'
                        f'SELECT @{variable};\nRemediation:\nReview manually.\n')
                rule = CISPdfParser('unused', 'sqlserver')._extract_rules(text)[0]
                self.assertEqual(len(rule['checks']), 1)
                check = rule['checks'][0]
                self.assertEqual(check['type'], 'manual')
                self.assertIn('DECLARE', check['cmd'])
                self.assertIn('EXEC', check['cmd'])
                driver = SQLServerDriver({}); driver.cursor = Mock()
                self.assertEqual(driver.execute_policy(check)['status'], 'MANUAL')
                self.assertEqual(driver.execute_check('sql', f'SELECT @{variable}')['status'], 'MANUAL')
                driver.cursor.execute.assert_not_called()

    def test_sqlserver_proxy_check_uses_msdb_without_switching_database(self):
        text = '''3.11 Ensure public cannot use proxies (Automated)
Audit:
USE [msdb]
GO
SELECT sp.name AS proxyname
FROM dbo.sysproxylogin spl
JOIN sys.database_principals dp
ON dp.sid = spl.sid
JOIN sysproxies sp
ON sp.proxy_id = spl.proxy_id
WHERE principal_id = USER_ID('public');
GO
This query should not return any rows.
Remediation:
Review manually.
'''
        rule = CISPdfParser('unused', 'sqlserver')._extract_rules(text)[0]
        check = rule['checks'][0]
        self.assertIn('msdb.dbo.sysproxylogin', check['cmd'])
        self.assertIn('msdb.sys.database_principals', check['cmd'])
        self.assertIn('msdb.dbo.sysproxies', check['cmd'])
        self.assertNotIn('USER_ID', check['cmd'])
        driver = SQLServerDriver({}); driver.cursor = Mock()
        driver.cursor.description = [('proxyname',)]
        for rows, status in (([], 'PASS'), ([('proxy',)], 'FAIL')):
            driver.cursor.fetchall.return_value = rows
            self.assertEqual(driver.execute_policy(check)['status'], status)
        self.assertEqual(driver.cursor.execute.call_count, 2)
        driver.cursor.execute.assert_called_with(check['cmd'])

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