import importlib
import os
import re
from .base import AuditDriver
from src.core.sqlserver_checks import (REGISTRY_CHECKS, SQLSERVER_SPECIAL_CHECKS,
                                       registry_check_name)


class SQLServerDriver(AuditDriver):
    """Direct SQL Server connection, with independent optional Linux SSH access."""

    def __init__(self, config):
        super().__init__(config)
        self.conn = None
        self.cursor = None

    @staticmethod
    def _quote(value):
        return '{' + str(value).replace('}', '}}') + '}'

    def connect(self):
        try:
            module = importlib.import_module('mssql_python')
        except ImportError as exc:
            raise RuntimeError('SQL Server requires mssql-python; install requirements.txt') from exc
        conf = self.config.get('connection', {})
        password = os.environ[conf['password_env']] if conf.get('password_env') else conf.get('password', '')
        parts = {
            'Server': f"{self.config['host']},{conf.get('port', 1433)}",
            'Database': conf.get('database', 'master'),
            'UID': conf['user'], 'PWD': password,
            'Encrypt': 'yes' if conf.get('encrypt', True) else 'no',
            'TrustServerCertificate': 'yes' if conf.get('trust_server_certificate', False) else 'no',
        }
        connection_string = ';'.join(f'{key}={self._quote(value)}' for key, value in parts.items())
        self.conn = module.connect(connection_string, timeout=conf.get('timeout', 10))
        self.cursor = self.conn.cursor()
        self.connect_optional_ssh()

    def disconnect(self):
        try:
            if self.cursor is not None:
                self.cursor.close()
        finally:
            try:
                if self.conn is not None:
                    self.conn.close()
            finally:
                if self.ssh is not None:
                    self.ssh.close()
                self.cursor = self.conn = self.ssh = None

    def execute_check(self, check_type, command):
        return self.execute_policy({'type': check_type, 'cmd': command})

    def execute_policy(self, check):
        if check['type'] == 'sqlserver_registry':
            return self._run_registry_check(check)
        if check['type'] == 'sqlserver_special':
            return self._run_special_check(check)
        if check['type'] == 'manual':
            return {'status': 'MANUAL', 'output': 'Batch requires variable initialization and procedure execution; review the complete audit script manually'}
        if check['type'] == 'shell':
            return self._run_shell(check['cmd'])
        if check['type'] != 'sql':
            return {'status': 'SKIPPED', 'output': 'Unsupported check type'}
        if self.cursor is None:
            return {'status': 'SKIPPED', 'output': 'No DB Connection'}
        sql = check['cmd'].strip().rstrip(';')
        # Fail closed on batches and writes. CTEs / EXEC require manual review.
        tokens = re.sub(r"'(?:''|[^'])*'|\[(?:\]\]|[^\]])*\]|\"(?:\"\"|[^\"])*\"", '', sql)
        if re.search(r'(?<!@)@(?!@)[A-Za-z_]', tokens):
            return {'status': 'MANUAL', 'output': 'Query depends on local variables; execute the complete audit batch manually'}
        if (not re.match(r'^SELECT\b', sql, re.I) or ';' in tokens
                or '--' in tokens or '/*' in tokens
                or re.search(r'\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|CREATE|EXEC|EXECUTE|INTO|OPENROWSET|OPENDATASOURCE)\b', tokens, re.I)):
            return {'status': 'MANUAL', 'output': 'Query requires manual read-only review; not executed'}
        try:
            self.cursor.execute(sql)
            rows = self.cursor.fetchall()
            columns = [item[0].lower() for item in self.cursor.description]
            output = str(rows)[:2000]
            expectation = check.get('expectation', {})
            mode = expectation.get('mode')
            if mode == 'empty_rows':
                passed = not rows
            elif mode == 'columns_equal':
                if not rows:
                    return {'status': 'MANUAL', 'output': 'No rows; applicability requires review'}
                expected = expectation['columns']
                if not expected:
                    return {'status': 'ERROR', 'output': 'columns_equal requires nonempty columns'}
                indexes = {name: columns.index(name.lower()) for name in expected}
                passed = all(all(row[indexes[name]] == value for name, value in expected.items()) for row in rows)
            elif mode == 'scalar_equal':
                passed = len(rows) == 1 and len(rows[0]) == 1 and rows[0][0] == expectation['value']
            elif mode == 'all_scalar_equal':
                passed = bool(rows) and all(len(row) == 1 and row[0] == expectation['value'] for row in rows)
            elif mode == 'all_rows_equal':
                expected = expectation['columns']
                indexes = {name: columns.index(name.lower()) for name in expected}
                passed = all(all(row[indexes[name]] == value for name, value in expected.items()) for row in rows)
            elif mode == 'no_column_value':
                index = columns.index(expectation['column'].lower())
                passed = all(row[index] != expectation['value'] for row in rows)
            elif mode == 'audit_groups':
                indexes = {name: columns.index(name.lower()) for name in ('audit_action_name', *expectation['columns'])}
                groups = {row[indexes['audit_action_name']]: row for row in rows}
                passed = all(
                    group in groups and all(groups[group][indexes[name]] == value
                                           for name, value in expectation['columns'].items())
                    and 'SUCCESS' in str(groups[group][columns.index('audited_result')]).upper()
                    and 'FAILURE' in str(groups[group][columns.index('audited_result')]).upper()
                    for group in expectation['groups']
                )
            else:
                return {'status': 'MANUAL', 'output': output + '; no unambiguous expectation; review required'}
            return {'status': 'PASS' if passed else 'FAIL', 'output': output or 'No rows returned'}
        except Exception as exc:
            return {'status': 'ERROR', 'output': str(exc)}

    def _run_registry_check(self, check):
        name = check.get('operation')
        if name not in REGISTRY_CHECKS or registry_check_name(check['cmd']) != name:
            return {'status': 'SKIPPED', 'output': 'Registry batch is not on the read-only allowlist'}
        if self.cursor is None:
            return {'status': 'SKIPPED', 'output': 'No DB Connection'}
        definition = REGISTRY_CHECKS[name]
        try:
            # Only fixed, reviewed constants are executed. No writes or dynamic SQL.
            self.cursor.execute('SET NOCOUNT ON;\n' + definition['source'])
            while self.cursor.description is None:
                if not self.cursor.nextset():
                    return {'status': 'ERROR', 'output': 'Registry batch returned no result set'}
            rows = self.cursor.fetchall()
            if len(rows) != 1 or len(rows[0]) != 1 or type(rows[0][0]) is not int:
                return {'status': 'ERROR', 'output': f'Expected one integer registry value; received {rows!r}'}
            value = rows[0][0]
            expected = definition['expectation']
            passed = value == expected['value'] if expected['mode'] == 'scalar_equal' else value >= expected['value']
            return {'status': 'PASS' if passed else 'FAIL', 'output': str(rows)}
        except Exception as exc:
            return {'status': 'ERROR', 'output': str(exc)}

    @staticmethod
    def _quote_identifier(value):
        return '[' + str(value).replace(']', ']]') + ']'

    def _run_special_check(self, check):
        operation = check.get('operation')
        definition = next((item for item in SQLSERVER_SPECIAL_CHECKS.values()
                           if item['operation'] == operation), None)
        if definition is None or check.get('cmd', '').strip() != definition['source']:
            return {'status': 'SKIPPED', 'output': 'Special SQL Server check is not on the read-only allowlist'}
        if self.cursor is None:
            return {'status': 'SKIPPED', 'output': 'No DB Connection'}
        try:
            if operation == 'login_auditing':
                self.cursor.execute(definition['source'])
                while self.cursor.description is None:
                    if not self.cursor.nextset():
                        return {'status': 'ERROR', 'output': 'Login auditing batch returned no result set'}
                rows = self.cursor.fetchall()
                columns = [item[0].lower() for item in self.cursor.description]
                value_index = columns.index('config_value')
                values = [str(row[value_index]).strip().lower() for row in rows]
                passed = len(values) == 1 and values[0] in definition['accepted_values']
                return {'status': 'PASS' if passed else 'FAIL', 'output': str(rows) or 'No rows returned'}

            self.cursor.execute(definition['source'])
            databases = [row[0] for row in self.cursor.fetchall()]
            findings = []
            for database in databases:
                self.cursor.execute(f'USE {self._quote_identifier(database)};\n{definition["query"]}')
                rows = self.cursor.fetchall()
                findings.extend((database, *row) for row in rows)
            return {'status': 'PASS' if not findings else 'FAIL',
                    'output': str(findings) if findings else 'No rows returned'}
        except Exception as exc:
            return {'status': 'ERROR', 'output': str(exc)}