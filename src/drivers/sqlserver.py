import importlib
import os
import re
from .base import AuditDriver


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
        if check['type'] == 'shell':
            return self._run_shell(check['cmd'])
        if check['type'] != 'sql':
            return {'status': 'SKIPPED', 'output': 'Unsupported check type'}
        if self.cursor is None:
            return {'status': 'SKIPPED', 'output': 'No DB Connection'}
        sql = check['cmd'].strip().rstrip(';')
        # Fail closed on batches and writes. CTEs / EXEC require manual review.
        tokens = re.sub(r"'(?:''|[^'])*'|\[(?:\]\]|[^\]])*\]|\"(?:\"\"|[^\"])*\"", '', sql)
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
            else:
                return {'status': 'MANUAL', 'output': output + '; no unambiguous expectation; review required'}
            return {'status': 'PASS' if passed else 'FAIL', 'output': output or 'No rows returned'}
        except Exception as exc:
            return {'status': 'ERROR', 'output': str(exc)}