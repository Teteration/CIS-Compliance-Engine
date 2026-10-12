import oracledb
import logging
import os
from .base import AuditDriver

logger = logging.getLogger(__name__)

class OracleDriver(AuditDriver):
    def __init__(self, config):
        super().__init__(config)
        self.conn = None
        self.cursor = None
        self.ssh = None

    def connect(self):
        # 1. Connect to Database
        db_conf = self.config.get('connection', {})
        dsn = f"{self.config['host']}:{db_conf['port']}/{db_conf['service_name']}"
        
        logger.info(f"Connecting to Oracle DB: {dsn}")
        try:
            self.conn = oracledb.connect(
                user=db_conf['user'],
                password=os.environ[db_conf['password_env']] if db_conf.get('password_env') else db_conf['password'],
                dsn=dsn
            )
            self.cursor = self.conn.cursor()
        except oracledb.Error as e:
            logger.error(f"Oracle Connection Failed: {e}")
            raise

        # Database access works without OS access.
        self.connect_optional_ssh()

    def _connect_ssh(self):
        self.connect_optional_ssh()

    def disconnect(self):
        try:
            if self.cursor is not None: self.cursor.close()
        finally:
            try:
                if self.conn is not None: self.conn.close()
            finally:
                if self.ssh is not None: self.ssh.close()
                self.cursor = self.conn = self.ssh = None

    def execute_check(self, check_type: str, command: str) -> dict:
        command = command.strip()
        
        if check_type == 'sql':
            return self._run_sql(command)
        elif check_type == 'shell':
            return self._run_shell(command)
        else:
            return {'status': 'SKIPPED', 'output': f'Unknown check type: {check_type}'}

    def _run_sql(self, sql):
        if not self.cursor:
            return {'status': 'SKIPPED', 'output': 'No DB Connection'}
        
        try:
            self.cursor.execute(sql.rstrip(';'))
            rows = self.cursor.fetchall()
            if rows:
                return {'status': 'FAIL', 'output': str(rows)[:500]}
            return {'status': 'PASS', 'output': 'No rows returned'}
        except oracledb.Error as e:
            return {'status': 'ERROR', 'output': str(e)}

    def _run_shell(self, cmd):
        return super()._run_shell(cmd)