import oracledb
import paramiko
import logging
import getpass
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
                password=db_conf['password'],
                dsn=dsn
            )
            self.cursor = self.conn.cursor()
        except oracledb.Error as e:
            logger.error(f"Oracle Connection Failed: {e}")
            raise

        # 2. Connect to SSH (Optional but recommended)
        if self.config.get('ssh', {}).get('enabled'):
            self._connect_ssh()

    def _connect_ssh(self):
        ssh_conf = self.config['ssh']
        logger.info(f"Connecting SSH to {self.config['host']}...")
        
        password = ssh_conf.get('password')
        if not password:
            password = getpass.getpass(f"Enter SSH Password for {ssh_conf['user']}: ")

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(
                self.config['host'],
                port=ssh_conf['port'],
                username=ssh_conf['user'],
                password=password
            )
        except Exception as e:
            logger.error(f"SSH Connection Failed: {e}")
            self.ssh = None

    def disconnect(self):
        if self.cursor: self.cursor.close()
        if self.conn: self.conn.close()
        if self.ssh: self.ssh.close()

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
        if not self.ssh:
            return {'status': 'SKIPPED', 'output': 'No SSH Connection'}

        # Fix PDF variables
        cmd = cmd.replace('$ ', '$').replace('% ', '%')
        
        try:
            # Source bash_profile to fix environment variables
            full_cmd = f"source ~/.bash_profile 2>/dev/null; {cmd}"
            stdin, stdout, stderr = self.ssh.exec_command(full_cmd, timeout=10)
            
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if out:
                return {'status': 'FAIL', 'output': out}
            return {'status': 'PASS', 'output': 'No output'}
        except Exception as e:
            return {'status': 'ERROR', 'output': str(e)}