from abc import ABC, abstractmethod
from typing import Any, Dict
import logging
import shlex

class AuditDriver(ABC):
    """
    Abstract Base Class that all Compliance Drivers must implement.
    This ensures consistency whether scanning Oracle, Linux, or Docker.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssh = None
        self.ssh_reason = 'SSH disabled in configuration'

    def connect_optional_ssh(self):
        """OS access is independent of database access and never mandatory."""
        ssh_conf = self.config.get('ssh', {})
        if not ssh_conf.get('enabled', False):
            return
        client = None
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            if ssh_conf.get('known_hosts'):
                client.load_host_keys(ssh_conf['known_hosts'])
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                ssh_conf.get('host', self.config['host']),
                port=ssh_conf.get('port', 22), username=ssh_conf['user'],
                password=ssh_conf.get('password'),
                key_filename=ssh_conf.get('key_filename'),
                timeout=ssh_conf.get('timeout', 10),
                auth_timeout=ssh_conf.get('timeout', 10),
                banner_timeout=ssh_conf.get('timeout', 10),
            )
            self.ssh = client
            self.ssh_reason = ''
        except Exception as exc:
            if client is not None:
                client.close()
            self.ssh_reason = f'SSH unavailable: {exc}'
            logging.getLogger(__name__).warning(self.ssh_reason)

    def execute_policy(self, check):
        return self.execute_check(check['type'], check['cmd'])

    def _run_shell(self, cmd):
        if not self.ssh:
            return {'status': 'SKIPPED', 'output': self.ssh_reason}
        ssh_conf = self.config.get('ssh', {})
        if ssh_conf.get('platform', 'linux') != 'linux':
            return {'status': 'SKIPPED', 'output': 'Only Linux SSH commands are supported; Windows OS checks require manual review'}
        try:
            # No login profile is sourced: auditing must not execute profile side effects.
            _, stdout, stderr = self.ssh.exec_command(
                'bash -c ' + shlex.quote(cmd), timeout=ssh_conf.get('timeout', 10))
            out = stdout.read().decode(errors='replace').strip()
            err = stderr.read().decode(errors='replace').strip()
            code = stdout.channel.recv_exit_status()
            # grep exit 1 means no match, not an execution error.
            grep_no_match = cmd.lstrip().startswith('grep ') and code == 1 and not err
            if err or (code != 0 and not grep_no_match):
                return {'status': 'ERROR', 'output': err or f'Exit code {code}: {out}'}
            # The meaning of shell output differs between controls. Retain evidence.
            return {'status': 'MANUAL', 'output': out or 'No output; review audit expectations'}
        except Exception as exc:
            return {'status': 'ERROR', 'output': str(exc)}

    @abstractmethod
    def connect(self):
        """Establish connection to the target system."""
        pass

    @abstractmethod
    def disconnect(self):
        """Close all connections."""
        pass

    @abstractmethod
    def execute_check(self, check_type: str, command: str) -> Dict[str, Any]:
        """
        Executes a specific check command.
        
        Args:
            check_type: 'sql', 'shell', 'api', etc.
            command: The actual command string to run.
            
        Returns:
            Dict containing status (PASS/FAIL/ERROR/SKIPPED/MANUAL) and output.
        """
        pass