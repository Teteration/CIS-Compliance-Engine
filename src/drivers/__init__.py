from .base import AuditDriver

# Future expansions:
# from .linux import LinuxDriver
# from .docker import DockerDriver

__all__ = ["AuditDriver", "OracleDriver", "SQLServerDriver"]


def __getattr__(name):
    if name == 'OracleDriver':
        from .oracle import OracleDriver
        return OracleDriver
    if name == 'SQLServerDriver':
        from .sqlserver import SQLServerDriver
        return SQLServerDriver
    raise AttributeError(name)