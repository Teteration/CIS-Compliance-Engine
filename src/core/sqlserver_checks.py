"""Small, explicit allowlist of read-only SQL Server registry audit batches."""

REGISTRY_CHECKS = {
    'hide_instance': {
        'source': r"""DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
@rootkey = N'HKEY_LOCAL_MACHINE',
@key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
@value_name = N'HideInstance',
@value = @getValue OUTPUT;
SELECT @getValue;""",
        'expectation': {'mode': 'scalar_equal', 'value': 1},
    },
    'error_log_count': {
        'source': r"""DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
@NumErrorLogs OUTPUT;
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];""",
        'expectation': {'mode': 'scalar_at_least', 'value': 12},
    },
}


def registry_check_name(batch):
    # Accommodate PDF line wrapping only. The driver executes our canonical
    # constant, never the normalized PDF text or arbitrary procedure arguments.
    normalized = ' '.join(batch.split())
    for name, definition in REGISTRY_CHECKS.items():
        if normalized == ' '.join(definition['source'].split()):
            return name
    return None