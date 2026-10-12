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

# Explicit, reviewed expectations for the SQL Server 2017 Benchmark currently
# supported by this project. These rules supplement PDF extraction; they avoid
# guessing result semantics merely from a control title.
SQLSERVER_EXPECTATIONS = {
    '2.7': {'mode': 'columns_equal', 'columns': {'value_configured': 0, 'value_in_use': 0}},
    '2.9': {'mode': 'empty_rows'},
    '2.11': {'mode': 'scalar_equal', 'value': 0},
    '2.13': {'mode': 'empty_rows'},
    '2.14': {'mode': 'no_column_value', 'column': 'name', 'value': 'sa'},
    '2.16': {'mode': 'empty_rows'},
    '2.17': {'mode': 'empty_rows'},
    '3.1': {'mode': 'scalar_equal', 'value': 1},
    '3.8': {'mode': 'empty_rows'},
    '3.9': {'mode': 'empty_rows'},
    '3.10': {'mode': 'empty_rows'},
    '4.2': {'mode': 'empty_rows'},
    '4.3': {'mode': 'all_rows_equal', 'columns': {'is_disabled': 1}},
    '5.4': {
        'mode': 'audit_groups',
        'groups': ('AUDIT_CHANGE_GROUP', 'FAILED_LOGIN_GROUP', 'SUCCESSFUL_LOGIN_GROUP'),
        'columns': {'audit enabled': 'Y', 'audit specification enabled': 'Y'},
    },
    '6.2': {'mode': 'all_rows_equal', 'columns': {'permission_set_desc': 'SAFE_ACCESS'}},
    '7.1': {'mode': 'empty_rows'},
    '7.2': {'mode': 'empty_rows'},
    '7.3': {'mode': 'empty_rows'},
    '7.4': {'mode': 'all_scalar_equal', 'value': 'TRUE'},
    '7.5': {'mode': 'empty_rows'},
}

# Fixed multi-database and stored-procedure checks. These are intentionally
# separate from arbitrary PDF batches: identifiers come from sys.databases and
# each SQL statement is a reviewed read-only constant.
SQLSERVER_SPECIAL_CHECKS = {
    '3.2': {
        'operation': 'guest_connect',
        'source': """SELECT name FROM sys.databases
WHERE state = 0 AND name NOT IN ('master', 'tempdb', 'msdb')""",
        'query': """SELECT DB_NAME() AS database_name, permission_name, state_desc
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest')
AND state_desc LIKE 'GRANT%'
AND permission_name = 'CONNECT'""",
    },
    '3.3': {
        'operation': 'orphaned_users',
        'source': """SELECT name FROM sys.databases
WHERE state = 0 AND database_id > 4""",
        'query': """SELECT dp.name AS orphaned_user
FROM sys.database_principals AS dp
LEFT JOIN master.sys.server_principals AS sp ON dp.sid = sp.sid
WHERE dp.type = 'S'
AND dp.authentication_type = 1
AND dp.sid IS NOT NULL
AND sp.sid IS NULL
AND dp.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')""",
    },
    '3.4': {
        'operation': 'contained_sql_authentication',
        'source': """SELECT name FROM sys.databases
WHERE state = 0 AND containment <> 0""",
        'query': """SELECT name AS db_user
FROM sys.database_principals
WHERE name NOT IN ('dbo', 'INFORMATION_SCHEMA', 'sys', 'guest')
AND type IN ('U', 'S', 'G')
AND authentication_type = 2""",
    },
    '5.3': {
        'operation': 'login_auditing',
        'source': "EXEC xp_loginconfig 'audit level';",
        'accepted_values': ('failure', 'all'),
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