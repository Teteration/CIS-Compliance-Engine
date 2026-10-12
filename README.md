# CIS Compliance Engine (CCE)

**CIS Compliance Engine (CCE)** is an automated, agentless security auditing framework designed to validate IT infrastructure against **Center for Internet Security (CIS) Benchmarks**.

Unlike traditional compliance tools that rely on static, manually maintained templates, CCE dynamically parses official CIS Benchmark PDF documents and converts their audit procedures into executable audit policies.

> **Current Status:** v1.0.0 codebase with initial SQL Server support; live SQL Server validation pending
> **Current Focus:** Oracle Database 19c and initial SQL Server support

## Direct database access and optional OS access

Database connections are direct; SSH is not a tunnel or a prerequisite. With
`target.ssh.enabled: false` (also the default when omitted), database checks run
normally and extracted shell checks are `SKIPPED` with a reason. With SSH enabled,
the tool attempts additional Linux OS checks. SSH failure does not abort the
database audit. Windows OS checks are not currently automated.

SSH uses verified system host keys (or `target.ssh.known_hosts`) and rejects
unknown hosts. Configure `key_filename` or `password`; no interactive password
prompt is required. An optional `target.ssh.host` can differ from the database
endpoint. Shells do not source login profiles, so configure required environment
variables in the commands/environment. Shell results currently require manual
review rather than assuming that empty stdout means compliance.

### SQL Server setup

SQL Server uses Microsoft's `mssql-python` driver and requires Python 3.10+.
Install the unified project requirements in a virtual environment:

```bash
python3 -m venv /home/nox/Desktop/CIS-Compliance-Engine/.venv
/home/nox/Desktop/CIS-Compliance-Engine/.venv/bin/python -m pip install -r /home/nox/Desktop/CIS-Compliance-Engine/requirements.txt
```

Linux may additionally require distribution-specific native libraries; consult
Microsoft's `mssql-python` installation documentation. All Oracle and SQL Server
Python dependencies are maintained together in `requirements.txt`.

Configure the example at
`/home/nox/Desktop/CIS-Compliance-Engine/config/sqlserver.example.yaml` with the
target host, database and dedicated audit user. Set `CCE_SQLSERVER_PASSWORD` in
your process environment; avoid committing passwords. Encryption is enabled and
server certificates are verified by default. Then, from the project root:

```bash
/home/nox/Desktop/CIS-Compliance-Engine/.venv/bin/python -m src.main --config /home/nox/Desktop/CIS-Compliance-Engine/config/sqlserver.example.yaml
```

The Oracle equivalent is
`/home/nox/Desktop/CIS-Compliance-Engine/config/oracle.example.yaml`; it accepts
`CCE_ORACLE_PASSWORD`. Existing `connection.password` settings remain supported.
Existing private configuration files are not modified by this change.

### Evaluation and coverage

SQL Server checks with explicit `Both value columns must show 0/1` audit wording
and matching configuration-column aliases receive a narrowly inferred comparison.
Other SELECT results are retained as `MANUAL` unless a reviewed expectation is
configured. Only simple SELECTs are executed; batches, EXEC, writes and CTEs are
left for manual review. This is a conservative guard, not a security sandbox:
always use an appropriately restricted audit account and a trusted benchmark.

For a control with exactly one SQL check, an optional rule-ID expectation can be
set under `audit.expectations`. Supported SQL Server modes are `empty_rows`,
`scalar_equal` and `columns_equal`. For example (verify against your benchmark):

```yaml
audit:
  expectations:
    "2.1":
      mode: columns_equal
      columns:
        value_configured: 0
        value_in_use: 0
```

SQL Server controls returning no rows for a column comparison require manual
applicability review. Multi-query controls do not accept these overrides.
Oracle retains its existing SQL empty-row evaluation behavior; improving its
per-control interpretation is a separate follow-up, and SQL expectation overrides
currently apply only to SQL Server.

Reports distinguish `PASS`, `FAIL`, `ERROR`, `SKIPPED` and `MANUAL`. The score is
`PASS / (PASS + FAIL)`; it is `N/A` when no controls are evaluated. Evaluated
coverage is `(PASS + FAIL) / total extracted controls`. Always review coverage
alongside the score: a high score is not evidence of complete benchmark coverage.
SSH availability does not guarantee 100% coverage. The `reporting.format` option
is still not implemented; reports produce both JSON and TXT.

### Extracted rule cache

Rules are extracted once and stored in the JSON file specified by
`audit.rules_cache` (default `.cache/rules.json`, relative to the working directory).
The same file can store multiple benchmarks. Cache entries are separated by the
PDF's SHA-256 content hash, vendor and parser source hash. Changing PDF contents
or parser code automatically triggers extraction again; moving an unchanged PDF
does not. Missing, unreadable, malformed or incompatible cached entries are rebuilt.
The PDF must still exist so its hash can be verified. Only rules are cached, not
credentials or audit results; database checks execute on every run.

Use `--refresh-rules` with the normal execution command to force fresh extraction,
or set `audit.rules_cache: null` to disable caching. Removing the cache file also
forces extraction. A cache write failure does not prevent the current audit.
Cache files contain executable policies: keep them writable only by trusted users.
Writes use atomic replacement; simultaneous writers may lose each other's cache
entries, but a later cache miss simply rebuilds them.

Run offline regression tests from the project root:

```bash
python3 -B -m unittest discover -s /home/nox/Desktop/CIS-Compliance-Engine/tests -v
```

---

<img width="2665" height="1135" alt="image" src="https://github.com/user-attachments/assets/8095bdb1-e674-4f7e-a9f3-ca469977faf2" />

## 📸 Overview

*Above: CCE performing a live audit against an Oracle Database 19c and evaluating CIS controls automatically.*

## 🌟 Key Features

### 🧠 Intelligent PDF Parsing

* **Dynamic Rule Extraction:** Ingests CIS Benchmark PDFs and extracts Rule IDs, titles, audit text, and executable checks.
* **Rule Cache:** Reuses extracted rules for unchanged documents; missing or invalid cache entries are rebuilt automatically.
* **Smart Command Detection:** Uses heuristics to distinguish between SQL queries (`SELECT`, `WITH`) and operating-system commands (`grep`, `ls`, `opatch`, etc.).
* **Multi-line Check Support:** Handles complex, multi-line audit procedures.
* **Benchmark-Driven:** Audit logic is derived from the supplied CIS Benchmark PDF rather than hard-coded exclusively in the application.

### 🛡️ Enterprise-Ready Auditing

* **Agentless Architecture:** No CCE agent or software installation is required on the target database/server.
* **Native Connectivity:** Connects directly to Oracle or SQL Server; optional SSH adds Linux operating-system checks.
* **Granular Reporting:** Generates JSON and text reports under the `reports/` directory.
* **CLI Feedback:** Provides color-coded `PASS`, `FAIL`, `ERROR`, `SKIPPED`, and `MANUAL` results with progress information.
* **Audit Traceability:** Each result is associated with its corresponding CIS control.

---

# 🏗️ Architecture

CCE operates through three primary layers:

### 1. Parser Core

Located in:

```text
src/core/parser.py
```

The parser:

* Reads the supplied CIS Benchmark PDF.
* Extracts benchmark controls and audit procedures.
* Removes common PDF/OCR artifacts.
* Identifies executable SQL and shell commands.
* Classifies checks according to their execution context.

### 2. Driver Layer

Located in:

```text
src/drivers/
```

The driver layer:

* Establishes connections to target systems.
* Executes extracted audit commands.
* Handles database and SSH communication.
* Captures command output and errors.

Currently supported:

```text
Oracle Database 19c
SQL Server 2017 (initial support; live connection not yet validated)
```

### 3. Reporter

Located in:

```text
src/core/reporter.py
```

The reporter:

* Aggregates audit results.
* Calculates the automated compliance score.
* Generates JSON and text reports.
* Provides a human-readable compliance summary.

---

# 🔐 Oracle Database Access Requirements

CCE does **not** require an application account or access to application data for normal CIS auditing.

However, Oracle CIS Benchmarks inspect a large number of **Oracle Data Dictionary and dynamic performance views**, including objects such as:

```text
DBA_USERS
DBA_PROFILES
DBA_SYS_PRIVS
DBA_ROLE_PRIVS
DBA_ROLES
DBA_TAB_PRIVS
DBA_OBJECTS
DBA_REGISTRY
V$PARAMETER
V$INSTANCE
V$DATABASE
V$OPTION
V$SERVICES
V$PWFILE_USERS
```

Some controls also require information related to:

* database auditing
* initialization parameters
* users and profiles
* system privileges
* roles
* database components
* Oracle software/version information
* listener configuration
* operating-system configuration

Therefore, the audit account must have sufficient privileges to read the required Oracle dictionary and dynamic performance views.

## Recommended Access for Full Oracle 19c Benchmark Coverage

For the current version of CCE, the recommended audit account is:

```text
DBA
SELECT_CATALOG_ROLE
```

For example, an Oracle administrator can create a dedicated audit account and grant the required roles:

```sql
CREATE USER cce_audit IDENTIFIED BY "CHANGE_ME_STRONG_PASSWORD";

GRANT CREATE SESSION TO cce_audit;

GRANT SELECT_CATALOG_ROLE TO cce_audit;

GRANT DBA TO cce_audit;
```

After connecting with the audit account, the following should work without `ORA-00942` errors:

```sql
SELECT COUNT(*) FROM DBA_USERS;

SELECT COUNT(*) FROM DBA_PROFILES;

SELECT COUNT(*) FROM DBA_SYS_PRIVS;

SELECT VALUE
FROM V$PARAMETER
WHERE NAME = 'audit_trail';

SELECT VALUE
FROM V$PARAMETER
WHERE NAME = 'audit_sys_operations';
```

### ⚠️ Security Consideration

The `DBA` role provides extensive administrative privileges and should **not automatically be granted to a permanent production account**.

For controlled audits, the recommended operational approach is:

```text
1. Create a dedicated temporary CCE audit account.
2. Grant the privileges required for the audit.
3. Run the CIS assessment.
4. Export and review the reports.
5. Revoke unnecessary privileges or remove the temporary account.
```

For example, after completing the audit:

```sql
REVOKE DBA FROM cce_audit;
REVOKE SELECT_CATALOG_ROLE FROM cce_audit;
```

Alternatively, the account can be removed completely if it is only required for a one-time assessment:

```sql
DROP USER cce_audit CASCADE;
```

> **Production environments:** Before granting `DBA`, review the required privileges against your organization's security policy and change-management process. A future version of CCE may provide a more granular least-privilege role specifically for Oracle auditing.

---

# 🖥️ Operating-System / SSH Access

Some CIS controls cannot be evaluated through SQL alone.

Examples include controls related to:

* `listener.ora`
* Oracle Net configuration
* Oracle software installation
* Oracle patches
* operating-system files
* listener configuration
* filesystem permissions
* Oracle binaries

For these checks, CCE can optionally connect to the target server through SSH.

The SSH account should normally be the **Oracle software owner** or another account with read-only access to the required Oracle configuration files and commands.

For example:

```yaml
ssh:
  enabled: true
  user: oracle
  port: 22
  password: "CHANGE_ME"
```

CCE does not require root access for the normal Oracle audit workflow.

If a particular CIS control requires information that the configured SSH user cannot read, that control may be reported as:

```text
ERROR
```

or

```text
SKIPPED
```

depending on the check and driver behavior.

---

# ⚙️ Configuration

Create:

```text
config/config.yaml
```

Example:

```yaml
target:
  driver: "oracle"

  host: "192.168.1.100"

  connection:
    port: 1521
    service_name: "ORCL"
    user: "cce_audit"
    password: "CHANGE_ME_STRONG_PASSWORD"

  ssh:
    enabled: true
    user: "oracle"
    port: 22
    password: "CHANGE_ME_SSH_PASSWORD"

audit:
  benchmark_pdf: "benchmarks/CIS_Oracle_Database_19c_Benchmark_v1.2.0.pdf"
  rules_cache: "rules_cache.json"

reporting:
  output_dir: "reports"
  format: "both"
```

### Configuration Parameters

| Parameter                        | Description                           |
| -------------------------------- | ------------------------------------- |
| `target.driver`                  | `oracle`, `sqlserver`, or `mssql`      |
| `target.host`                    | Target database/server IP or hostname |
| `target.connection.port`         | Oracle listener port, normally `1521` |
| `target.connection.service_name` | Oracle service name                   |
| `target.connection.user`         | Dedicated CCE audit account           |
| `target.connection.password`     | Password of the audit account         |
| `target.connection.password_env` | Environment variable containing the password (preferred; overrides password) |
| `target.connection.database`     | SQL Server initial database, default `master` |
| `target.connection.encrypt`      | SQL Server encryption, default `true` |
| `target.connection.trust_server_certificate` | Skip certificate validation, default `false` |
| `target.ssh.enabled`             | Enables SSH-based checks              |
| `target.ssh.user`                | SSH account used for OS-level checks  |
| `target.ssh.port`                | SSH port                              |
| `audit.benchmark_pdf`            | CIS Benchmark PDF                     |
| `audit.rules_cache`              | JSON cache path; defaults to `.cache/rules.json`; `null` disables it |
| `audit.expectations`             | Reviewed SQL Server evaluation overrides keyed by rule ID |
| `reporting.output_dir`           | Report directory                      |
| `reporting.format`               | Reserved setting; currently both JSON and TXT are generated |

---

# 🚀 Quick Start

## Prerequisites

* Python 3.10 or higher
* Oracle Database 19c or SQL Server 2017
* Project Python dependencies and any required native connectivity libraries
* Network access to the target database
* SSH access if OS-level checks are required

## 1. Clone the Repository

```bash
git clone https://github.com/Teteration/CIS-Compliance-Engine.git
cd CIS-Compliance-Engine
```

## 2. Install Dependencies

```bash
python3 -m venv /home/nox/Desktop/CIS-Compliance-Engine/.venv
source /home/nox/Desktop/CIS-Compliance-Engine/.venv/bin/activate
python -m pip install -r /home/nox/Desktop/CIS-Compliance-Engine/requirements.txt
```

## 3. Configure the Target

Create:

```text
config/config.yaml
```

Alternatively, copy the Oracle or SQL Server example to a `*.local.yaml` file
under `/home/nox/Desktop/CIS-Compliance-Engine/config/` and configure the connection.
Local configuration files are ignored by Git. Use environment-variable passwords
and optional SSH access; do not commit credentials.

## 4. Run the Audit

```bash
python -m src.main --config /home/nox/Desktop/CIS-Compliance-Engine/config/oracle.local.yaml
```

---

# 🔍 Verifying the Oracle Audit Account

Before running a complete assessment, verify that the configured account can access Oracle's dictionary views.

Connect using the configured audit account and execute:

```sql
SELECT USER FROM DUAL;

SELECT COUNT(*) FROM DBA_USERS;

SELECT COUNT(*) FROM DBA_PROFILES;

SELECT COUNT(*) FROM DBA_SYS_PRIVS;

SELECT COUNT(*) FROM DBA_ROLE_PRIVS;

SELECT VALUE
FROM V$PARAMETER
WHERE NAME = 'audit_trail';

SELECT VALUE
FROM V$PARAMETER
WHERE NAME = 'audit_sys_operations';
```

If these queries fail with:

```text
ORA-00942: table or view does not exist
```

the audit account does not have sufficient dictionary privileges for the corresponding controls.

If they execute successfully, CCE can proceed with the relevant automated checks.

---

# 📊 Sample Output

CCE provides a tabular summary of the compliance state:

The TITLE column is at least 100 characters wide and expands to the longest
cleaned title so RESULT stays aligned. Narrow terminals may wrap the output.

```text
NO.  TIME      TYPE    ID       STATUS   TITLE                                                        RESULT
========================================================================================================================
1    15:21:10  AUTO    1.1      FAIL     Ensure the Appropriate Version/Patches for Oracle Software   Error
2    15:21:10  MANUAL  2.1.1    PASS     Ensure 'extproc' Is Not Present in 'listener.ora'            No output
3    15:21:10  AUTO    2.2.1    PASS     Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'               TRUE
...
========================================================================================================================
   COMPLIANCE SCORE: 85.00% (Automated Only)
========================================================================================================================
```

> **Important:** `PASS` and `FAIL` represent the result of the extracted audit procedure. A `MANUAL` control requires human verification according to the CIS Benchmark.

---

# 📋 Automated vs. Manual Controls

CCE distinguishes between controls that can be automatically evaluated and controls that require human verification.

### Automated

Typical automated checks include:

```text
Database parameters
User configuration
Password profiles
System privileges
Roles
Auditing configuration
Database components
Oracle configuration values
```

### Manual

Depending on the CIS Benchmark version, examples may include:

```text
Listener configuration verification
Authorized software verification
Network encryption/checksum verification
Approved network ports
Operational/security procedures
```

Manual controls are reported separately and are not automatically interpreted as compliant merely because the engine cannot identify a violation.

---

# 📈 Compliance Score

CCE calculates the compliance score using automatically evaluated controls.

Conceptually:

```text
Compliance Score =
    Passed Evaluated Controls
    --------------------------
    Passed + Failed Controls
```

Manual, skipped and error outcomes are excluded from the score. If no controls
have PASS/FAIL outcomes, the score is `N/A`. Evaluated coverage is
`(PASS + FAIL) / total extracted controls`; inspect it alongside the score.

---

# 🗂️ Output

Reports are generated under:

```text
reports/
```

CCE currently produces both formats regardless of `reporting.format`:

```text
JSON
TXT
```

These reports can be retained as audit evidence and used for remediation tracking.

---

# 🧩 Supported Benchmark

Current primary target:

```text
CIS Oracle Database 19c Benchmark
CIS Microsoft SQL Server 2017 Benchmark v1.3.0 (initial support)
```

The benchmark PDF supplied to CCE determines the controls and audit procedures that are evaluated.

Different benchmark versions may contain different control IDs, titles, procedures, and expected configurations.

For reproducible audits, keep the exact CIS Benchmark PDF used for the assessment together with the generated report.

---

# ⚠️ Important Operational Notes

### Dedicated Audit Account

Use a dedicated account for CCE rather than a normal application account.

```text
Application Account
        ↓
       NO

CCE Audit Account
        ↓
       YES
```

### Do Not Use Application Credentials

The CCE audit account should not be the same account used by the application or business service.

### Temporary Privileges

If `DBA` is used for a full assessment, treat the account as a privileged audit account and remove or reduce its privileges after the assessment.

### UAT / Production

The engine can be used against UAT or production systems, but the audit account, SSH access, query load, and change-management requirements should be reviewed according to the organization's security policy.

CCE performs read-oriented compliance checks by design, but some extracted benchmark procedures may invoke privileged database metadata or operating-system commands.

---

# 🤝 Contributing

Contributions are welcome!

1. Fork the repository.
2. Create a feature branch:

```bash
git checkout -b feature/AmazingFeature
```

3. Commit your changes:

```bash
git commit -m "Add AmazingFeature"
```

4. Push the branch:

```bash
git push origin feature/AmazingFeature
```

5. Open a Pull Request.

---

# 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

*Built with ❤️ by Teteration Security Team*
