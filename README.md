# CIS Compliance Engine (CCE)

**CIS Compliance Engine (CCE)** is an automated, agentless security auditing framework designed to validate IT infrastructure against **Center for Internet Security (CIS) Benchmarks**.

Unlike traditional compliance tools that rely on static, manually maintained templates, CCE dynamically parses official CIS Benchmark PDF documents and converts their audit procedures into executable audit policies.

> **Current Status:** Stable — v1.0.0
> **Current Focus:** Oracle Database 19c

---

<img width="2665" height="1135" alt="image" src="https://github.com/user-attachments/assets/8095bdb1-e674-4f7e-a9f3-ca469977faf2" />

## 📸 Overview

*Above: CCE performing a live audit against an Oracle Database 19c and evaluating CIS controls automatically.*

## 🌟 Key Features

### 🧠 Intelligent PDF Parsing

* **Dynamic Rule Extraction:** Directly ingests CIS Benchmark PDFs and automatically extracts Rule IDs, titles, descriptions, and audit procedures.
* **Smart Command Detection:** Uses heuristics to distinguish between SQL queries (`SELECT`, `WITH`) and operating-system commands (`grep`, `ls`, `opatch`, etc.).
* **Multi-line Check Support:** Handles complex, multi-line audit procedures.
* **Benchmark-Driven:** Audit logic is derived from the supplied CIS Benchmark PDF rather than hard-coded exclusively in the application.

### 🛡️ Enterprise-Ready Auditing

* **Agentless Architecture:** No CCE agent or software installation is required on the target database/server.
* **Native Connectivity:** Uses Oracle SQL*Net for database checks and SSH for operating-system checks.
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
| `target.driver`                  | Database driver, currently `oracle`   |
| `target.host`                    | Target database/server IP or hostname |
| `target.connection.port`         | Oracle listener port, normally `1521` |
| `target.connection.service_name` | Oracle service name                   |
| `target.connection.user`         | Dedicated CCE audit account           |
| `target.connection.password`     | Password of the audit account         |
| `target.ssh.enabled`             | Enables SSH-based checks              |
| `target.ssh.user`                | SSH account used for OS-level checks  |
| `target.ssh.port`                | SSH port                              |
| `audit.benchmark_pdf`            | CIS Benchmark PDF                     |
| `audit.rules_cache`              | Extracted rule cache                  |
| `reporting.output_dir`           | Report directory                      |
| `reporting.format`               | Report format                         |

---

# 🚀 Quick Start

## Prerequisites

* Python 3.9 or higher
* Oracle Database 19c
* Oracle Python driver / Oracle connectivity dependencies
* Network access to the target database
* SSH access if OS-level checks are required

## 1. Clone the Repository

```bash
git clone https://github.com/Teteration/CIS-Compliance-Engine.git
cd CIS-Compliance-Engine
```

## 2. Install Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

## 3. Configure the Target

Create:

```text
config/config.yaml
```

and configure the Oracle connection and, if required, SSH access.

## 4. Run the Audit

```bash
python3 -m src.main --config config/config.yaml
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
    Passed Automated Controls
    --------------------------
    Total Automated Controls
```

Manual controls are excluded from the automated score because they require human verification.

---

# 🗂️ Output

Reports are generated under:

```text
reports/
```

Depending on the configured output format, CCE produces:

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
