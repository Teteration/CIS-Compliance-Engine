# CIS Compliance Engine (CCE)

CCE extracts audit checks from user-supplied CIS Benchmark PDFs, runs supported
checks against Oracle or SQL Server, and generates JSON/TXT reports.

**Experimental:** current focus is Oracle Database 19c and SQL Server 2017.
Extraction is heuristic, not a guarantee of full coverage or correct interpretation
of every control. Review the evidence alongside the score.

## Features

- Direct database connections, with optional SSH for operating-system checks.
- Cached PDF rules, refreshed when the source or parser changes.
- Reports with commands, outputs, status, and database/benchmark metadata.
- Local execution without an AI service or SecureSuite API dependency.
- Explicit manual, skipped, and error outcomes rather than assumed compliance.

## Install

Use Python 3.10+. Commands below assume the project is located at
`/home/nox/Desktop/CIS-Compliance-Engine`; adjust that path if needed.

```bash
cd /home/nox/Desktop/CIS-Compliance-Engine
python3 -m venv /home/nox/Desktop/CIS-Compliance-Engine/.venv
source /home/nox/Desktop/CIS-Compliance-Engine/.venv/bin/activate
python -m pip install -r /home/nox/Desktop/CIS-Compliance-Engine/requirements.txt
```

SQL Server uses `mssql-python`; its native runtime dependencies must also be
available on your operating system.

## Configure

Copy the example for your target without overwriting an existing local file:

```bash
cp -n /home/nox/Desktop/CIS-Compliance-Engine/config/oracle.example.yaml /home/nox/Desktop/CIS-Compliance-Engine/config/oracle.local.yaml
cp -n /home/nox/Desktop/CIS-Compliance-Engine/config/sqlserver.example.yaml /home/nox/Desktop/CIS-Compliance-Engine/config/sqlserver.local.yaml
```

Edit the chosen local file:

| Setting | Purpose |
| --- | --- |
| `target.host` | Database server address |
| `target.connection.port` | Listener port |
| `target.connection.user` | Audit account |
| `target.connection.service_name` | Oracle service |
| `target.connection.database` | SQL Server database context |
| `audit.benchmark_pdf` | Path to your Benchmark PDF |
| `reporting.output_dir` | Report directory; typically `reports` |

### Password

To store the password directly, **remove `password_env`** and add `password`
under `target.connection`:

```yaml
    password: 'your-database-password'
```

Alternatively, keep `password_env` and export the variable named there.
If both exist, `password_env` takes precedence. Local `*.local.yaml` files are
ignored by Git; keep credential files private and do not commit them.

### Connection notes

- **Oracle:** omit `mode` for normal users. For SYSDBA, use `user: sys` and
  `mode: sysdba`, not `user: sys as sysdba`.
- **SQL Server:** uses SQL Server authentication. Set the correct port and
  database. Keep encryption enabled; certificate-verification bypass should
  be limited to controlled test environments.
- **SSH:** leave `target.ssh.enabled: false` for database-only auditing. Enable
  it for OS checks with the SSH user, key and verified known hosts configured.
  Missing OS access does not prevent database checks.
- Use a dedicated audit account with the permissions required by the controls.
  Validate behavior outside production first.

## Run

From the project root, with the virtual environment active:

```bash
# Oracle
python -m src.main -c /home/nox/Desktop/CIS-Compliance-Engine/config/oracle.local.yaml

# SQL Server
python -m src.main -c /home/nox/Desktop/CIS-Compliance-Engine/config/sqlserver.local.yaml
```

Rules are cached at `.cache/rules.json` by default. Set `audit.rules_cache` to
another path or `false` to disable caching. Append `--refresh-rules` to force
PDF extraction. Changing credentials does not require refreshing rules.

## Results

Both JSON and TXT reports are written to the configured output directory,
regardless of `reporting.format`.

| Status | Meaning |
| --- | --- |
| `PASS` | The implemented check met its expected condition |
| `FAIL` | The implemented check did not meet its expected condition |
| `ERROR` | Evaluation encountered an execution error |
| `SKIPPED` | Assessment was not completed, for example due to missing access or unsupported logic |
| `MANUAL` | Human review is required |

Terminal titles are limited to 100 characters and results to 70, separated by
four spaces. JSON preserves full recorded titles, audit text and check outputs;
driver-side output limits still apply. Embedded newlines in report fields are
replaced with spaces.

- **Compliance score:** `PASS / (PASS + FAIL)`; `N/A` if nothing was evaluated.
- **Evaluated coverage:** `(PASS + FAIL) / total extracted controls`.
- **Automation completion:** declared Automated controls with PASS/FAIL outcomes
  divided by all declared Automated controls. This is not parser accuracy.

Always read coverage alongside the score. Unsupported Automated controls are
reported as skipped, not silently treated as compliant.

## Direction and content rights

The goal is community-developed, reviewable, evidence-based auditing. Planned
work includes a common rule model, optional validated AI-assisted rule authoring,
and OpenSCAP integration. These are not implemented yet.

CCE is not CIS-certified or endorsed. Code and Benchmark content have separate
licensing requirements: verify applicable terms before redistributing PDFs or
rule packs, or uploading content to external services. An explicit code license
still needs to be selected before claiming licensed open-source status.
