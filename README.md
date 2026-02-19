# CIS Compliance Engine (CCE)

**The CIS Compliance Engine (CCE)** is an automated, agentless audit framework designed to validate IT infrastructure against Center for Internet Security (CIS) Benchmarks. Unlike traditional tools that rely on static templates, CCE dynamically parses official CIS PDF documents to generate executable audit policies in real-time.

> **Current Status:** Stable (v1.0.0) - Focused on **Oracle Database 19c** auditing.

---

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/4b9e08b9-3b02-4139-a5e0-3f4162ba6f83" />


## 📸 Overview

*Above: CCE performing a live audit against an Oracle Database, identifying 113 unique controls.*

## 🌟 Key Features

### 🧠 Intelligent PDF Parsing

* **Dynamic Rule Extraction:** Directly ingests CIS Benchmark PDFs, extracting Rule IDs, Titles, and Audit Procedures automatically.
* **Smart Command Detection:** Uses advanced heuristics to distinguish between SQL queries (`SELECT`, `WITH`) and Shell commands (`grep`, `ls`, `opatch`), ensuring accurate execution contexts.
* **Full Coverage:** Validated support for **113+ rules**, including complex multi-line checks.

### 🛡️ Enterprise-Ready Auditing

* **Agentless Architecture:** Requires zero software installation on the target nodes. Connects via native protocols (SQL*Net, SSH).
* **Granular Reporting:** Generates detailed JSON and Text-based reports in the `reports/` directory for compliance trails.
* **Visual Feedback:** Professional CLI output with color-coded status indicators (**PASS**, **FAIL**, **MANUAL**) and progress tracking.

---

## 🚀 Quick Start

### Prerequisites

* Python 3.9 or higher
* Oracle Instant Client (if auditing Oracle DBs)
* Network access to the target database/server

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Teteration/CIS-Compliance-Engine.git
cd CIS-Compliance-Engine
pip install -r requirements.txt

```

### 2. Configuration

Create a `config/config.yaml` file. A sample configuration is provided below:

```yaml
audit:
  benchmark_pdf: "benchmarks/CIS_Oracle_Database_19c_Benchmark_v1.1.0.pdf"

target:
  driver: "oracle"
  host: "192.168.1.100"
  port: 1521
  service_name: "ORCL"
  user: "cce_audit_user"
  password: "secure_password"

reporting:
  output_dir: "reports/"

```

### 3. Usage

Run the engine as a module:

```bash
python3 -m src.main --config config/config.yaml

```

---

## 📊 Sample Output

The engine provides a clear, tabular summary of the compliance state:

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

## 🛠️ Architecture

CCE operates in three distinct phases:

1. **Parser Core (`src/core/parser.py`):**
* Reads the raw PDF binary.
* Cleans OCR artifacts (e.g., removing `....... 57` page numbers).
* Identifies rules and classifies checks as `SQL` or `SHELL`.


2. **Driver Layer (`src/drivers/`):**
* Executes the extracted commands against the target environment.
* Handles connection pooling and error management.


3. **Reporter (`src/core/reporter.py`):**
* Aggregates results.
* Calculates compliance scores.
* Exports artifacts.



## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

*Built with ❤️ by Teteration Security Team*
