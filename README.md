# CIS Compliance Engine (CCE)

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Target Support](https://img.shields.io/badge/targets-Oracle%20%7C%20Linux%20%7C%20Docker-orange)

**An extensible, modular, and automated framework for auditing IT infrastructure against Center for Internet Security (CIS) Benchmarks.**

## 🌟 Why CCE?

Most compliance tools are expensive black boxes or rigid Bash scripts. **CIS Compliance Engine** is designed for **DevSecOps** agility:
* **Universal Architecture:** Plugin-based design supports Databases (Oracle, Postgres), Operating Systems (Ubuntu, RHEL), and Containers.
* **PDF-to-Policy:** Proprietary engine that parses official CIS PDF Benchmarks into executable audit policies.
* **Agentless:** Zero-footprint auditing using native protocols (SSH, SQL*Net, Docker API).
* **JSON & HTML Reporting:** Enterprise-ready artifacts for audit trails.

## 🚀 Quick Start

### 1. Installation
```bash
git clone [https://github.com/yourusername/cis-compliance-engine.git](https://github.com/yourusername/cis-compliance-engine.git)
cd cis-compliance-engine
pip install -r requirements.txt
