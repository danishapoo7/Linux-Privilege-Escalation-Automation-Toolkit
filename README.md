# Linux Privilege Escalation Automation Toolkit (LPEAT)

## Overview

Linux Privilege Escalation Automation Toolkit (LPEAT) is a Python-based security auditing tool designed to automate the detection of Linux misconfigurations that may increase security risk.

The toolkit performs read-only security assessments and generates structured reports containing findings, severity ratings, and remediation recommendations.

## Features

* System Information Collection
* SUID/SGID Binary Discovery
* Weak Permission Detection
* Sudo Configuration Auditing
* Cron Job Security Analysis
* Service Configuration Review
* Kernel Security Checks
* HTML and TXT Report Generation
* Severity-Based Risk Classification

## Technologies Used

* Python 3
* Linux
* Bash Commands
* Systemd
* HTML Reporting

## Project Structure

Linux-Privilege-Escalation-Automation-Toolkit/

├── main.py

├── modules/

│ ├── system_info.py

│ ├── suid_scanner.py

│ ├── permissions.py

│ ├── services.py

│ ├── cron_scanner.py

│ ├── kernel_check.py

│ ├── sudo_check.py

│ └── report_generator.py

├── reports/

└── README.md

## Installation

Clone the repository:

git clone https://github.com/yourusername/Linux-Privilege-Escalation-Automation-Toolkit.git

cd Linux-Privilege-Escalation-Automation-Toolkit

Install dependencies:

pip install -r requirements.txt

## Usage

Run the toolkit:

python3 main.py

Generate reports:

python3 main.py --format both

## Output

The toolkit generates:

* HTML Security Report
* TXT Security Report
* Severity Summary
* Mitigation Recommendations

## Educational Purpose

This project is intended for educational and defensive security auditing purposes only. The toolkit performs detection and reporting and does not execute exploitation activities.

## Author

Muhammed Danish AP
Cybersecurity Enthusiast | Linux Security | SOC Operations | Security Automation
