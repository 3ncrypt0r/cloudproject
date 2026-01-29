# Cloud Misconfiguration Scanner & Patch Manager

## Project Overview
Cloud misconfigurations are one of the leading causes of security incidents in cloud environments.
This project is a **Cloud Misconfiguration Scanner with Patch Management** that detects common AWS security issues and provides safe remediation options.

The tool is built using **Python, Flask, and AWS boto3 SDK** and follows real-world cloud security best practices.

---

## Features

### Amazon S3
- Detects public bucket policies
- Detects public bucket ACLs
- Detects disabled or weak Block Public Access (BPA)
- Detects publicly accessible objects
- Patch: Enable Block Public Access (BPA)

### Amazon EC2
- Detects Security Groups with inbound rules open to the world:
  - `0.0.0.0/0`
  - `::/0`
- Patch: Replaces world-open rules with the administrator’s IP (`/32`) instead of deleting rules

### AWS IAM
- Detects IAM users without MFA enabled
- Provides step-by-step remediation instructions for MFA

---

## Patch Management Logic
- S3: Automatically enables Block Public Access on risky buckets
- EC2: Restricts inbound access to the current admin IP instead of removing rules
- IAM: Displays secure remediation steps (MFA activation cannot be fully automated)

---

## Architecture
```
User
 ↓
Flask Web UI
 ↓
Scanner Modules (S3 / EC2 / IAM)
 ↓
AWS APIs via boto3
 ↓
JSON Reports + Patch Actions
```

---

## Technology Stack
- Python 3
- Flask
- boto3 (AWS SDK)
- AWS IAM, S3, EC2
- HTML & CSS (Jinja templates)

---

## Security Best Practices Followed
- No hardcoded AWS credentials
- Uses AWS SDK credential resolution
- Least-privilege IAM permissions
- MFA recommended for admin accounts
- Scan output excluded from version control

---

## Setup Instructions

### Clone Repository
```bash
git clone https://github.com/3ncrypt0r/cloudproject.git
cd cloudproject
```

### Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies
```bash
pip install flask boto3
```

### Configure AWS CLI
```bash
aws configure
```
Provide:
- AWS Access Key ID
- AWS Secret Access Key
- Default region
- Output format (json)

Ensure the IAM user has required permissions for scanning and patching.

---

## Run the Project
```bash
python3 scanner.py
```

Open in browser:
```
http://127.0.0.1:5000
```

---

## Reports
- `individual_report/` – Service-specific scan reports
- `final_report/report.json` – Combined report

> These directories are excluded from GitHub to prevent sensitive information exposure.

---

## Academic Note
This project was developed for **Cloud Security coursework** and demonstrates:
- Cloud misconfiguration detection
- Secure remediation design
- Practical AWS security implementation

---

## License
Educational use only.
