#!/usr/bin/env python3
import json
from datetime import datetime, timezone
import boto3

def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def scan_iam_users_without_mfa():
    iam = boto3.client("iam")
    findings = {
        "generated_at": utcnow_iso(),
        "users_without_mfa": [],
        "total_users": 0
    }

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users = page.get("Users", [])
        findings["total_users"] += len(users)
        for u in users:
            uname = u["UserName"]
            mfas = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if len(mfas) == 0:
                findings["users_without_mfa"].append(uname)

    return findings

if __name__ == "__main__":
    result = scan_iam_users_without_mfa()
    print(json.dumps(result, indent=2))
    with open("iam_report.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\n[+] Wrote iam_report.json")
