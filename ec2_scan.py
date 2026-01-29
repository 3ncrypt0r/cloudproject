#!/usr/bin/env python3
import json
from datetime import datetime, timezone
import boto3

WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"

# Common sensitive ports; -1 means "all ports"
DEFAULT_PORTS_OF_INTEREST = {22, 80, 443, 3389, 3306, 5432, -1}

def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def scan_security_groups(ports_of_interest=None):
    if ports_of_interest is None:
        ports_of_interest = DEFAULT_PORTS_OF_INTEREST

    ec2 = boto3.client("ec2")
    findings = {
        "generated_at": utcnow_iso(),
        "world_open_rules": [],
        "total_security_groups": 0
    }

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        sgs = page.get("SecurityGroups", [])
        findings["total_security_groups"] += len(sgs)

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            vpc_id = sg.get("VpcId", "")
            for rule in sg.get("IpPermissions", []):
                proto = rule.get("IpProtocol", "tcp")
                from_p = rule.get("FromPort", -1)
                to_p = rule.get("ToPort", -1)

                world_v4 = any(r.get("CidrIp") == WORLD_V4 for r in rule.get("IpRanges", []))
                world_v6 = any(r.get("CidrIpv6") == WORLD_V6 for r in rule.get("Ipv6Ranges", []))
                if not (world_v4 or world_v6):
                    continue

                # If rule is all ports, boto3 often gives From/To as -1
                ports_match = (
                    from_p in ports_of_interest or
                    to_p in ports_of_interest or
                    from_p == -1 or to_p == -1
                )
                if not ports_match:
                    continue

                findings["world_open_rules"].append({
                    "security_group_id": sg_id,
                    "name": sg_name,
                    "vpc": vpc_id,
                    "protocol": proto,
                    "from_port": from_p,
                    "to_port": to_p,
                    "world_open_ipv4": world_v4,
                    "world_open_ipv6": world_v6
                })

    return findings

if __name__ == "__main__":
    result = scan_security_groups()
    print(json.dumps(result, indent=2))
    with open("ec2_report.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\n[+] Wrote ec2_report.json")
