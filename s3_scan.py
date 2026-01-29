#!/usr/bin/env python3
import json
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

WORLD_PUBLIC_PRINCIPAL_TOKENS = ['"Principal":"*"', '"Principal": "*"']

def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def get_all_buckets(s3):
    resp = s3.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]

def bucket_bpa_disabled(s3, bucket):
    """Check if Block Public Access (BPA) is disabled or weak."""
    try:
        bpa = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        return not all([
            bpa.get("BlockPublicAcls", False),
            bpa.get("IgnorePublicAcls", False),
            bpa.get("BlockPublicPolicy", False),
            bpa.get("RestrictPublicBuckets", False)
        ])
    except ClientError:
        return True  # No BPA config = disabled

def bucket_has_public_policy(s3, bucket):
    try:
        policy = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        return any(tok in policy for tok in WORLD_PUBLIC_PRINCIPAL_TOKENS)
    except ClientError:
        return False

def bucket_has_public_acl(s3, bucket):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
        return False
    except ClientError:
        return False

def list_public_objects_by_acl(s3, bucket, max_keys=500):
    """List objects whose ACLs are public. Scans up to max_keys objects for speed."""
    public_objs = []
    token = None
    scanned = 0
    while True:
        kwargs = {"Bucket": bucket, "MaxKeys": 1000}
        if token: kwargs["ContinuationToken"] = token
        try:
            resp = s3.list_objects_v2(**kwargs)
        except ClientError:
            break
        contents = resp.get("Contents", [])
        if not contents:
            break
        for obj in contents:
            key = obj["Key"]
            scanned += 1
            acl = s3.get_object_acl(Bucket=bucket, Key=key)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                perm = grant.get("Permission", "")
                if perm in ("READ", "FULL_CONTROL") and ("AllUsers" in uri or "AuthenticatedUsers" in uri):
                    public_objs.append({"bucket": bucket, "key": key})
                    break
            if scanned >= max_keys:
                return public_objs
        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break
    return public_objs

def scan_s3():
    s3 = boto3.client("s3")
    findings = {
        "generated_at": utcnow_iso(),
        "public_buckets": [],
        "bpa_disabled_buckets": [],
        "public_objects": [],
        "total_buckets": 0
    }

    buckets = get_all_buckets(s3)
    findings["total_buckets"] = len(buckets)

    for b in buckets:
        bpa_disabled = bucket_bpa_disabled(s3, b)
        public_policy = bucket_has_public_policy(s3, b)
        public_acl = bucket_has_public_acl(s3, b)

        if bpa_disabled or public_policy or public_acl:
            findings["public_buckets"].append({
                "bucket": b,
                "public_policy": public_policy,
                "public_acl": public_acl,
                "bpa_disabled": bpa_disabled
            })

        if bpa_disabled:
            findings["bpa_disabled_buckets"].append(b)

        findings["public_objects"].extend(list_public_objects_by_acl(s3, b, max_keys=500))

    return findings

if __name__ == "__main__":
    results = scan_s3()
    print(json.dumps(results, indent=2))
    with open("s3_report.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n[+] Wrote s3_report.json")
