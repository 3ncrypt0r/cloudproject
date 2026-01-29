#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def list_s3_buckets():
    try:
        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
        print("S3 Buckets found:", buckets if buckets else "No buckets in this account.")
    except NoCredentialsError:
        print("ERROR: No AWS credentials found. Run `aws configure`.")
    except ClientError as e:
        print("AWS ClientError:", e)

def get_caller_identity():
    try:
        sts = boto3.client("sts")
        resp = sts.get_caller_identity()
        print("Caller Identity:", resp)
    except Exception as e:
        print("Failed to get caller identity:", e)

if __name__ == "__main__":
    print("== Testing AWS connectivity ==")
    get_caller_identity()
    print()
    list_s3_buckets()
