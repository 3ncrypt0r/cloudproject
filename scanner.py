#!/usr/bin/env python3
import os
import json
import shutil
from datetime import datetime, timezone
from flask import Flask, render_template_string, redirect, url_for, flash, request

import boto3
from botocore.exceptions import ClientError

# Import scanners (must be present in same folder)
from s3_scan import scan_s3
from ec2_scan import scan_security_groups
from iam_scan import scan_iam_users_without_mfa

# ---------------- helpers ----------------
def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ensure_dirs():
    os.makedirs("individual_report", exist_ok=True)
    os.makedirs("final_report", exist_ok=True)

def write_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def delete_all_reports():
    for d in ("individual_report", "final_report"):
        if os.path.isdir(d):
            shutil.rmtree(d)
    ensure_dirs()

# ---------------- remediation helpers ----------------
def enable_bucket_bpa(bucket):
    """Enable Block Public Access (BPA) for the bucket."""
    s3 = boto3.client("s3")
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        return True, f"BPA enabled on bucket: {bucket}"
    except ClientError as e:
        return False, f"Failed to enable BPA on {bucket}: {e}"

def _is_ipv4(addr):
    return ":" not in addr

def _format_client_cidr(remote_addr):
    """Return a default CIDR for the requester. IPv4 -> /32, IPv6 -> /128."""
    if remote_addr is None:
        return None
    if _is_ipv4(remote_addr):
        return f"{remote_addr}/32"
    else:
        # if IPv6, ensure proper form
        return f"{remote_addr}/128"

def restrict_world_to_cidr(sg_id, cidr):
    """
    Replace any world-open (0.0.0.0/0 or ::/0) entries in SG ingress rules
    with the provided CIDR (e.g., admin_public_ip/32).
    Steps:
      - Describe SG, locate offending IpPermissions
      - For each offending permission: revoke only the world ranges, then add the same permission with the given CIDR
    Returns: (success:bool, message:str)
    """
    ec2 = boto3.client("ec2")
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return False, f"Security group {sg_id} not found."

        sg = sgs[0]
        offending_revoke_perms = []
        offending_add_perms = []

        for perm in sg.get("IpPermissions", []):
            # identify v4/v6 world ranges in this permission
            v4_world = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            v6_world = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]

            if not (v4_world or v6_world):
                continue

            # Minimal structure for revoke: include only world ranges (we will revoke these)
            revoke_perm = {}
            if "IpProtocol" in perm:
                revoke_perm["IpProtocol"] = perm["IpProtocol"]
            if "FromPort" in perm:
                revoke_perm["FromPort"] = perm["FromPort"]
            if "ToPort" in perm:
                revoke_perm["ToPort"] = perm["ToPort"]
            if v4_world:
                revoke_perm["IpRanges"] = v4_world
            if v6_world:
                revoke_perm["Ipv6Ranges"] = v6_world
            offending_revoke_perms.append(revoke_perm)

            # Build the "add" permission: same proto/ports, but with the provided CIDR
            add_perm = {}
            if "IpProtocol" in perm:
                add_perm["IpProtocol"] = perm["IpProtocol"]
            if "FromPort" in perm:
                add_perm["FromPort"] = perm["FromPort"]
            if "ToPort" in perm:
                add_perm["ToPort"] = perm["ToPort"]

            if _is_ipv4(cidr.split("/")[0]):
                add_perm["IpRanges"] = [{"CidrIp": cidr}]
            else:
                add_perm["Ipv6Ranges"] = [{"CidrIpv6": cidr}]
            offending_add_perms.append(add_perm)

        if not offending_revoke_perms:
            return True, "No world-open rules found to restrict."

        # Revoke world entries
        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=offending_revoke_perms)
        except ClientError as e:
            # If revoke fails, return failure (do not proceed to add)
            return False, f"Failed to revoke existing world-open rules: {e}"

        # Add new, restricted rules
        try:
            # Note: authorize_security_group_ingress accepts a list of IpPermissions similar to revoke
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=offending_add_perms)
        except ClientError as e:
            # If adding new rules fails, attempt to rollback by re-adding world rules to avoid lockout.
            try:
                ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=offending_revoke_perms)
                return False, f"Failed to add restricted rule but rolled back revoke: {e}"
            except ClientError:
                return False, f"Failed to add restricted rule and failed to rollback: {e}"

        return True, f"Replaced world-open rules in {sg_id} with {cidr}."
    except ClientError as e:
        return False, f"Failed operating on security group {sg_id}: {e}"

def get_iam_mfa_instructions():
    """Return a human-friendly instruction string for enabling MFA."""
    return (
        "IAM MFA Remediation Steps:\n"
        "1. Open AWS Console -> IAM -> Users.\n"
        "2. Click the user name -> Security credentials tab -> Manage MFA device.\n"
        "3. Choose 'Virtual MFA device', scan the QR code with an authenticator app, then enter the two OTPs to activate.\n\n"
        "Note: MFA activation requires the user to enter OTP codes and cannot be fully automated by the scanner."
    )

# ---------------- UI template ----------------
PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Cloud Misconfiguration Scanner</title>
  <style>
    body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin: 20px; color: #111; }
    h1 { margin-bottom: 10px; }
    .row { display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }
    .btn { text-decoration:none; padding:8px 12px; border-radius:8px; border:1px solid #333; font-weight:600; background:#fff; }
    .fix { border-color:#0a7; color:#0a7; }
    .danger { border-color:#c0392b; color:#c0392b; }
    .note { color:#555; margin:6px 0 12px; }
    .flash { background:#fff8c6; padding:10px; border-radius:8px; border:1px solid #ffec99; margin-bottom:12px; }
    table { border-collapse: collapse; width:100%; margin:12px 0; }
    th, td { border:1px solid #ddd; padding:8px; text-align:left; font-size:0.95rem; }
    th { background:#f5f5f5; }
    .bad { background:#ffe6e6; }
    .ok { background:#e8fceb; }
    code { background:#f4f4f4; padding:2px 6px; border-radius:6px; }
    pre { background:#fafafa; border:1px solid #eee; padding:10px; border-radius:6px; overflow:auto; }
    .small { font-size:0.9rem; color:#444; }
  </style>
</head>
<body>
  <h1>Cloud Misconfiguration Scanner</h1>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      {% for m in messages %}
        <div class="flash">{{ m }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  <div class="row">
    <a class="btn" href="{{ url_for('scan_ec2') }}">1) EC2 report</a>
    <a class="btn" href="{{ url_for('scan_iam') }}">2) IAM report</a>
    <a class="btn" href="{{ url_for('scan_s3_route') }}">3) S3 report</a>
    <a class="btn" href="{{ url_for('scan_all') }}">4) All report</a>
    <a class="btn danger" href="{{ url_for('wipe_reports') }}" onclick="return confirm('Delete ALL generated reports?')">5) Delete all reports</a>
  </div>

  <!-- ================= S3 VIEW ================= -->
  {% if view == 's3' %}
    <h2>S3 Bucket Findings</h2>
    <p class="note">Public policy, public ACL and Block Public Access (BPA) status. Fix attempts to enable BPA.</p>
    <p>Total buckets: <strong>{{ s3.total_buckets }}</strong></p>

    <h3>Public / Risky Buckets</h3>
    <table>
      <tr><th>Bucket</th><th>Public Policy</th><th>Public ACL</th><th>BPA Disabled/Weak</th><th>Action</th></tr>
      {% for b in s3.public_buckets %}
        <tr class="bad">
          <td>{{ b.bucket }}</td><td>{{ b.public_policy }}</td><td>{{ b.public_acl }}</td><td>{{ b.bpa_disabled }}</td>
          <td>
            {% if b.bpa_disabled %}
              <form method="post" action="{{ url_for('fix_s3_bpa', bucket=b.bucket) }}" style="display:inline;">
                <button class="btn fix" type="submit">Fix (enable BPA)</button>
              </form>
            {% else %}
              <span class="small">No-auto-fix needed</span>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      {% if s3.public_buckets|length == 0 %}
        <tr class="ok"><td colspan="5">No publicly exposed buckets detected.</td></tr>
      {% endif %}
    </table>

    <h3>Public Objects (by ACL)</h3>
    <table>
      <tr><th>Bucket</th><th>Object Key</th></tr>
      {% for o in s3.public_objects %}
        <tr class="bad"><td>{{ o.bucket }}</td><td>{{ o.key }}</td></tr>
      {% endfor %}
      {% if s3.public_objects|length == 0 %}
        <tr class="ok"><td colspan="2">No public objects detected by ACL check.</td></tr>
      {% endif %}
    </table>
  {% endif %}

  <!-- ================= EC2 VIEW ================= -->
  {% if view == 'ec2' %}
    <h2>EC2 Security Groups</h2>
    <p class="note">World-open inbound rules (0.0.0.0/0 or ::/0). Fix attempts to replace world-open rules with your IP.</p>
    <p>Total security groups scanned: <strong>{{ ec2.total_security_groups }}</strong></p>

    <h3>World-open inbound rules</h3>
    <table>
      <tr><th>SG ID</th><th>Name</th><th>Protocol</th><th>From</th><th>To</th><th>IPv4</th><th>IPv6</th><th>Action</th></tr>
      {% for sg in ec2.world_open_rules %}
        <tr class="bad">
          <td>{{ sg.security_group_id }}</td><td>{{ sg.name }}</td><td>{{ sg.protocol }}</td><td>{{ sg.from_port }}</td><td>{{ sg.to_port }}</td><td>{{ sg.world_open_ipv4 }}</td><td>{{ sg.world_open_ipv6 }}</td>
          <td>
            <form method="post" action="{{ url_for('fix_ec2_replace', sg_id=sg.security_group_id) }}" style="display:inline;">
              <button class="btn fix" type="submit">Fix (restrict to my IP)</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      {% if ec2.world_open_rules|length == 0 %}
        <tr class="ok"><td colspan="8">No world-open rules found.</td></tr>
      {% endif %}
    </table>
  {% endif %}

  <!-- ================= IAM VIEW ================= -->
  {% if view == 'iam' %}
    <h2>IAM Users Without MFA</h2>
    <p class="note">Lists IAM users that do not have an MFA device registered.</p>
    <p>Total users: <strong>{{ iam.total_users }}</strong></p>

    <table>
      <tr><th>User</th></tr>
      {% for u in iam.users_without_mfa %}
        <tr class="bad"><td>{{ u }}</td></tr>
      {% endfor %}
      {% if iam.users_without_mfa|length == 0 %}
        <tr class="ok"><td>All users have MFA enabled.</td></tr>
      {% endif %}
    </table>

    <h3>Remediation (IAM MFA)</h3>
    <p class="small">Enabling MFA requires per-user activation. The app cannot fully automate this because OTP entry is required.</p>
    <form method="get" action="{{ url_for('fix_iam_mfa') }}">
      <button class="btn" type="submit">Show MFA remediation steps & CLI</button>
    </form>

    {% if remediation %}
      <h4>Instructions</h4>
      <pre>{{ remediation }}</pre>
    {% endif %}
  {% endif %}

  <!-- ================= ALL REPORT VIEW (STACKED FULL TABLES) ================= -->
  {% if view == 'all' %}
    <h2>ALL REPORT - Full Details</h2>

    <!-- S3 Section -->
    <section style="margin-top:14px;">
      <h3>S3 Bucket Findings</h3>
      <p class="note">Public policy, public ACL and Block Public Access (BPA) status. Fix attempts to enable BPA.</p>
      <p>Total buckets: <strong>{{ s3.total_buckets }}</strong></p>

      <table>
        <tr><th>Bucket</th><th>Public Policy</th><th>Public ACL</th><th>BPA Disabled/Weak</th><th>Action</th></tr>
        {% for b in s3.public_buckets %}
          <tr class="bad">
            <td>{{ b.bucket }}</td><td>{{ b.public_policy }}</td><td>{{ b.public_acl }}</td><td>{{ b.bpa_disabled }}</td>
            <td>
              {% if b.bpa_disabled %}
                <form method="post" action="{{ url_for('fix_s3_bpa', bucket=b.bucket) }}" style="display:inline;">
                  <button class="btn fix" type="submit">Fix (enable BPA)</button>
                </form>
              {% else %}
                <span class="small">No-auto-fix needed</span>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
        {% if s3.public_buckets|length == 0 %}
          <tr class="ok"><td colspan="5">No publicly exposed buckets detected.</td></tr>
        {% endif %}
      </table>

      <h4>Public Objects (by ACL)</h4>
      <table>
        <tr><th>Bucket</th><th>Object Key</th></tr>
        {% for o in s3.public_objects %}
          <tr class="bad"><td>{{ o.bucket }}</td><td>{{ o.key }}</td></tr>
        {% endfor %}
        {% if s3.public_objects|length == 0 %}
          <tr class="ok"><td colspan="2">No public objects detected by ACL check.</td></tr>
        {% endif %}
      </table>
    </section>

    <hr style="margin:18px 0; border:0; border-top:1px solid #eee;"/>

    <!-- EC2 Section -->
    <section>
      <h3>EC2 Security Groups</h3>
      <p class="note">World-open inbound rules (0.0.0.0/0 or ::/0). Fix attempts to restrict these rules to your client IP.</p>
      <p>Total security groups scanned: <strong>{{ ec2.total_security_groups }}</strong></p>

      <table>
        <tr><th>SG ID</th><th>Name</th><th>Protocol</th><th>From</th><th>To</th><th>IPv4</th><th>IPv6</th><th>Action</th></tr>
        {% for sg in ec2.world_open_rules %}
          <tr class="bad">
            <td>{{ sg.security_group_id }}</td><td>{{ sg.name }}</td><td>{{ sg.protocol }}</td><td>{{ sg.from_port }}</td><td>{{ sg.to_port }}</td><td>{{ sg.world_open_ipv4 }}</td><td>{{ sg.world_open_ipv6 }}</td>
            <td>
              <form method="post" action="{{ url_for('fix_ec2_replace', sg_id=sg.security_group_id) }}" style="display:inline;">
                <button class="btn fix" type="submit">Fix (restrict to my IP)</button>
              </form>
            </td>
          </tr>
        {% endfor %}
        {% if ec2.world_open_rules|length == 0 %}
          <tr class="ok"><td colspan="8">No world-open rules found.</td></tr>
        {% endif %}
      </table>
    </section>

    <hr style="margin:18px 0; border:0; border-top:1px solid #eee;"/>

    <!-- IAM Section -->
    <section>
      <h3>IAM Users Without MFA</h3>
      <p class="note">Lists IAM users without MFA devices.</p>
      <p>Total users: <strong>{{ iam.total_users }}</strong></p>

      <table>
        <tr><th>User</th></tr>
        {% for u in iam.users_without_mfa %}
          <tr class="bad"><td>{{ u }}</td></tr>
        {% endfor %}
        {% if iam.users_without_mfa|length == 0 %}
          <tr class="ok"><td>All users have MFA enabled.</td></tr>
        {% endif %}
      </table>

      <h4>Remediation (IAM MFA)</h4>
      <p class="small">Enabling MFA requires per-user activation. The app cannot fully automate this because OTP entry is required.</p>
      <form method="get" action="{{ url_for('fix_iam_mfa') }}">
        <button class="btn" type="submit">Show MFA remediation steps & CLI</button>
      </form>

      {% if remediation %}
        <h4>Instructions</h4>
        <pre>{{ remediation }}</pre>
      {% endif %}
    </section>
  {% endif %}

  <p class="note">Timestamp: {{ now }}</p>
</body>
</html>
"""

# ---------------- Flask App ----------------
app = Flask(__name__)
app.secret_key = "scanner-secret"

@app.route("/")
def home():
    ensure_dirs()
    return render_template_string(PAGE, view=None, remediation=None, now=utcnow_iso())

# ---------------- S3 routes ----------------
@app.route("/scan/s3")
def scan_s3_route():
    ensure_dirs()
    s3 = scan_s3()
    write_json(s3, "individual_report/s3_report.json")
    return render_template_string(PAGE, view="s3", s3=s3, remediation=None, now=utcnow_iso())

@app.route("/fix/s3/bpa/<path:bucket>", methods=["POST"])
def fix_s3_bpa(bucket):
    ensure_dirs()
    success, msg = enable_bucket_bpa(bucket)
    flash(msg)
    s3 = scan_s3()
    write_json(s3, "individual_report/s3_report.json")
    return render_template_string(PAGE, view="s3", s3=s3, remediation=msg, now=utcnow_iso())

# ---------------- EC2 routes ----------------
@app.route("/scan/ec2")
def scan_ec2():
    ensure_dirs()
    ec2 = scan_security_groups()
    write_json(ec2, "individual_report/ec2_report.json")
    return render_template_string(PAGE, view="ec2", ec2=ec2, remediation=None, now=utcnow_iso())

@app.route("/fix/ec2/revoke/<sg_id>", methods=["POST"])
def fix_ec2_revoke(sg_id):
    # kept for backward compatibility (if used)
    ensure_dirs()
    success, msg = revoke_world_ingress(sg_id) if 'revoke_world_ingress' in globals() else (False, "Function not available")
    flash(msg)
    ec2 = scan_security_groups()
    write_json(ec2, "individual_report/ec2_report.json")
    return render_template_string(PAGE, view="ec2", ec2=ec2, remediation=msg, now=utcnow_iso())

@app.route("/fix/ec2/replace/<sg_id>", methods=["POST"])
def fix_ec2_replace(sg_id):
    """
    New behavior: instead of deleting world-open rules, we replace them with the client's IP/CIDR.
    The CIDR is taken from the request's remote address (default) and converted to /32 (IPv4) or /128 (IPv6).
    """
    ensure_dirs()
    remote = request.remote_addr
    cidr = _format_client_cidr(remote)
    cli = None
    if cidr is None:
        flash("Unable to determine your client IP. Provide a CIDR manually.")
        # provide CLI snippet to run from admin
        cli = f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --ip-permissions '[...world ranges...]' && aws ec2 authorize-security-group-ingress --group-id {sg_id} --ip-permissions '[...with your-ip/CIDR...]'"
        return render_template_string(PAGE, view="ec2", ec2=scan_security_groups(), remediation="Client IP not available; see CLI snippet below.", cli_snippet=cli, now=utcnow_iso())

    # attempt to perform restrict operation
    success, msg = restrict_world_to_cidr(sg_id, cidr)
    if not success:
        # prepare CLI snippet for manual operation by admin
        # This is a generic snippet; user must edit the permissions details as required.
        cli = f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --ip-permissions '[{{\"IpProtocol\":\"tcp\",\"IpRanges\":[{{\"CidrIp\":\"0.0.0.0/0\"}}]}}]'\n" \
              f"aws ec2 authorize-security-group-ingress --group-id {sg_id} --ip-permissions '[{{\"IpProtocol\":\"tcp\",\"IpRanges\":[{{\"CidrIp\":\"{cidr}\"}}]}}]'"
        flash(f"Patch attempt failed: {msg}. CLI snippet provided for manual fix.")
    else:
        flash(msg)
    ec2 = scan_security_groups()
    write_json(ec2, "individual_report/ec2_report.json")
    return render_template_string(PAGE, view="ec2", ec2=ec2, remediation=msg, cli_snippet=cli, now=utcnow_iso())

# ---------------- IAM routes ----------------
@app.route("/scan/iam")
def scan_iam():
    ensure_dirs()
    iam = scan_iam_users_without_mfa()
    write_json(iam, "individual_report/iam_report.json")
    return render_template_string(PAGE, view="iam", iam=iam, remediation="Click for steps", now=utcnow_iso())

@app.route("/fix/iam/mfa")
def fix_iam_mfa():
    ensure_dirs()
    instr = get_iam_mfa_instructions()
    iam = scan_iam_users_without_mfa()
    return render_template_string(PAGE, view="iam", iam=iam, remediation=instr, now=utcnow_iso())

# ---------------- ALL report route ----------------
@app.route("/scan/all")
def scan_all():
    ensure_dirs()
    s3 = scan_s3()
    ec2 = scan_security_groups()
    iam = scan_iam_users_without_mfa()
    combined = {"s3": s3, "ec2": ec2, "iam": iam, "generated_at": utcnow_iso()}
    write_json(combined, "final_report/report.json")
    return render_template_string(PAGE, view="all", s3=s3, ec2=ec2, iam=iam, remediation=None, now=utcnow_iso())

# ---------------- Delete reports ----------------
@app.route("/delete-all")
def wipe_reports():
    delete_all_reports()
    flash("All generated JSON reports deleted (individual_report/ and final_report/ reset).")
    return redirect(url_for("home"))

# ---------------- Main ----------------
if __name__ == "__main__":
    ensure_dirs()
    app.run(host="127.0.0.1", port=5000, debug=True)
