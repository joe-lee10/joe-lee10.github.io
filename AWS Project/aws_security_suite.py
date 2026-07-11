#!/usr/bin/env python3
"""
aws_security_suite.py
---------------------
A three-module AWS security audit suite that analyzes sample IAM policy
configurations, S3 bucket settings, and CloudTrail events — flagging
misconfigurations, overpermissioned roles, and suspicious activity.

Modules:
  1. IAM Analyzer      — flags wildcard permissions, missing MFA, excessive access
  2. S3 Security Check — flags public access, missing encryption, logging gaps
  3. CloudTrail Audit  — flags root usage, failed logins, destructive API calls

Usage:
    python3 aws_security_suite.py              # run all modules + generate report
    python3 aws_security_suite.py --iam        # IAM module only
    python3 aws_security_suite.py --s3         # S3 module only
    python3 aws_security_suite.py --cloudtrail # CloudTrail module only
    python3 aws_security_suite.py --summary    # terminal summary, no report
    python3 aws_security_suite.py --output my_audit  # custom report filename
"""

import csv
import os
import sys
from datetime import date
from collections import defaultdict

# ── File paths ────────────────────────────────────────────────────────────────
IAM_FILE         = os.path.join("data", "iam_policies.csv")
S3_FILE          = os.path.join("data", "s3_config.csv")
CLOUDTRAIL_FILE  = os.path.join("data", "cloudtrail_events.csv")
DEFAULT_OUTPUT   = "report.html"

# ── Severity levels ───────────────────────────────────────────────────────────
CRITICAL = "Critical"
HIGH     = "High"
MEDIUM   = "Medium"
LOW      = "Low"
PASS     = "Pass"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, PASS: 4}

# ── CSV loader ────────────────────────────────────────────────────────────────
def load_csv(filepath):
    with open(filepath, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — IAM ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

def analyze_iam(rows):
    findings = []
    for r in rows:
        name       = r["role_name"]
        wildcard_a = r["allows_wildcard_actions"].strip().lower() == "true"
        wildcard_r = r["allows_wildcard_resources"].strip().lower() == "true"
        mfa        = r["has_mfa_condition"].strip().lower() == "true"
        assigned   = r["assigned_to"]
        policies   = r["attached_policies"]
        last_used  = int(r["last_used_days_ago"]) if r["last_used_days_ago"].strip().isdigit() else 999

        # Root account usage
        if r["role_type"].strip() == "" and "root" in name.lower():
            findings.append({
                "module": "IAM", "resource": name, "severity": CRITICAL,
                "finding": "Root account has been used recently",
                "detail": "Root account activity detected. Root usage should be restricted to break-glass scenarios only. Enable MFA on root and remove all root access keys.",
                "recommendation": "Disable root access keys, enable MFA on root account, use IAM roles for all administrative tasks."
            })
            continue

        # Wildcard actions + wildcard resources = full admin equivalent
        if wildcard_a and wildcard_r:
            findings.append({
                "module": "IAM", "resource": name, "severity": CRITICAL,
                "finding": "Wildcard actions and resources — equivalent to AdministratorAccess",
                "detail": f"Role grants * on * — effectively full administrative access. Assigned to: {assigned}.",
                "recommendation": "Scope permissions to specific actions and resources required for the role's function."
            })
        elif wildcard_a:
            findings.append({
                "module": "IAM", "resource": name, "severity": HIGH,
                "finding": "Wildcard actions granted",
                "detail": f"Policy allows all actions (*) on scoped resources. Assigned to: {assigned}.",
                "recommendation": "Replace wildcard actions with an explicit allow list of required API actions."
            })
        elif wildcard_r:
            findings.append({
                "module": "IAM", "resource": name, "severity": MEDIUM,
                "finding": "Wildcard resource scope",
                "detail": f"Policy actions apply to all resources (*). Attached policies: {policies}.",
                "recommendation": "Scope resource ARNs to specific buckets, instances, or prefixes where possible."
            })

        # IAM + EC2 full access for non-admin role
        if "IAMFullAccess" in policies and "intern" in assigned.lower():
            findings.append({
                "module": "IAM", "resource": name, "severity": CRITICAL,
                "finding": "IAMFullAccess assigned to intern account",
                "detail": "IAM full access on an intern account allows privilege escalation to any permission level.",
                "recommendation": "Remove IAMFullAccess immediately. Grant read-only IAM permissions only if required."
            })

        # MFA not enforced for console-accessible roles
        if not mfa and "user" in assigned.lower():
            findings.append({
                "module": "IAM", "resource": name, "severity": HIGH,
                "finding": "No MFA condition on IAM user role",
                "detail": f"Role assigned to {assigned} does not enforce MFA authentication as a condition.",
                "recommendation": "Add a condition requiring MFA (aws:MultiFactorAuthPresent: true) for all human IAM users."
            })

        # Stale role — not used in 30+ days
        if last_used > 30:
            findings.append({
                "module": "IAM", "resource": name, "severity": LOW,
                "finding": f"Role unused for {last_used} days",
                "detail": f"Role has not been used in {last_used} days. Assigned to: {assigned}.",
                "recommendation": "Review necessity of this role. Consider removing if no longer required."
            })

        # Clean finding
        if not wildcard_a and not wildcard_r and mfa and last_used <= 30:
            findings.append({
                "module": "IAM", "resource": name, "severity": PASS,
                "finding": "No issues detected",
                "detail": "Role follows least privilege principles with MFA enforced.",
                "recommendation": "Continue periodic access reviews."
            })

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — S3 SECURITY CHECKER
# ══════════════════════════════════════════════════════════════════════════════

def analyze_s3(rows):
    findings = []
    for r in rows:
        name      = r["bucket_name"]
        public    = r["public_access_blocked"].strip().lower() != "true"
        pub_pol   = r["bucket_policy_allows_public"].strip().lower() == "true"
        encrypted = r["server_side_encryption"].strip() not in ("", "None")
        versioned = r["versioning_enabled"].strip().lower() == "true"
        logged    = r["logging_enabled"].strip().lower() == "true"
        mfa_del   = r["mfa_delete"].strip().lower() == "true"
        sensitive = r["contains_sensitive_data"].strip().lower() == "true"
        enc_type  = r["server_side_encryption"].strip()
        age       = int(r["last_modified_days_ago"]) if r["last_modified_days_ago"].strip().isdigit() else 0
        is_static = "website" in name or "static" in name or "assets" in name

        # Public + sensitive data
        if (public or pub_pol) and sensitive and not is_static:
            findings.append({
                "module": "S3", "resource": name, "severity": CRITICAL,
                "finding": "Public access not blocked on bucket containing sensitive data",
                "detail": f"Bucket '{name}' contains sensitive data but public access controls are not fully enforced.",
                "recommendation": "Enable S3 Block Public Access on bucket and account level. Review bucket policy for public Allow statements."
            })
        elif public and not is_static:
            findings.append({
                "module": "S3", "resource": name, "severity": HIGH,
                "finding": "Public access not blocked",
                "detail": f"Block Public Access is not enabled. Bucket policy or ACLs may expose data publicly.",
                "recommendation": "Enable all four S3 Block Public Access settings unless the bucket is intentionally serving public content."
            })

        # Missing encryption on sensitive bucket
        if not encrypted and sensitive:
            findings.append({
                "module": "S3", "resource": name, "severity": HIGH,
                "finding": "Server-side encryption not configured on sensitive data bucket",
                "detail": f"Bucket contains sensitive data but has no SSE configured (current: {enc_type}).",
                "recommendation": "Enable SSE-S3 (AES256) at minimum. Consider SSE-KMS for sensitive data to enable key management and audit trails."
            })
        elif not encrypted:
            findings.append({
                "module": "S3", "resource": name, "severity": MEDIUM,
                "finding": "Server-side encryption not configured",
                "detail": f"No SSE configured on bucket '{name}'.",
                "recommendation": "Enable SSE-S3 as a baseline. Consider a bucket policy that denies uploads without encryption."
            })

        # Versioning
        if not versioned and sensitive:
            findings.append({
                "module": "S3", "resource": name, "severity": MEDIUM,
                "finding": "Versioning not enabled on sensitive data bucket",
                "detail": "Versioning protects against accidental deletion and ransomware. Not enabled on this sensitive data bucket.",
                "recommendation": "Enable versioning and consider Object Lock for compliance data."
            })
        elif not versioned:
            findings.append({
                "module": "S3", "resource": name, "severity": LOW,
                "finding": "Versioning not enabled",
                "detail": f"Versioning is disabled on '{name}'.",
                "recommendation": "Enable versioning to protect against accidental overwrites and deletions."
            })

        # Access logging
        if not logged:
            findings.append({
                "module": "S3", "resource": name, "severity": MEDIUM,
                "finding": "Access logging not enabled",
                "detail": f"S3 server access logging is disabled. No audit trail for access to '{name}'.",
                "recommendation": "Enable S3 server access logging and route logs to a dedicated audit log bucket."
            })

        # MFA delete for sensitive data
        if not mfa_del and sensitive:
            findings.append({
                "module": "S3", "resource": name, "severity": MEDIUM,
                "finding": "MFA delete not enabled on sensitive data bucket",
                "detail": "MFA delete prevents permanent object deletion without a second factor. Recommended for sensitive or regulated data.",
                "recommendation": "Enable MFA delete on buckets containing sensitive, financial, or regulated data."
            })

        # Aged temp bucket
        if age > 30 and ("temp" in name or "scratch" in name or "test" in name):
            findings.append({
                "module": "S3", "resource": name, "severity": LOW,
                "finding": f"Temporary/scratch bucket aged {age} days",
                "detail": f"Bucket '{name}' appears to be a temporary bucket that hasn't been modified in {age} days.",
                "recommendation": "Review bucket contents. Delete if no longer needed to reduce attack surface."
            })

        # Clean
        if not public and encrypted and versioned and logged:
            findings.append({
                "module": "S3", "resource": name, "severity": PASS,
                "finding": "Core security controls in place",
                "detail": "Public access blocked, encryption enabled, versioning on, logging active.",
                "recommendation": "Review MFA delete status for sensitive data buckets."
            })

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CLOUDTRAIL AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

# High-risk API calls that warrant review
DESTRUCTIVE_APIS = {
    "DeleteTrail", "StopLogging", "DeleteBucket", "DeleteUser",
    "DetachRolePolicy", "DeleteRolePolicy", "DeletePolicy"
}
PRIVILEGE_ESCALATION_APIS = {
    "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey",
    "UpdateAssumeRolePolicy", "PutUserPolicy", "AddUserToGroup"
}
IAM_CHANGE_APIS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAssumeRolePolicy",
    "DisableMFADevice", "DeactivateMFADevice"
}

def analyze_cloudtrail(rows):
    findings   = []
    fail_count = defaultdict(list)

    # First pass — collect failed logins
    for r in rows:
        if r["error_code"].strip() and "failed" in r["error_code"].lower():
            fail_count[r["user_identity"]].append(r)

    seen_root   = False
    seen_ips    = {}

    for r in rows:
        event   = r["event_name"].strip()
        user    = r["user_identity"].strip()
        ip      = r["source_ip"].strip()
        mfa     = r["mfa_authenticated"].strip().lower() == "true"
        error   = r["error_code"].strip()
        ts      = r["timestamp"]
        eid     = r["event_id"]
        resource = r["resources_affected"].strip()

        # Root account usage
        if "root" in user.lower() and not seen_root:
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {user}", "severity": CRITICAL,
                "finding": "Root account activity detected",
                "detail": f"Root account logged in or performed API actions at {ts} from {ip}. Root usage should be restricted to break-glass scenarios only.",
                "recommendation": "Remove root access keys, enable MFA on root, use IAM roles for all administrative tasks. Alert on all future root activity."
            })
            seen_root = True

        # Brute force — 3+ failed logins same user
        if user in fail_count and len(fail_count[user]) >= 3 and error and "failed" in error.lower():
            if user not in [f["resource"].split(" / ")[1] for f in findings if "Brute" in f["finding"]]:
                findings.append({
                    "module": "CloudTrail", "resource": f"{eid} / {user}", "severity": HIGH,
                    "finding": f"Brute force indicator — {len(fail_count[user])} consecutive failed logins",
                    "detail": f"{len(fail_count[user])} failed login attempts for {user} from {ip}. Possible credential stuffing or brute force attack.",
                    "recommendation": "Lock account, investigate source IP, enable GuardDuty for automated threat detection."
                })

        # CloudTrail tampering
        if event in ("DeleteTrail", "StopLogging"):
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": CRITICAL,
                "finding": f"CloudTrail tampering — {event}",
                "detail": f"{user} performed {event} at {ts}. Disabling audit logging is a common attacker tactic to cover tracks.",
                "recommendation": "Restore CloudTrail logging immediately. Enable CloudTrail log file integrity validation and alert on all StopLogging/DeleteTrail events."
            })

        # Privilege escalation
        if event in PRIVILEGE_ESCALATION_APIS and not mfa:
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": HIGH,
                "finding": f"Privilege escalation API call without MFA — {event}",
                "detail": f"{user} called {event} without MFA at {ts}. Target resource: {resource}.",
                "recommendation": "Require MFA for all IAM modification actions. Review the policy change for legitimacy."
            })

        # Admin policy attached
        if event == "AttachUserPolicy" and "Administrator" in resource:
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": CRITICAL,
                "finding": "AdministratorAccess policy attached to user",
                "detail": f"{user} attached AdministratorAccess to {resource} at {ts}.",
                "recommendation": "Review whether this grant is legitimate. Remove if not authorized. Use SCPs to prevent AdministratorAccess grants without approval."
            })

        # MFA disabled
        if event == "DisableMFADevice":
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": HIGH,
                "finding": "MFA device disabled",
                "detail": f"{user} disabled MFA for {resource} at {ts}.",
                "recommendation": "Verify this action was authorized. Re-enable MFA immediately if not. Alert on all MFA disable events."
            })

        # Sensitive secret access without MFA
        if event == "GetSecretValue" and not mfa:
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": HIGH,
                "finding": "Secrets Manager access without MFA",
                "detail": f"{user} accessed secret {resource} at {ts} without MFA authentication.",
                "recommendation": "Require MFA for access to production secrets. Review intern access to production Secrets Manager."
            })

        # Security group opened to world
        if event == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in r["notes"]:
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": HIGH,
                "finding": "Security group opened to 0.0.0.0/0",
                "detail": f"{user} opened port access to the public internet on {resource} at {ts}.",
                "recommendation": "Restrict security group ingress to known CIDR ranges. Use VPN or bastion hosts for SSH/RDP access."
            })

        # S3 bucket made public
        if event == "PutBucketAcl" and "public" in r["notes"].lower():
            findings.append({
                "module": "CloudTrail", "resource": f"{eid} / {resource}", "severity": HIGH,
                "finding": "S3 bucket ACL changed to public",
                "detail": f"{user} changed bucket ACL to public-read on {resource} at {ts}.",
                "recommendation": "Revert bucket ACL. Enable S3 Block Public Access at account level to prevent future public ACL grants."
            })

        # External IP login
        if event == "ConsoleLogin" and not error and not any(ip.startswith(p) for p in ("10.", "172.", "192.")):
            if ip not in seen_ips:
                seen_ips[ip] = True
                if "auditor" in user.lower() or "external" in user.lower():
                    findings.append({
                        "module": "CloudTrail", "resource": f"{eid} / {user}", "severity": LOW,
                        "finding": "Console login from external IP",
                        "detail": f"{user} logged in from external IP {ip} at {ts}. Verify this is an expected access pattern.",
                        "recommendation": "Confirm with the user that this login is legitimate. Consider IP allowlisting for privileged accounts."
                    })

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(iam, s3, ct):
    all_findings = iam + s3 + ct
    by_sev = defaultdict(int)
    for f in all_findings:
        by_sev[f["severity"]] += 1

    print("\n" + "=" * 62)
    print("  AWS SECURITY SUITE — AUDIT SUMMARY")
    print(f"  {date.today().isoformat()}")
    print("=" * 62)
    print(f"\n  Total findings  : {len(all_findings)}")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, PASS]:
        count = by_sev.get(sev, 0)
        bar   = "█" * count
        print(f"  {sev:<10} {count:>3}  {bar}")
    print(f"\n  IAM findings        : {len(iam)}")
    print(f"  S3 findings         : {len(s3)}")
    print(f"  CloudTrail findings : {len(ct)}")
    print("\n" + "=" * 62 + "\n")


def sev_badge(sev):
    classes = {
        CRITICAL: "sev-critical", HIGH: "sev-high",
        MEDIUM: "sev-medium", LOW: "sev-low", PASS: "sev-pass"
    }
    return f'<span class="badge {classes.get(sev, "")}">{sev}</span>'


def module_icon(mod):
    icons = {"IAM": "🔑", "S3": "🗄", "CloudTrail": "📋"}
    return icons.get(mod, "•")


def build_report(iam, s3, ct, output_path):
    all_findings = sorted(iam + s3 + ct, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    total     = len(all_findings)
    by_sev    = defaultdict(int)
    for f in all_findings:
        by_sev[f["severity"]] += 1

    criticals = by_sev[CRITICAL]
    highs     = by_sev[HIGH]
    passes    = by_sev[PASS]

    rows_html = ""
    for f in all_findings:
        rows_html += f"""
        <tr class="sev-row-{f['severity'].lower()}">
          <td class="mod">{module_icon(f['module'])} {f['module']}</td>
          <td class="resource">{f['resource']}</td>
          <td>{sev_badge(f['severity'])}</td>
          <td class="finding-text">{f['finding']}</td>
          <td class="detail-text">{f['detail']}</td>
          <td class="rec-text">{f['recommendation']}</td>
        </tr>"""

    critical_rows = ""
    for f in [x for x in all_findings if x["severity"] == CRITICAL]:
        critical_rows += f"""
        <tr>
          <td class="mod">{module_icon(f['module'])} {f['module']}</td>
          <td class="resource">{f['resource']}</td>
          <td class="finding-text">{f['finding']}</td>
          <td class="rec-text">{f['recommendation']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AWS Security Audit Report — {date.today().isoformat()}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,500&display=swap" rel="stylesheet">
<style>
  :root{{
    --bg:#ECEAE3;--panel:#E2DFD5;--ink:#1C2430;--ink-dim:#535C68;--ink-faint:#7C8490;
    --hairline:#C9C4B7;--accent:#6E2A2A;--accent-dim:rgba(110,42,42,0.1);
    --critical:#7A1C1C;--critical-bg:rgba(122,28,28,0.10);
    --high:#8A4A1A;--high-bg:rgba(138,74,26,0.10);
    --medium:#7A6A1A;--medium-bg:rgba(122,106,26,0.10);
    --low:#4A6A3A;--low-bg:rgba(74,106,58,0.10);
    --pass:#3A6A5A;--pass-bg:rgba(58,106,90,0.10);
    --sans:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;--serif:'Newsreader',Georgia,serif;
  }}
  *{{box-sizing:border-box;}}
  body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;}}

  .page-header{{background:var(--ink);color:var(--bg);padding:32px 44px;}}
  .page-header .eyebrow{{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:rgba(236,234,227,0.5);margin-bottom:8px;}}
  .page-header h1{{font-family:var(--serif);font-size:28px;font-weight:500;margin:0 0 6px;}}
  .page-header .meta{{font-family:var(--mono);font-size:12px;color:rgba(236,234,227,0.6);}}

  .stat-bar{{display:flex;border-bottom:1px solid var(--hairline);}}
  .stat{{flex:1;padding:22px 28px;border-right:1px solid var(--hairline);}}
  .stat:last-child{{border-right:none;}}
  .stat .num{{font-family:var(--serif);font-size:34px;line-height:1;}}
  .stat .label{{font-family:var(--mono);font-size:10.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);margin-top:4px;}}
  .stat.crit .num{{color:var(--critical);}}
  .stat.high .num{{color:var(--high);}}
  .stat.pass-s .num{{color:var(--pass);}}

  .sev-bar{{display:flex;gap:0;border-bottom:1px solid var(--hairline);}}
  .sev-seg{{padding:10px 20px;font-family:var(--mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;border-right:1px solid var(--hairline);}}
  .sev-seg.c{{color:var(--critical);background:var(--critical-bg);}}
  .sev-seg.h{{color:var(--high);background:var(--high-bg);}}
  .sev-seg.m{{color:var(--medium);background:var(--medium-bg);}}
  .sev-seg.l{{color:var(--low);background:var(--low-bg);}}
  .sev-seg.p{{color:var(--pass);background:var(--pass-bg);}}

  .content{{padding:36px 44px;overflow-x:auto;}}
  .section-head{{margin-bottom:18px;}}
  .section-head h2{{font-family:var(--serif);font-size:22px;font-weight:500;margin:0 0 4px;}}
  .section-head p{{color:var(--ink-dim);font-size:13px;margin:0;}}

  .critical-box{{background:var(--critical-bg);border:1px solid rgba(122,28,28,0.25);border-radius:2px;padding:24px 28px;margin-bottom:40px;}}
  .critical-box h2{{font-family:var(--serif);font-size:20px;color:var(--critical);margin:0 0 16px;font-weight:500;}}

  table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:48px;}}
  thead th{{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);padding:0 12px 12px;border-bottom:2px solid var(--hairline);white-space:nowrap;}}
  tbody tr{{border-bottom:1px solid var(--hairline);transition:background .1s;}}
  tbody tr:hover{{background:var(--panel);}}
  td{{padding:13px 12px;vertical-align:top;}}
  td.mod{{font-family:var(--mono);font-size:11px;white-space:nowrap;color:var(--ink-dim);}}
  td.resource{{font-family:var(--mono);font-size:11px;color:var(--ink-dim);max-width:160px;word-break:break-all;}}
  td.finding-text{{font-weight:500;max-width:200px;}}
  td.detail-text{{color:var(--ink-dim);max-width:260px;font-size:12.5px;}}
  td.rec-text{{color:var(--ink-dim);max-width:220px;font-size:12.5px;}}

  .badge{{font-family:var(--mono);font-size:10px;letter-spacing:0.04em;text-transform:uppercase;padding:4px 8px;border-radius:20px;white-space:nowrap;}}
  .sev-critical{{color:var(--critical);background:var(--critical-bg);}}
  .sev-high{{color:var(--high);background:var(--high-bg);}}
  .sev-medium{{color:var(--medium);background:var(--medium-bg);}}
  .sev-low{{color:var(--low);background:var(--low-bg);}}
  .sev-pass{{color:var(--pass);background:var(--pass-bg);}}

  .report-footer{{border-top:1px solid var(--hairline);padding:20px 44px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);display:flex;justify-content:space-between;}}
</style>
</head>
<body>

<div class="page-header">
  <div class="eyebrow">AWS Security Audit — Sample Data</div>
  <h1>AWS Security Suite Report</h1>
  <div class="meta">Generated: {date.today().isoformat()} &nbsp;·&nbsp; Modules: IAM · S3 · CloudTrail &nbsp;·&nbsp; Note: Built on sample data for portfolio demonstration</div>
</div>

<div class="stat-bar">
  <div class="stat"><div class="num">{total}</div><div class="label">Total Findings</div></div>
  <div class="stat crit"><div class="num">{by_sev[CRITICAL]}</div><div class="label">Critical</div></div>
  <div class="stat high"><div class="num">{by_sev[HIGH]}</div><div class="label">High</div></div>
  <div class="stat"><div class="num">{by_sev[MEDIUM]}</div><div class="label">Medium</div></div>
  <div class="stat"><div class="num">{by_sev[LOW]}</div><div class="label">Low</div></div>
  <div class="stat pass-s"><div class="num">{passes}</div><div class="label">Pass</div></div>
</div>

<div class="sev-bar">
  <div class="sev-seg c">Critical: {by_sev[CRITICAL]}</div>
  <div class="sev-seg h">High: {by_sev[HIGH]}</div>
  <div class="sev-seg m">Medium: {by_sev[MEDIUM]}</div>
  <div class="sev-seg l">Low: {by_sev[LOW]}</div>
  <div class="sev-seg p">Pass: {passes}</div>
</div>

<div class="content">

  {"" if criticals == 0 else f'''
  <div class="critical-box">
    <h2>⚠ Critical Findings ({criticals})</h2>
    <table>
      <thead><tr><th>Module</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
      <tbody>{critical_rows}</tbody>
    </table>
  </div>
  '''}

  <div class="section-head">
    <h2>All Findings</h2>
    <p>Sorted by severity. IAM, S3, and CloudTrail findings consolidated into a single view.</p>
  </div>

  <table>
    <thead>
      <tr><th>Module</th><th>Resource</th><th>Severity</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

</div>

<div class="report-footer">
  <span>DOCUMENT CONTROL — Classification: Confidential · Sample data only — not a real AWS environment</span>
  <span>Generated by aws_security_suite.py · {date.today().isoformat()}</span>
</div>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Report written to: {output_path}\n")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]
    output = DEFAULT_OUTPUT
    if "--output" in args:
        idx    = args.index("--output")
        output = (args[idx + 1] + ".html") if idx + 1 < len(args) else DEFAULT_OUTPUT

    run_iam = "--iam" in args or not any(a in args for a in ["--iam","--s3","--cloudtrail"])
    run_s3  = "--s3"  in args or not any(a in args for a in ["--iam","--s3","--cloudtrail"])
    run_ct  = "--cloudtrail" in args or not any(a in args for a in ["--iam","--s3","--cloudtrail"])

    for filepath in ([IAM_FILE] if run_iam else []) + ([S3_FILE] if run_s3 else []) + ([CLOUDTRAIL_FILE] if run_ct else []):
        if not os.path.exists(filepath):
            print(f"\n  Could not find '{filepath}'. Run from the repo root.\n")
            sys.exit(1)

    iam = analyze_iam(load_csv(IAM_FILE)) if run_iam else []
    s3  = analyze_s3(load_csv(S3_FILE))   if run_s3  else []
    ct  = analyze_cloudtrail(load_csv(CLOUDTRAIL_FILE)) if run_ct else []

    print_summary(iam, s3, ct)

    if "--summary" not in args:
        build_report(iam, s3, ct, output)


if __name__ == "__main__":
    main()
