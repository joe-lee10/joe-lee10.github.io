# AWS Security Suite

A three-module Python audit suite that analyzes AWS IAM policy configurations, S3 bucket security settings, and CloudTrail event logs — flagging misconfigurations, overpermissioned roles, and suspicious activity in a consolidated HTML report.

Built to demonstrate cloud security engineering thinking: structured analysis, severity-tiered findings, and actionable remediation guidance — the same outputs a security engineer would produce from a real AWS environment audit.

> **Note:** This suite runs against sample CSV data representing a fictional AWS environment. In a production context, the data files would be replaced with exports from AWS Config, IAM Access Analyzer, S3 inventory reports, and CloudTrail Lake queries.

---

## Modules

| Module | Data Source | What it checks |
|--------|-------------|----------------|
| **IAM Analyzer** | `data/iam_policies.csv` | Wildcard permissions, missing MFA conditions, privilege escalation paths, stale roles |
| **S3 Security Checker** | `data/s3_config.csv` | Public access, missing encryption, versioning, logging, MFA delete on sensitive buckets |
| **CloudTrail Auditor** | `data/cloudtrail_events.csv` | Root account usage, brute force indicators, CloudTrail tampering, privilege escalation APIs, destructive actions |

---

## Quickstart

Requires Python 3.10+. No external dependencies.

```bash
# Run all three modules and generate report.html
python3 aws_security_suite.py

# Run individual modules
python3 aws_security_suite.py --iam
python3 aws_security_suite.py --s3
python3 aws_security_suite.py --cloudtrail

# Terminal summary only (no report file)
python3 aws_security_suite.py --summary

# Custom output filename
python3 aws_security_suite.py --output acme_aws_audit
```

---

## Sample output (fictional environment)

Running against the sample data produces:

```
Total findings  : 63
Critical      7  ███████
High         21  █████████████████████
Medium       22  ██████████████████████
Low           7  ███████
Pass          6  ██████
```

A pre-generated sample report is available here: [View sample report](report.html)

---

## Structure

```
aws-security-suite/
├── data/
│   ├── iam_policies.csv        # Sample IAM roles and policy configurations
│   ├── s3_config.csv           # Sample S3 bucket security settings
│   └── cloudtrail_events.csv   # Sample CloudTrail event log
├── aws_security_suite.py       # Main audit script
├── report.html                 # Generated HTML report
└── README.md
```

---

## What gets flagged

### IAM Analyzer
- Wildcard actions (`*`) on wildcard resources — equivalent to AdministratorAccess
- Wildcard actions or wildcard resource scope individually
- IAMFullAccess assigned to non-admin accounts (privilege escalation risk)
- Missing MFA condition on human IAM user roles
- Root account activity
- Stale roles unused for 30+ days

### S3 Security Checker
- Public access not blocked (critical when sensitive data is present)
- Missing server-side encryption (SSE-S3 or SSE-KMS)
- Versioning disabled (especially on sensitive data buckets)
- Access logging not enabled
- MFA delete not enabled on sensitive or regulated data buckets
- Aged temporary/scratch buckets not cleaned up

### CloudTrail Auditor
- Root account console login or API activity
- Brute force indicators (3+ consecutive failed logins from same IP)
- CloudTrail tampering — `DeleteTrail` or `StopLogging` events
- AdministratorAccess attached to a user
- MFA device disabled
- Privilege escalation APIs called without MFA (`AttachUserPolicy`, `CreateAccessKey`, etc.)
- Secrets Manager access without MFA
- Security group opened to `0.0.0.0/0`
- S3 bucket ACL changed to public

---

## Adapting to a real environment

To run against real AWS data:

**IAM data** — export via AWS CLI:
```bash
aws iam get-account-authorization-details --output json
```

**S3 config** — export via AWS Config or CLI:
```bash
aws s3api list-buckets
aws s3api get-bucket-encryption --bucket <bucket-name>
```

**CloudTrail events** — export via CloudTrail Lake or CLI:
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
```

Reformat exports to match the CSV schema in the `data/` directory, then re-run the suite.

---

## Severity definitions

| Level | Definition |
|-------|------------|
| Critical | Immediate risk of breach, data exposure, or compliance violation |
| High | Significant control gap requiring prompt remediation |
| Medium | Control weakness that should be addressed in the next review cycle |
| Low | Best practice gap or hygiene issue |
| Pass | Control is in place — no finding |

---

## References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS CloudTrail Best Practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [NIST SP 800-144 — Security and Privacy in Public Cloud Computing](https://csrc.nist.gov/publications/detail/sp/800-144/final)

---

## Author

**Joseph Lee** — GRC & Privacy Program Manager  
CIPP/US · CIPP/E · AWS Cloud Practitioner · OneTrust Certified  
[LinkedIn](https://linkedin.com/in/[your-handle]) · [Portfolio](https://joe-lee10.github.io)
