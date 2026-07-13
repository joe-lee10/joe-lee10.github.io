# SOC 2 Type II Audit Walkthrough

A mock SOC 2 Type II audit built to demonstrate end-to-end compliance program execution — from control design through evidence collection, exception management, and audit opinion. Covers Security (Common Criteria), Availability, and Confidentiality Trust Services Criteria over a 12-month audit period.

Built to show how a GRC practitioner thinks about SOC 2 readiness: controls mapped to TSC criteria, evidence tied to specific testing procedures, exceptions documented with management responses, and an auditor opinion derived from the aggregate results.

> **Note:** All data represents a fictional entity ("Acme Technologies, Inc.") and a mock audit engagement. This is a portfolio demonstration, not a real SOC 2 report.

---

## What's covered

| Trust Services Criteria | Controls | Audit Period |
|------------------------|----------|-------------|
| Security (CC1–CC9) | 18 | Jul 1, 2025 – Jun 30, 2026 |
| Availability (A1) | 3 | Jul 1, 2025 – Jun 30, 2026 |
| Confidentiality (C1–C2) | 5 | Jul 1, 2025 – Jun 30, 2026 |
| **Total** | **26** | **12 months** |

---

## Quickstart

Requires Python 3.10+. No external dependencies.

```bash
# Run full audit and generate report.html
python3 soc2_audit.py

# Terminal summary only
python3 soc2_audit.py --summary

# Print exceptions to terminal
python3 soc2_audit.py --exceptions

# Filter by Trust Services Criteria
python3 soc2_audit.py --tsc Security
python3 soc2_audit.py --tsc Availability
python3 soc2_audit.py --tsc Confidentiality

# Custom output filename
python3 soc2_audit.py --output client_soc2_report
```

## Sample output

```
Total controls   : 26
Total exceptions : 7 (0 open)

Effective                         19
Effective with Exceptions          7
Ineffective                        0
Insufficient Evidence              0

Security             18/18 controls effective
Availability          3/3 controls effective
Confidentiality       5/5 controls effective
```

**Auditor opinion: Unqualified with Exceptions Noted** — all 7 exceptions identified during testing were remediated within the audit period.

A pre-generated sample report is available here: [View sample report](report.html)

---

## Structure

```
soc2-walkthrough/
├── data/
│   ├── controls.csv          # Control library mapped to TSC criteria
│   ├── evidence_log.csv      # Evidence of control operation over audit period
│   └── exceptions.csv        # Control exceptions and management responses
├── soc2_audit.py             # Audit processing script
├── report.html               # Generated HTML audit report
└── README.md
```

---

## Data schemas

### controls.csv
| Column | Description |
|--------|-------------|
| `control_id` | Unique identifier (e.g. CC-001, A-001, C-001) |
| `tsc_category` | Trust Services Criteria category (Security, Availability, Confidentiality) |
| `tsc_ref` | Specific TSC reference (e.g. CC6.1, A1.3) |
| `control_title` | Short control name |
| `control_description` | Full description of what the control does |
| `control_type` | Preventive / Detective / Corrective / Monitoring / Entity-Level |
| `frequency` | How often the control operates (Continuous / Daily / Quarterly / Annual / Per Event) |
| `control_owner` | Team or role responsible |
| `testing_method` | How the control is tested during audit |

### evidence_log.csv
| Column | Description |
|--------|-------------|
| `evidence_id` | Unique identifier |
| `control_id` | Control this evidence supports |
| `evidence_date` | Date evidence was collected |
| `evidence_type` | Documentation / System Screenshot / Report / Ticket / Interview |
| `evidence_description` | What was reviewed and what it showed |
| `evidence_source` | System or document the evidence came from |
| `reviewer` | Person who collected and reviewed the evidence |
| `result` | Effective / Exception |

### exceptions.csv
| Column | Description |
|--------|-------------|
| `exception_id` | Unique identifier |
| `control_id` | Control where exception was identified |
| `exception_title` | Short description of the exception |
| `exception_description` | Full description of what was found |
| `severity` | Minor / Moderate / Significant |
| `management_response` | How management responded to the finding |
| `remediation_owner` | Team responsible for fixing it |
| `remediation_date` | Date remediation was completed |
| `status` | Remediated / Open |

---

## Audit opinion logic

The script derives an auditor opinion from the control results:

| Condition | Opinion |
|-----------|---------|
| All controls effective, no exceptions | Unqualified (Clean) |
| Controls effective, exceptions identified and remediated | Unqualified with Exceptions Noted |
| Open exceptions or ineffective controls | Qualified |

---

## References

- [AICPA Trust Services Criteria](https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [SOC 2 Trust Services Criteria (2017)](https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf)
- [COSO Internal Control Framework](https://www.coso.org/guidance-on-ic)

---

## Author

**Joseph Lee** — GRC & Privacy Program Manager  
CIPP/US · CIPP/E · AWS Cloud Practitioner · OneTrust Certified  
[LinkedIn](https://linkedin.com/in/[your-handle]) · [Portfolio](https://joe-lee10.github.io)
