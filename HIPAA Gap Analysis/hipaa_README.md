# HIPAA Compliance Gap Analysis

A Python-based HIPAA risk assessment tool covering both the Security Rule (45 CFR §164.308–312) and Privacy Rule (45 CFR §164.502–530) — loading a control library and gap assessment data to produce a risk-tiered gap analysis report with prioritized remediation recommendations.

Built to demonstrate how a compliance practitioner approaches HIPAA readiness: controls mapped to CFR citations, current state assessment against each control, risk and priority scoring, and a structured remediation roadmap — the same outputs produced in a real HIPAA compliance engagement.

> **Note:** All data represents a fictional entity ("Acme Health Technologies, Inc.") and a mock assessment. This is a portfolio demonstration, not a real HIPAA compliance assessment.

---

## Scope

| Rule | CFR Reference | Controls | Categories |
|------|--------------|----------|------------|
| Security Rule | 45 CFR §164.308–312 | 42 | Administrative · Physical · Technical |
| Privacy Rule | 45 CFR §164.502–530 | 15 | Privacy |
| **Total** | | **57** | |

---

## Quickstart

Requires Python 3.10+. No external dependencies.

```bash
# Run full gap analysis and generate report.html
python3 hipaa_gap_analysis.py

# Terminal summary only
python3 hipaa_gap_analysis.py --summary

# Show only gap controls
python3 hipaa_gap_analysis.py --gaps

# Filter by rule
python3 hipaa_gap_analysis.py --rule Security
python3 hipaa_gap_analysis.py --rule Privacy

# Filter by remediation priority
python3 hipaa_gap_analysis.py --priority P1
python3 hipaa_gap_analysis.py --priority P2

# Custom output filename
python3 hipaa_gap_analysis.py --output acme_hipaa_assessment
```

## Sample output (mock entity)

```
Total controls   : 57
Gaps identified  : 39 (68%)

Implemented              18
Partially Implemented    33
Not Implemented           6

Security Rule    14/42 implemented
Privacy Rule      4/15 implemented

Critical          3 gap(s)
High             22 gap(s)
Medium           14 gap(s)

P1    25 item(s)
P2    14 item(s)
```

A pre-generated sample report is available here: [View sample report](report.html)

---

## Structure

```
hipaa-gap-analysis/
├── data/
│   ├── hipaa_controls.csv    # HIPAA control library (Security + Privacy Rule)
│   └── gap_assessment.csv    # Current state assessment per control
├── hipaa_gap_analysis.py     # Gap analysis script
├── report.html               # Generated HTML report
└── README.md
```

---

## Data schemas

### hipaa_controls.csv

| Column | Description |
|--------|-------------|
| `control_id` | Unique identifier (e.g. SR-001, PR-001) |
| `hipaa_rule` | Security Rule or Privacy Rule |
| `cfr_reference` | Specific CFR citation (e.g. §164.308(a)(1)) |
| `safeguard_category` | Administrative / Physical / Technical / Privacy |
| `control_title` | Short control name |
| `control_description` | Full regulatory description of the control |
| `required_or_addressable` | Required (must implement) or Addressable (implement or document why not) |

### gap_assessment.csv

| Column | Description |
|--------|-------------|
| `control_id` | Maps to `hipaa_controls.csv` |
| `current_status` | Implemented / Partially Implemented / Not Implemented / Not Applicable |
| `gap_description` | Description of the gap and what is missing |
| `risk_level` | Critical / High / Medium / Low |
| `remediation_priority` | P1 (immediate) / P2 (near-term) / P3 (planned) |
| `remediation_recommendation` | Specific action to close the gap |
| `evidence_available` | Yes / No — whether supporting evidence exists |
| `owner` | Team or role responsible for remediation |
| `target_date` | Target remediation date |

---

## Risk and priority definitions

### Risk levels

| Level | Definition |
|-------|------------|
| Critical | Significant regulatory exposure or likelihood of OCR enforcement action |
| High | Material gap in Required control with substantial compliance risk |
| Medium | Gap in Addressable control or Required control with partial implementation |
| Low | Best practice gap or minor documentation deficiency |

### Remediation priorities

| Priority | Definition |
|----------|------------|
| P1 | Immediate — remediate within 90 days |
| P2 | Near-term — remediate within 180 days |
| P3 | Planned — remediate within 12 months |

---

## Key findings in the mock assessment

The mock assessment reflects a common pattern for organizations earlier in HIPAA maturity:

- **No formal risk analysis (SR-002)** — the foundational HIPAA requirement; all other controls depend on it
- **No accounting of disclosures process (PR-004)** — a frequent OCR audit finding
- **Incomplete BAA inventory (SR-025, PR-012)** — missing BAAs are a leading cause of HIPAA settlements
- **MFA not consistently enforced (SR-040)** — top technical safeguard gap across the industry
- **HIPAA-specific training absent (SR-014, PR-007)** — general security training does not satisfy the HIPAA training requirement

---

## References

- [HHS HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [HHS HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
- [OCR HIPAA Audit Protocol](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html)
- [NIST SP 800-66r2 — Implementing the HIPAA Security Rule](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)
- [HHS Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html)

---

## Author

**Joseph Lee** — GRC & Privacy Program Manager  
CIPP/US · CIPP/E · AWS Cloud Practitioner · OneTrust Certified  
[LinkedIn](https://linkedin.com/in/[your-handle]) · [Portfolio](https://joe-lee10.github.io)
