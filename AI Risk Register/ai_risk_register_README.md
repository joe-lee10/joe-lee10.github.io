# AI Governance Risk Register — NIST AI RMF

A structured risk register for AI/ML systems mapped to the [NIST AI Risk Management Framework (AI RMF 1.0)](https://airc.nist.gov/Home). Built to give engineering and product teams a working register rather than a static compliance artifact — risks are tied to specific AI lifecycle stages, control owners are named, and gaps are actionable.

---

## Why this exists

Most AI governance artifacts are produced for regulators, not operators. They document what *should* be true rather than what *is* true, and they rarely get updated after the initial audit cycle.

This register is built on a different premise: compliance artifacts should be version-controlled, machine-readable, and integrated into the same review cadence as other risk documentation. A risk entry that can't be parsed, filtered, or diff'd is harder to act on.

---

## Structure

```
ai-governance-risk-register/
├── ai_risk_register.csv     # The register itself
├── validate_register.py     # Validation and reporting script
└── README.md
```

---

## The Register (`ai_risk_register.csv`)

20 risks across all four NIST AI RMF functions, each tied to a specific lifecycle stage and control owner.

### Schema

| Column | Description |
|--------|-------------|
| `risk_id` | Unique identifier (RISK-001 through RISK-020) |
| `rmf_function` | NIST AI RMF function: GOVERN, MAP, MEASURE, or MANAGE |
| `rmf_category` | Subcategory code (e.g. GV-1.1, MP-3.4) |
| `risk_title` | Short descriptive title |
| `risk_description` | Full description of the risk |
| `ai_lifecycle_stage` | Stage where the risk is most relevant: Design, Development, Deployment, Operation, or Decommission |
| `likelihood` | 1–5 scale (1 = rare, 5 = almost certain) |
| `impact` | 1–5 scale (1 = negligible, 5 = critical) |
| `risk_score` | `likelihood × impact` (range: 1–25) |
| `risk_level` | Derived from score: Low (1–5), Medium (6–10), High (11–17), Critical (18–25) |
| `control_owner` | Team or role accountable for this risk |
| `current_controls` | Controls currently in place |
| `gaps_and_recommendations` | What's missing and what to do about it |
| `status` | Open, In Progress, Mitigated, or Accepted |
| `last_reviewed` | ISO 8601 date of last review (YYYY-MM-DD) |

### Risk scoring matrix

| Score | Level |
|-------|-------|
| 1–5 | Low |
| 6–10 | Medium |
| 11–17 | High |
| 18–25 | Critical |

---

## NIST AI RMF Coverage

The register covers all four core functions of the NIST AI RMF:

| Function | Purpose | Risks in Register |
|----------|---------|:-----------------:|
| **GOVERN** | Organizational policies, accountability structures, and culture | 5 |
| **MAP** | Identifying and classifying AI risks in context | 5 |
| **MEASURE** | Analyzing and tracking risk with metrics | 5 |
| **MANAGE** | Responding to and monitoring AI risks over time | 5 |

---

## Validation Script (`validate_register.py`)

Requires Python 3.10+. No external dependencies — runs on stdlib only.

```bash
# Validate the register and print a summary dashboard
python validate_register.py

# Full report broken down by RMF function
python validate_register.py --report

# Show Critical and High risks only
python validate_register.py --critical

# Show all Open risks
python validate_register.py --open

# Filter by RMF function
python validate_register.py --function GOVERN
python validate_register.py --function MAP
python validate_register.py --function MEASURE
python validate_register.py --function MANAGE
```

The script validates:
- Required fields are populated
- `rmf_function` is one of the four valid NIST AI RMF functions
- `risk_level` is consistent with `likelihood × impact`
- `risk_score` equals `likelihood × impact`
- `likelihood` and `impact` are integers in the 1–5 range
- `status` and `ai_lifecycle_stage` use controlled vocabulary
- `last_reviewed` is a valid ISO 8601 date
- No duplicate `risk_id` values

The script exits with code `0` on a clean pass and `1` if validation errors are found, making it suitable for use in CI pipelines.

---

## Extending the Register

To add a risk:
1. Add a new row to `ai_risk_register.csv`
2. Use the next sequential `risk_id` (e.g. `RISK-021`)
3. Run `python validate_register.py` to confirm no validation errors
4. Commit the updated CSV

To mark a risk mitigated:
- Update `status` to `Mitigated`
- Update `current_controls` to reflect the new control
- Update `last_reviewed` to today's date

---

## References

- [NIST AI RMF 1.0](https://doi.org/10.6028/NIST.AI.100-1)
- [NIST AI RMF Playbook](https://airc.nist.gov/Docs/2)
- [Executive Order 14110 on Safe, Secure, and Trustworthy AI](https://www.federalregister.gov/documents/2023/11/01/2023-24283/safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence)

---

## Author

**Joseph Lee** — GRC & Privacy Program Manager  
CIPP/US · CIPP/E · AWS Cloud Practitioner · OneTrust Certified  
[LinkedIn](https://linkedin.com/in/[your-handle]) · [Portfolio](https://[your-username].github.io)
