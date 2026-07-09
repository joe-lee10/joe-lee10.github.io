#!/usr/bin/env python3
"""
validate_register.py
--------------------
Parses and validates ai_risk_register.csv against the NIST AI RMF structure.

Usage:
    python validate_register.py                  # validate + print summary
    python validate_register.py --report         # full report by RMF function
    python validate_register.py --critical       # show Critical and High risks only
    python validate_register.py --open           # show Open risks only
    python validate_register.py --function MAP   # filter by RMF function
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime, date

REQUIRED_COLUMNS = [
    "risk_id", "rmf_function", "rmf_category", "risk_title",
    "risk_description", "ai_lifecycle_stage", "likelihood", "impact",
    "risk_score", "risk_level", "control_owner", "current_controls",
    "gaps_and_recommendations", "status", "last_reviewed",
]

VALID_RMF_FUNCTIONS  = {"GOVERN", "MAP", "MEASURE", "MANAGE"}
VALID_RISK_LEVELS    = {"Low", "Medium", "High", "Critical"}
VALID_STATUSES       = {"Open", "In Progress", "Mitigated", "Accepted"}
VALID_STAGES         = {"Design", "Development", "Deployment", "Operation", "Decommission"}
REGISTER_FILE = "ai_risk_register.csv"

def load_register(filepath):
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return rows

def expected_risk_level(score):
    if score <= 5:   return "Low"
    if score <= 10:  return "Medium"
    if score <= 17:  return "High"
    return "Critical"

def validate(rows):
    errors = []
    seen_ids = set()
    for i, row in enumerate(rows, start=2):
        rid = row.get("risk_id", f"ROW-{i}")
        prefix = f"[{rid}]"
        if rid in seen_ids:
            errors.append(f"{prefix} Duplicate risk_id.")
        seen_ids.add(rid)
        if row["rmf_function"] not in VALID_RMF_FUNCTIONS:
            errors.append(f"{prefix} Invalid rmf_function: '{row['rmf_function']}'.")
        if row["risk_level"] not in VALID_RISK_LEVELS:
            errors.append(f"{prefix} Invalid risk_level: '{row['risk_level']}'.")
        if row["status"] not in VALID_STATUSES:
            errors.append(f"{prefix} Invalid status: '{row['status']}'.")
        if row["ai_lifecycle_stage"] not in VALID_STAGES:
            errors.append(f"{prefix} Invalid ai_lifecycle_stage: '{row['ai_lifecycle_stage']}'.")
        try:
            likelihood = int(row["likelihood"])
            impact     = int(row["impact"])
            risk_score = int(row["risk_score"])
            if not (1 <= likelihood <= 5):
                errors.append(f"{prefix} likelihood must be 1-5, got {likelihood}.")
            if not (1 <= impact <= 5):
                errors.append(f"{prefix} impact must be 1-5, got {impact}.")
            if risk_score != likelihood * impact:
                errors.append(f"{prefix} risk_score {risk_score} != likelihood x impact ({likelihood}x{impact}={likelihood*impact}).")
            expected = expected_risk_level(risk_score)
            if row["risk_level"] != expected:
                errors.append(f"{prefix} risk_level '{row['risk_level']}' inconsistent with risk_score {risk_score} (expected '{expected}').")
        except ValueError as e:
            errors.append(f"{prefix} Non-numeric value in likelihood/impact/risk_score: {e}.")
        try:
            datetime.strptime(row["last_reviewed"], "%Y-%m-%d")
        except ValueError:
            errors.append(f"{prefix} last_reviewed '{row['last_reviewed']}' must be YYYY-MM-DD.")
        for col in REQUIRED_COLUMNS:
            if not row.get(col, "").strip():
                errors.append(f"{prefix} Required column '{col}' is empty.")
    return errors

LEVEL_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

def print_summary(rows, errors):
    total = len(rows)
    by_level  = defaultdict(int)
    by_func   = defaultdict(int)
    by_status = defaultdict(int)
    for r in rows:
        by_level[r["risk_level"]] += 1
        by_func[r["rmf_function"]] += 1
        by_status[r["status"]] += 1
    print("\n" + "=" * 58)
    print("  AI GOVERNANCE RISK REGISTER — VALIDATION SUMMARY")
    print(f"  NIST AI RMF  |  {date.today().isoformat()}")
    print("=" * 58)
    print(f"\n  Total risks:   {total}")
    print(f"  Validation:    {'PASS — no errors found' if not errors else f'FAIL — {len(errors)} error(s)'}\n")
    print("  -- By Risk Level --")
    for level in ["Critical", "High", "Medium", "Low"]:
        bar = "#" * by_level.get(level, 0)
        print(f"  {level:<10} {by_level.get(level, 0):>3}  {bar}")
    print("\n  -- By NIST AI RMF Function --")
    for func in ["GOVERN", "MAP", "MEASURE", "MANAGE"]:
        print(f"  {func:<10} {by_func.get(func, 0):>3} risks")
    print("\n  -- By Status --")
    for status in ["Open", "In Progress", "Mitigated", "Accepted"]:
        print(f"  {status:<15} {by_status.get(status, 0):>3}")
    if errors:
        print("\n  -- Validation Errors --")
        for e in errors:
            print(f"  x {e}")
    print("\n" + "=" * 58 + "\n")

def print_report(rows):
    by_func = defaultdict(list)
    for r in rows:
        by_func[r["rmf_function"]].append(r)
    for func in ["GOVERN", "MAP", "MEASURE", "MANAGE"]:
        risks = sorted(by_func[func], key=lambda r: LEVEL_ORDER.get(r["risk_level"], 9))
        print(f"\n{'='*58}\n  {func}  ({len(risks)} risks)\n{'='*58}")
        for r in risks:
            print(f"\n  {r['risk_id']}  [{r['risk_level']}]  {r['risk_title']}")
            print(f"  Category : {r['rmf_category']}")
            print(f"  Stage    : {r['ai_lifecycle_stage']}")
            print(f"  Status   : {r['status']}")
            print(f"  Owner    : {r['control_owner']}")
            print(f"  Gap      : {r['gaps_and_recommendations'][:90]}{'...' if len(r['gaps_and_recommendations']) > 90 else ''}")
    print()

def print_filtered(rows, level_filter=None, status_filter=None, func_filter=None):
    filtered = rows
    if level_filter:  filtered = [r for r in filtered if r["risk_level"] in level_filter]
    if status_filter: filtered = [r for r in filtered if r["status"] in status_filter]
    if func_filter:   filtered = [r for r in filtered if r["rmf_function"] == func_filter.upper()]
    filtered = sorted(filtered, key=lambda r: (LEVEL_ORDER.get(r["risk_level"], 9), r["risk_id"]))
    print(f"\n  {len(filtered)} risks matched\n")
    print(f"  {'ID':<12} {'LEVEL':<10} {'FUNCTION':<10} {'STATUS':<14} TITLE")
    print("  " + "-" * 78)
    for r in filtered:
        print(f"  {r['risk_id']:<12} {r['risk_level']:<10} {r['rmf_function']:<10} "
              f"{r['status']:<14} {r['risk_title'][:40]}{'...' if len(r['risk_title']) > 40 else ''}")
    print()

def main():
    args = sys.argv[1:]
    try:
        rows = load_register(REGISTER_FILE)
    except FileNotFoundError:
        print(f"\n  Could not find '{REGISTER_FILE}'. Run this script from the repo root.\n")
        sys.exit(1)
    errors = validate(rows)
    if "--report" in args:
        print_summary(rows, errors)
        print_report(rows)
    elif "--critical" in args:
        print_summary(rows, errors)
        print_filtered(rows, level_filter={"Critical", "High"})
    elif "--open" in args:
        print_summary(rows, errors)
        print_filtered(rows, status_filter={"Open"})
    elif "--function" in args:
        idx = args.index("--function")
        func = args[idx + 1] if idx + 1 < len(args) else None
        if not func:
            print("  Usage: python validate_register.py --function [GOVERN|MAP|MEASURE|MANAGE]")
            sys.exit(1)
        print_summary(rows, errors)
        print_filtered(rows, func_filter=func)
    else:
        print_summary(rows, errors)
    sys.exit(1 if errors else 0)

if __name__ == "__main__":
    main()