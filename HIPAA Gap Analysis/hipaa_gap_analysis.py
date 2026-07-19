#!/usr/bin/env python3
"""
hipaa_gap_analysis.py
---------------------
Processes a HIPAA Security Rule + Privacy Rule gap assessment — loading
the control library and gap assessment data to produce a risk-tiered
gap analysis report with prioritized remediation recommendations.

Usage:
    python3 hipaa_gap_analysis.py                  # full report
    python3 hipaa_gap_analysis.py --summary        # terminal summary only
    python3 hipaa_gap_analysis.py --gaps           # show gaps only
    python3 hipaa_gap_analysis.py --rule Security  # filter by rule
    python3 hipaa_gap_analysis.py --priority P1    # filter by priority
    python3 hipaa_gap_analysis.py --output acme    # custom output filename
"""

import csv, os, sys
from collections import defaultdict
from datetime import date

CONTROLS_FILE  = os.path.join("data", "hipaa_controls.csv")
ASSESS_FILE    = os.path.join("data", "gap_assessment.csv")
DEFAULT_OUTPUT = "report.html"
REPORT_DATE    = date.today().isoformat()
ENTITY_NAME    = "Acme Health Technologies, Inc. (Mock)"
ASSESS_DATE    = "July 2026"

STATUS_ORDER = {"Not Implemented": 0, "Partially Implemented": 1, "Implemented": 2, "Not Applicable": 3}
RISK_ORDER   = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}

def load_csv(fp):
    with open(fp, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def merge(controls, assessments):
    assess_map = {a["control_id"]: a for a in assessments}
    results = []
    for ctrl in controls:
        a = assess_map.get(ctrl["control_id"], {})
        results.append({**ctrl, **a})
    return results

def print_summary(results):
    by_status   = defaultdict(int)
    by_rule     = defaultdict(lambda: defaultdict(int))
    by_risk     = defaultdict(int)
    by_priority = defaultdict(int)

    for r in results:
        st = r.get("current_status", "Unknown")
        by_status[st] += 1
        by_rule[r["hipaa_rule"]][st] += 1
        if st != "Implemented":
            by_risk[r.get("risk_level", "Unknown")] += 1
            by_priority[r.get("remediation_priority", "Unknown")] += 1

    total   = len(results)
    gaps    = total - by_status.get("Implemented", 0) - by_status.get("Not Applicable", 0)
    pct_gap = int(gaps / total * 100) if total else 0

    print("\n" + "="*66)
    print("  HIPAA GAP ANALYSIS — SUMMARY")
    print(f"  Assessment Date: {ASSESS_DATE}  |  Entity: {ENTITY_NAME}")
    print("="*66)
    print(f"\n  Total controls   : {total}")
    print(f"  Gaps identified  : {gaps} ({pct_gap}%)\n")
    for st in ["Implemented", "Partially Implemented", "Not Implemented", "Not Applicable"]:
        bar = "█" * by_status.get(st, 0)
        print(f"  {st:<28} {by_status.get(st,0):>3}  {bar}")
    print("\n  ── By HIPAA Rule ──────────────────────────────────────")
    for rule in ["Security Rule", "Privacy Rule"]:
        counts  = by_rule.get(rule, {})
        r_total = sum(counts.values())
        r_impl  = counts.get("Implemented", 0)
        print(f"  {rule:<20} {r_impl}/{r_total} implemented")
    print("\n  ── Gap Risk Levels ────────────────────────────────────")
    for risk in ["Critical", "High", "Medium", "Low"]:
        print(f"  {risk:<12} {by_risk.get(risk,0):>3} gap(s)")
    print("\n  ── Remediation Priority ───────────────────────────────")
    for p in ["P1", "P2", "P3"]:
        print(f"  {p}   {by_priority.get(p,0):>3} item(s)")
    print("\n" + "="*66 + "\n")

def print_gaps(results):
    gaps = [r for r in results if r.get("current_status") not in ("Implemented","Not Applicable")]
    gaps = sorted(gaps, key=lambda r: (RISK_ORDER.get(r.get("risk_level","Low"),9), PRIORITY_ORDER.get(r.get("remediation_priority","P3"),9)))
    print(f"\n  {len(gaps)} gap(s) identified:\n")
    print(f"  {'ID':<10}{'RULE':<16}{'STATUS':<24}{'RISK':<12}PRI  TITLE")
    print("  " + "-"*90)
    for r in gaps:
        title = r["control_title"][:38] + ("..." if len(r["control_title"])>38 else "")
        rule  = "Security" if "Security" in r["hipaa_rule"] else "Privacy"
        print(f"  {r['control_id']:<10}{rule:<16}{r.get('current_status',''):<24}{r.get('risk_level',''):<12}{r.get('remediation_priority','')}    {title}")
    print()

# ── HTML helpers ──────────────────────────────────────────────────────────────
def status_badge(st):
    m = {"Implemented":"st-impl","Partially Implemented":"st-part","Not Implemented":"st-not","Not Applicable":"st-na"}
    return f'<span class="badge {m.get(st,"st-na")}">{st}</span>'

def risk_badge(r):
    m = {"Critical":"risk-crit","High":"risk-high","Medium":"risk-med","Low":"risk-low"}
    return f'<span class="badge {m.get(r,"risk-low")}">{r}</span>'

def pri_badge(p):
    m = {"P1":"pri-p1","P2":"pri-p2","P3":"pri-p3"}
    return f'<span class="badge {m.get(p,"pri-p3")}">{p}</span>'

def req_badge(r):
    cls = "req-req" if r.strip().lower() == "required" else "req-addr"
    return f'<span class="badge {cls}">{r}</span>'

def build_report(results, output_path):
    by_status   = defaultdict(int)
    by_rule     = defaultdict(lambda: defaultdict(int))
    by_risk     = defaultdict(int)
    by_priority = defaultdict(int)
    by_cat      = defaultdict(list)

    for r in results:
        st = r.get("current_status","Unknown")
        by_status[st] += 1
        by_rule[r["hipaa_rule"]][st] += 1
        by_cat[r["safeguard_category"]].append(r)
        if st not in ("Implemented","Not Applicable"):
            by_risk[r.get("risk_level","Unknown")] += 1
            by_priority[r.get("remediation_priority","Unknown")] += 1

    total   = len(results)
    impl    = by_status.get("Implemented",0)
    partial = by_status.get("Partially Implemented",0)
    not_impl= by_status.get("Not Implemented",0)
    gaps    = partial + not_impl
    pct_impl= int(impl/total*100) if total else 0

    # P1 items
    p1_items = sorted(
        [r for r in results if r.get("remediation_priority")=="P1" and r.get("current_status") not in ("Implemented","Not Applicable")],
        key=lambda r: RISK_ORDER.get(r.get("risk_level","Low"),9)
    )
    p1_rows = "".join(f"""<tr>
      <td class="ctrl-id">{r['control_id']}</td>
      <td class="rule-label">{'Security' if 'Security' in r['hipaa_rule'] else 'Privacy'}</td>
      <td class="ctrl-title">{r['control_title']}</td>
      <td>{risk_badge(r.get('risk_level',''))}</td>
      <td class="rec-text">{r.get('remediation_recommendation','')}</td>
      <td style="white-space:nowrap">{r.get('target_date','')}</td>
      <td class="ctrl-owner">{r.get('owner','')}</td>
    </tr>""" for r in p1_items)

    # Full control table
    all_rows = ""
    sorted_results = sorted(results, key=lambda r: (
        0 if "Security" in r["hipaa_rule"] else 1,
        STATUS_ORDER.get(r.get("current_status","Unknown"),9),
        r["control_id"]
    ))
    for r in sorted_results:
        st = r.get("current_status","")
        all_rows += f"""<tr class="{'row-gap' if st not in ('Implemented','Not Applicable') else ''}">
          <td class="ctrl-id">{r['control_id']}</td>
          <td class="cfr-ref">{r['cfr_reference']}</td>
          <td class="ctrl-title">{r['control_title']}</td>
          <td class="cat-label">{r['safeguard_category']}</td>
          <td>{req_badge(r['required_or_addressable'])}</td>
          <td>{status_badge(st)}</td>
          <td>{risk_badge(r.get('risk_level','')) if st not in ('Implemented','Not Applicable') else '<span class="na">—</span>'}</td>
          <td>{pri_badge(r.get('remediation_priority','')) if st not in ('Implemented','Not Applicable') else '<span class="na">—</span>'}</td>
          <td class="gap-text">{r.get('gap_description','') if st != 'Implemented' else '<span class="na">No gap identified</span>'}</td>
          <td class="owner-text">{r.get('owner','')}</td>
        </tr>"""

    sec_rule = by_rule.get("Security Rule",{})
    priv_rule = by_rule.get("Privacy Rule",{})
    sec_total = sum(sec_rule.values())
    priv_total = sum(priv_rule.values())
    sec_impl  = sec_rule.get("Implemented",0)
    priv_impl = priv_rule.get("Implemented",0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HIPAA Gap Analysis — {ENTITY_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,500;1,6..72,400&display=swap" rel="stylesheet">
<style>
:root{{--bg:#ECEAE3;--panel:#E2DFD5;--ink:#1C2430;--ink-dim:#535C68;--ink-faint:#7C8490;--hairline:#C9C4B7;--accent:#6E2A2A;--accent-dim:rgba(110,42,42,0.08);
--crit:#7A1C1C;--crit-bg:rgba(122,28,28,0.10);--high:#8A4A1A;--high-bg:rgba(138,74,26,0.10);--med:#7A6A1A;--med-bg:rgba(122,106,26,0.10);
--low:#3A6A5A;--low-bg:rgba(58,106,90,0.10);--impl:#3A6A5A;--impl-bg:rgba(58,106,90,0.10);--part:#8A4A1A;--part-bg:rgba(138,74,26,0.10);
--not:#7A1C1C;--not-bg:rgba(122,28,28,0.10);--sans:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;--serif:'Newsreader',Georgia,serif;}}
*{{box-sizing:border-box;}} body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;}}
.page-header{{background:var(--ink);color:var(--bg);padding:36px 48px;}}
.page-header .eyebrow{{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:rgba(236,234,227,0.5);margin-bottom:10px;}}
.page-header h1{{font-family:var(--serif);font-size:30px;font-weight:500;margin:0 0 4px;}}
.page-header .entity{{font-family:var(--serif);font-style:italic;font-size:18px;color:rgba(236,234,227,0.7);margin:4px 0 12px;}}
.page-header .meta{{font-family:var(--mono);font-size:12px;color:rgba(236,234,227,0.5);line-height:2;}}
.stat-bar{{display:flex;border-bottom:1px solid var(--hairline);flex-wrap:wrap;}}
.stat{{flex:1;min-width:140px;padding:20px 28px;border-right:1px solid var(--hairline);}}
.stat:last-child{{border-right:none;}}
.stat .num{{font-family:var(--serif);font-size:32px;line-height:1;}}
.stat .label{{font-family:var(--mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);margin-top:4px;}}
.stat.s-impl .num{{color:var(--impl);}} .stat.s-gap .num{{color:var(--crit);}} .stat.s-crit .num{{color:var(--crit);}} .stat.s-high .num{{color:var(--high);}}
.progress-wrap{{padding:16px 28px;border-bottom:1px solid var(--hairline);display:flex;align-items:center;gap:16px;}}
.progress-track{{flex:1;height:6px;background:var(--hairline);border-radius:3px;overflow:hidden;}}
.progress-fill{{height:100%;background:var(--impl);border-radius:3px;}}
.progress-label{{font-family:var(--mono);font-size:12px;color:var(--ink-dim);white-space:nowrap;}}
.rule-summary{{display:flex;border-bottom:1px solid var(--hairline);}}
.rule-block{{flex:1;padding:18px 28px;border-right:1px solid var(--hairline);}}
.rule-block:last-child{{border-right:none;}}
.rule-block .rule-name{{font-family:var(--mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);margin-bottom:6px;}}
.rule-block .rule-stat{{font-family:var(--serif);font-size:18px;}}
.content{{padding:40px 48px;overflow-x:auto;}}
.p1-section{{background:var(--accent-dim);border:1px solid rgba(110,42,42,0.18);border-radius:2px;padding:28px 32px;margin-bottom:48px;}}
.p1-section h2{{font-family:var(--serif);font-size:22px;font-weight:500;margin:0 0 4px;}}
.p1-section .sub{{color:var(--ink-dim);font-size:13px;margin:0 0 20px;}}
.section-head{{margin-bottom:18px;}}
.section-head h2{{font-family:var(--serif);font-size:22px;font-weight:500;margin:0 0 4px;}}
.section-head p{{color:var(--ink-dim);font-size:13px;margin:0;}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px;}}
thead th{{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:0.07em;text-transform:uppercase;color:var(--ink-faint);padding:0 12px 10px;border-bottom:1px solid var(--hairline);white-space:nowrap;}}
tbody tr{{border-bottom:1px solid var(--hairline);transition:background .1s;}} tbody tr:hover{{background:var(--panel);}}
tbody tr.row-gap{{background:rgba(122,28,28,0.03);}}
td{{padding:12px;vertical-align:top;}}
td.ctrl-id{{font-family:var(--mono);font-size:11px;color:var(--ink-faint);white-space:nowrap;}}
td.cfr-ref{{font-family:var(--mono);font-size:10.5px;color:var(--ink-dim);white-space:nowrap;}}
td.ctrl-title{{font-weight:500;max-width:180px;}} td.cat-label{{font-size:12px;color:var(--ink-dim);white-space:nowrap;}}
td.gap-text{{color:var(--ink-dim);font-size:12.5px;max-width:260px;}} td.rec-text{{color:var(--ink-dim);font-size:12.5px;max-width:260px;}}
td.owner-text{{font-size:12px;color:var(--ink-dim);white-space:nowrap;}} td.rule-label{{font-family:var(--mono);font-size:11px;color:var(--ink-dim);white-space:nowrap;}}
.na{{color:var(--ink-faint);font-style:italic;font-size:12px;}}
.badge{{font-family:var(--mono);font-size:10px;letter-spacing:0.03em;text-transform:uppercase;padding:4px 8px;border-radius:20px;white-space:nowrap;display:inline-block;}}
.st-impl{{color:var(--impl);background:var(--impl-bg);}} .st-part{{color:var(--part);background:var(--part-bg);}}
.st-not{{color:var(--not);background:var(--not-bg);}} .st-na{{color:var(--ink-faint);background:var(--panel);}}
.risk-crit{{color:var(--crit);background:var(--crit-bg);}} .risk-high{{color:var(--high);background:var(--high-bg);}}
.risk-med{{color:var(--med);background:var(--med-bg);}} .risk-low{{color:var(--low);background:var(--low-bg);}}
.pri-p1{{color:var(--crit);background:var(--crit-bg);}} .pri-p2{{color:var(--high);background:var(--high-bg);}} .pri-p3{{color:var(--low);background:var(--low-bg);}}
.req-req{{color:var(--ink);background:var(--panel);}} .req-addr{{color:var(--ink-dim);background:var(--bg);border:1px solid var(--hairline);}}
.report-footer{{border-top:1px solid var(--hairline);padding:22px 48px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;}}
</style>
</head>
<body>
<div class="page-header">
  <div class="eyebrow">HIPAA Compliance — Security Rule + Privacy Rule Gap Analysis</div>
  <h1>HIPAA Gap Analysis Report</h1>
  <div class="entity">{ENTITY_NAME}</div>
  <div class="meta">Assessment Date: {ASSESS_DATE} &nbsp;·&nbsp; Report Generated: {REPORT_DATE}<br>Scope: Security Rule (45 CFR §164.308–312) · Privacy Rule (45 CFR §164.502–530)<br>Note: Mock data for portfolio demonstration only</div>
</div>
<div class="stat-bar">
  <div class="stat"><div class="num">{total}</div><div class="label">Controls Assessed</div></div>
  <div class="stat s-impl"><div class="num">{impl}</div><div class="label">Implemented</div></div>
  <div class="stat s-gap"><div class="num">{partial}</div><div class="label">Partial</div></div>
  <div class="stat s-crit"><div class="num">{not_impl}</div><div class="label">Not Implemented</div></div>
  <div class="stat s-high"><div class="num">{by_risk.get('Critical',0) + by_risk.get('High',0)}</div><div class="label">Crit/High Gaps</div></div>
  <div class="stat"><div class="num">{len(p1_items)}</div><div class="label">P1 Items</div></div>
</div>
<div class="progress-wrap">
  <div class="progress-track"><div class="progress-fill" style="width:{pct_impl}%"></div></div>
  <div class="progress-label">{impl} of {total} controls implemented ({pct_impl}%)</div>
</div>
<div class="rule-summary">
  <div class="rule-block"><div class="rule-name">Security Rule</div><div class="rule-stat">{sec_impl}/{sec_total} controls implemented &nbsp;·&nbsp; {sec_total - sec_impl} gap(s)</div></div>
  <div class="rule-block"><div class="rule-name">Privacy Rule</div><div class="rule-stat">{priv_impl}/{priv_total} controls implemented &nbsp;·&nbsp; {priv_total - priv_impl} gap(s)</div></div>
</div>
<div class="content">
  <div class="p1-section">
    <h2>Priority 1 — Immediate Remediation Required ({len(p1_items)} items)</h2>
    <p class="sub">Critical and High risk gaps requiring remediation within 90 days. Includes controls that are Required under HIPAA and represent significant compliance exposure.</p>
    <table><thead><tr><th>Control</th><th>Rule</th><th>Title</th><th>Risk</th><th>Recommendation</th><th>Target Date</th><th>Owner</th></tr></thead>
    <tbody>{p1_rows}</tbody></table>
  </div>
  <div class="section-head">
    <h2>Full Gap Assessment</h2>
    <p>All {total} controls assessed across Security Rule and Privacy Rule. Rows highlighted indicate identified gaps.</p>
  </div>
  <table>
    <thead><tr><th>Control</th><th>CFR Ref</th><th>Title</th><th>Category</th><th>Type</th><th>Status</th><th>Risk</th><th>Priority</th><th>Gap Description</th><th>Owner</th></tr></thead>
    <tbody>{all_rows}</tbody>
  </table>
</div>
<div class="report-footer">
  <span>DOCUMENT CONTROL — Classification: Confidential · Mock data — not a real HIPAA assessment</span>
  <span>Generated by hipaa_gap_analysis.py · {REPORT_DATE}</span>
</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Report written to: {output_path}\n")

def main():
    args   = sys.argv[1:]
    output = DEFAULT_OUTPUT
    if "--output" in args:
        idx    = args.index("--output")
        output = (args[idx+1] + ".html") if idx+1 < len(args) else DEFAULT_OUTPUT

    for fp in [CONTROLS_FILE, ASSESS_FILE]:
        if not os.path.exists(fp):
            print(f"\n  Could not find '{fp}'. Run from the repo root.\n"); sys.exit(1)

    controls    = load_csv(CONTROLS_FILE)
    assessments = load_csv(ASSESS_FILE)
    results     = merge(controls, assessments)

    if "--rule" in args:
        idx  = args.index("--rule")
        filt = args[idx+1] if idx+1 < len(args) else None
        if filt:
            results = [r for r in results if filt.lower() in r["hipaa_rule"].lower()]

    if "--priority" in args:
        idx  = args.index("--priority")
        filt = args[idx+1] if idx+1 < len(args) else None
        if filt:
            results = [r for r in results if r.get("remediation_priority","").upper() == filt.upper()]

    print_summary(results)

    if "--gaps" in args:
        print_gaps(results)
    if "--summary" not in args and "--gaps" not in args:
        build_report(results, output)
    elif "--summary" not in args:
        build_report(results, output)

if __name__ == "__main__":
    main()
