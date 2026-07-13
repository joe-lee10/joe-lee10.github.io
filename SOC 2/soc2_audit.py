#!/usr/bin/env python3
"""
soc2_audit.py
-------------
Processes a mock SOC 2 Type II audit — loading the control library,
evidence log, and exceptions log to produce a structured audit report
covering Security, Availability, and Confidentiality Trust Services Criteria.

Audit period: July 1, 2025 – June 30, 2026

Usage:
    python3 soc2_audit.py                  # run full audit + generate report
    python3 soc2_audit.py --summary        # terminal summary only
    python3 soc2_audit.py --exceptions     # print exceptions to terminal
    python3 soc2_audit.py --tsc Security   # filter by TSC category
    python3 soc2_audit.py --output acme    # custom report filename
"""

import csv, os, sys
from collections import defaultdict
from datetime import date

CONTROLS_FILE   = os.path.join("data", "controls.csv")
EVIDENCE_FILE   = os.path.join("data", "evidence_log.csv")
EXCEPTIONS_FILE = os.path.join("data", "exceptions.csv")
DEFAULT_OUTPUT  = "report.html"

AUDIT_PERIOD_START = "July 1, 2025"
AUDIT_PERIOD_END   = "June 30, 2026"
ENTITY_NAME        = "Acme Technologies, Inc. (Mock)"
REPORT_DATE        = date.today().isoformat()

TSC_ORDER = ["Security", "Availability", "Confidentiality"]

def load_csv(fp):
    with open(fp, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def run_audit(controls, evidence, exceptions):
    ev_by = defaultdict(list)
    ex_by = defaultdict(list)
    for e in evidence:   ev_by[e["control_id"]].append(e)
    for x in exceptions: ex_by[x["control_id"]].append(x)

    results = []
    for ctrl in controls:
        cid     = ctrl["control_id"]
        evs     = ev_by.get(cid, [])
        exs     = ex_by.get(cid, [])
        open_ex = [x for x in exs if x["status"].strip().lower() != "remediated"]
        if not evs:           opinion = "Insufficient Evidence"
        elif open_ex:         opinion = "Ineffective"
        elif exs:             opinion = "Effective with Exceptions"
        else:                 opinion = "Effective"
        results.append({"control": ctrl, "evidence": evs, "exceptions": exs, "opinion": opinion})
    return results

def print_summary(results, exceptions):
    opinions = defaultdict(int)
    by_tsc   = defaultdict(lambda: {"eff": 0, "total": 0})
    for r in results:
        opinions[r["opinion"]] += 1
        tsc = r["control"]["tsc_category"]
        by_tsc[tsc]["total"] += 1
        if r["opinion"] in ("Effective", "Effective with Exceptions"):
            by_tsc[tsc]["eff"] += 1
    open_ex = sum(1 for x in exceptions if x["status"].strip().lower() != "remediated")
    print("\n" + "="*64)
    print("  SOC 2 TYPE II — MOCK AUDIT SUMMARY")
    print(f"  Audit Period: {AUDIT_PERIOD_START} – {AUDIT_PERIOD_END}")
    print(f"  Entity: {ENTITY_NAME}")
    print("="*64)
    print(f"\n  Total controls   : {len(results)}")
    print(f"  Total exceptions : {len(exceptions)} ({open_ex} open)\n")
    for op in ["Effective", "Effective with Exceptions", "Ineffective", "Insufficient Evidence"]:
        print(f"  {op:<32} {opinions.get(op,0):>3}")
    print("\n  ── By Trust Services Criteria ──────────────────────────")
    for tsc in TSC_ORDER:
        v = by_tsc.get(tsc, {"eff":0,"total":0})
        print(f"  {tsc:<20} {v['eff']}/{v['total']} controls effective")
    print("\n" + "="*64 + "\n")

def print_exceptions(exceptions):
    print(f"\n  {len(exceptions)} exception(s):\n")
    print(f"  {'ID':<10}{'CTRL':<10}{'SEV':<12}{'STATUS':<16}TITLE")
    print("  " + "-"*78)
    for x in exceptions:
        t = x["exception_title"][:46] + ("..." if len(x["exception_title"])>46 else "")
        print(f"  {x['exception_id']:<10}{x['control_id']:<10}{x['severity']:<12}{x['status']:<16}{t}")
    print()

def badge(text, cls):
    return f'<span class="badge {cls}">{text}</span>'

def opinion_badge(op):
    m = {"Effective":"op-eff","Effective with Exceptions":"op-ewe","Ineffective":"op-ineff","Insufficient Evidence":"op-insuf"}
    return badge(op, m.get(op,"op-insuf"))

def sev_badge(s):
    m = {"Minor":"sev-minor","Moderate":"sev-mod","Significant":"sev-sig"}
    return badge(s, m.get(s,"sev-minor"))

def status_badge(s):
    return badge(s, "st-rem" if s.strip().lower()=="remediated" else "st-open")

def build_report(results, exceptions_raw, output_path):
    opinions = defaultdict(int)
    by_tsc   = defaultdict(list)
    for r in results:
        opinions[r["opinion"]] += 1
        by_tsc[r["control"]["tsc_category"]].append(r)

    total     = len(results)
    effective = opinions["Effective"] + opinions["Effective with Exceptions"]
    with_ex   = opinions["Effective with Exceptions"]
    ineffective = opinions["Ineffective"]
    total_ex  = len(exceptions_raw)
    open_ex   = sum(1 for x in exceptions_raw if x["status"].strip().lower() != "remediated")

    if ineffective > 0 or open_ex > 0:
        overall_opinion, overall_class = "Qualified", "qual"
        overall_text = f"Controls were not operating effectively for {ineffective} control(s), or {open_ex} exception(s) remain open."
    elif with_ex > 0:
        overall_opinion, overall_class = "Unqualified with Exceptions Noted", "ewe"
        overall_text = f"Controls operated effectively throughout the audit period. {with_ex} exception(s) were identified and remediated."
    else:
        overall_opinion, overall_class = "Unqualified (Clean)", "clean"
        overall_text = "Controls operated effectively throughout the audit period. No exceptions were identified."

    tsc_sections = ""
    for tsc in TSC_ORDER:
        tsc_results = by_tsc.get(tsc, [])
        rows = ""
        for r in tsc_results:
            ctrl = r["control"]
            exs  = r["exceptions"]
            ex_html = "".join(
                f'<div class="ex-inline"><span class="ex-id">{x["exception_id"]}</span> {x["exception_title"]} — {status_badge(x["status"])}</div>'
                for x in exs
            ) if exs else '<span class="none">—</span>'
            rows += f"""<tr>
              <td class="ctrl-id">{ctrl['control_id']}</td>
              <td class="tsc-ref">{ctrl['tsc_ref']}</td>
              <td class="ctrl-title">{ctrl['control_title']}</td>
              <td class="ctrl-owner">{ctrl['control_owner']}</td>
              <td class="ctrl-freq">{ctrl['frequency']}</td>
              <td><span class="ev-count">{len(r['evidence'])} item{'s' if len(r['evidence'])!=1 else ''}</span></td>
              <td>{opinion_badge(r['opinion'])}</td>
              <td class="ex-cell">{ex_html}</td>
            </tr>"""
        eff_count = sum(1 for r in tsc_results if r["opinion"] in ("Effective","Effective with Exceptions"))
        tsc_sections += f"""<div class="tsc-block">
          <div class="tsc-head">
            <div class="tsc-label">{tsc.upper()}</div>
            <div class="tsc-name">{tsc}</div>
            <div class="tsc-stat">{eff_count}/{len(tsc_results)} controls effective</div>
          </div>
          <table><thead><tr>
            <th>Control ID</th><th>TSC Ref</th><th>Title</th><th>Owner</th>
            <th>Frequency</th><th>Evidence</th><th>Opinion</th><th>Exceptions</th>
          </tr></thead><tbody>{rows}</tbody></table></div>"""

    ex_rows = "".join(f"""<tr>
      <td class="ctrl-id">{x['exception_id']}</td>
      <td class="ctrl-id">{x['control_id']}</td>
      <td class="ctrl-title">{x['exception_title']}</td>
      <td>{sev_badge(x['severity'])}</td>
      <td class="ex-desc">{x['exception_description']}</td>
      <td class="ex-resp">{x['management_response']}</td>
      <td class="ctrl-owner">{x['remediation_owner']}</td>
      <td style="white-space:nowrap">{x['remediation_date']}</td>
      <td>{status_badge(x['status'])}</td>
    </tr>""" for x in exceptions_raw)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SOC 2 Type II — {ENTITY_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,500;1,6..72,400&display=swap" rel="stylesheet">
<style>
:root{{--bg:#ECEAE3;--panel:#E2DFD5;--ink:#1C2430;--ink-dim:#535C68;--ink-faint:#7C8490;--hairline:#C9C4B7;--accent:#6E2A2A;--accent-dim:rgba(110,42,42,0.08);--eff:#3A6A5A;--eff-bg:rgba(58,106,90,0.10);--ewe:#5A5A2A;--ewe-bg:rgba(90,90,42,0.10);--ineff:#7A1C1C;--ineff-bg:rgba(122,28,28,0.10);--mod:#8A4A1A;--mod-bg:rgba(138,74,26,0.10);--sans:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;--serif:'Newsreader',Georgia,serif;}}
*{{box-sizing:border-box;}} body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;}}
.page-header{{background:var(--ink);color:var(--bg);padding:36px 48px;}}
.page-header .eyebrow{{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:rgba(236,234,227,0.5);margin-bottom:10px;}}
.page-header h1{{font-family:var(--serif);font-size:30px;font-weight:500;margin:0 0 4px;}}
.page-header .entity{{font-family:var(--serif);font-style:italic;font-size:18px;color:rgba(236,234,227,0.7);margin:4px 0 12px;}}
.page-header .meta{{font-family:var(--mono);font-size:12px;color:rgba(236,234,227,0.5);line-height:2;}}
.opinion-bar{{padding:28px 48px;border-bottom:1px solid var(--hairline);}}
.opinion-label{{font-family:var(--mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);margin-bottom:6px;}}
.opinion-value{{font-family:var(--serif);font-size:26px;font-weight:500;margin-bottom:6px;}}
.opinion-value.clean{{color:var(--eff);}} .opinion-value.ewe{{color:var(--ewe);}} .opinion-value.qual{{color:var(--ineff);}}
.opinion-sub{{font-size:13px;color:var(--ink-dim);max-width:560px;}}
.stat-bar{{display:flex;border-bottom:1px solid var(--hairline);}}
.stat{{flex:1;padding:20px 28px;border-right:1px solid var(--hairline);}}
.stat:last-child{{border-right:none;}}
.stat .num{{font-family:var(--serif);font-size:32px;line-height:1;}}
.stat .label{{font-family:var(--mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--ink-faint);margin-top:4px;}}
.stat.s-eff .num{{color:var(--eff);}} .stat.s-ex .num{{color:var(--ewe);}} .stat.s-ineff .num{{color:var(--ineff);}}
.content{{padding:40px 48px;overflow-x:auto;}}
.tsc-block{{margin-bottom:48px;}}
.tsc-head{{display:flex;align-items:baseline;gap:16px;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid var(--hairline);}}
.tsc-label{{font-family:var(--mono);font-size:12px;color:var(--accent);font-weight:500;}}
.tsc-name{{font-family:var(--serif);font-size:20px;font-weight:500;}}
.tsc-stat{{font-family:var(--mono);font-size:12px;color:var(--ink-faint);margin-left:auto;}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px;}}
thead th{{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:0.07em;text-transform:uppercase;color:var(--ink-faint);padding:0 12px 10px;border-bottom:1px solid var(--hairline);white-space:nowrap;}}
tbody tr{{border-bottom:1px solid var(--hairline);transition:background .1s;}} tbody tr:hover{{background:var(--panel);}}
td{{padding:12px;vertical-align:top;}}
td.ctrl-id{{font-family:var(--mono);font-size:11px;color:var(--ink-faint);white-space:nowrap;}}
td.tsc-ref{{font-family:var(--mono);font-size:11px;color:var(--ink-dim);white-space:nowrap;}}
td.ctrl-title{{font-weight:500;max-width:200px;}} td.ctrl-owner{{font-size:12px;color:var(--ink-dim);white-space:nowrap;}}
td.ctrl-freq{{font-family:var(--mono);font-size:11px;color:var(--ink-dim);white-space:nowrap;}}
td.ex-desc,td.ex-resp{{color:var(--ink-dim);font-size:12.5px;max-width:220px;}}
td.ex-cell{{font-size:12px;max-width:180px;}}
.ex-inline{{margin-bottom:4px;}} .ex-id{{font-family:var(--mono);font-size:10px;color:var(--ink-faint);margin-right:6px;}}
.ev-count{{font-family:var(--mono);font-size:11px;color:var(--ink-dim);}} .none{{color:var(--ink-faint);}}
.badge{{font-family:var(--mono);font-size:10px;letter-spacing:0.03em;text-transform:uppercase;padding:4px 8px;border-radius:20px;white-space:nowrap;display:inline-block;}}
.op-eff{{color:var(--eff);background:var(--eff-bg);}} .op-ewe{{color:var(--ewe);background:var(--ewe-bg);}}
.op-ineff{{color:var(--ineff);background:var(--ineff-bg);}} .op-insuf{{color:var(--ink-faint);background:var(--panel);}}
.sev-minor{{color:var(--ewe);background:var(--ewe-bg);}} .sev-mod{{color:var(--mod);background:var(--mod-bg);}} .sev-sig{{color:var(--ineff);background:var(--ineff-bg);}}
.st-rem{{color:var(--eff);background:var(--eff-bg);}} .st-open{{color:var(--ineff);background:var(--ineff-bg);}}
.ex-section{{background:var(--accent-dim);border:1px solid rgba(110,42,42,0.18);border-radius:2px;padding:28px 32px;margin-bottom:48px;}}
.ex-section h2{{font-family:var(--serif);font-size:22px;font-weight:500;margin:0 0 4px;}}
.ex-section .sub{{color:var(--ink-dim);font-size:13px;margin:0 0 20px;}}
.section-head{{margin-bottom:20px;}}
.section-head h2{{font-family:var(--serif);font-size:22px;font-weight:500;margin:0 0 4px;}}
.section-head p{{color:var(--ink-dim);font-size:13px;margin:0;}}
.report-footer{{border-top:1px solid var(--hairline);padding:22px 48px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;}}
</style>
</head>
<body>
<div class="page-header">
  <div class="eyebrow">SOC 2 Type II — Mock Audit Walkthrough</div>
  <h1>System and Organization Controls Report</h1>
  <div class="entity">{ENTITY_NAME}</div>
  <div class="meta">Audit Period: {AUDIT_PERIOD_START} – {AUDIT_PERIOD_END}<br>Trust Services Criteria: Security · Availability · Confidentiality<br>Report Date: {REPORT_DATE} · Note: Mock data for portfolio demonstration only</div>
</div>
<div class="opinion-bar">
  <div class="opinion-label">Auditor Opinion</div>
  <div class="opinion-value {overall_class}">{overall_opinion}</div>
  <div class="opinion-sub">{overall_text}</div>
</div>
<div class="stat-bar">
  <div class="stat"><div class="num">{total}</div><div class="label">Controls Tested</div></div>
  <div class="stat s-eff"><div class="num">{effective}</div><div class="label">Effective</div></div>
  <div class="stat s-ex"><div class="num">{total_ex}</div><div class="label">Exceptions</div></div>
  <div class="stat s-ineff"><div class="num">{open_ex}</div><div class="label">Open Exceptions</div></div>
  <div class="stat"><div class="num">12</div><div class="label">Audit Months</div></div>
</div>
<div class="content">
  <div class="ex-section">
    <h2>Exceptions ({total_ex} identified · {open_ex} open)</h2>
    <p class="sub">All exceptions identified during control testing. Each includes management response, remediation owner, and current status.</p>
    <table><thead><tr><th>ID</th><th>Control</th><th>Exception</th><th>Severity</th><th>Description</th><th>Management Response</th><th>Owner</th><th>Remediated</th><th>Status</th></tr></thead>
    <tbody>{ex_rows}</tbody></table>
  </div>
  <div class="section-head">
    <h2>Control Testing Results by Trust Services Criteria</h2>
    <p>Results of testing all controls over the audit period — {AUDIT_PERIOD_START} through {AUDIT_PERIOD_END}.</p>
  </div>
  {tsc_sections}
</div>
<div class="report-footer">
  <span>DOCUMENT CONTROL — Classification: Confidential · Mock data — not a real SOC 2 report</span>
  <span>Generated by soc2_audit.py · {REPORT_DATE}</span>
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

    for fp in [CONTROLS_FILE, EVIDENCE_FILE, EXCEPTIONS_FILE]:
        if not os.path.exists(fp):
            print(f"\n  Could not find '{fp}'. Run from the repo root.\n"); sys.exit(1)

    controls   = load_csv(CONTROLS_FILE)
    evidence   = load_csv(EVIDENCE_FILE)
    exceptions = load_csv(EXCEPTIONS_FILE)

    if "--tsc" in args:
        idx = args.index("--tsc")
        filt = args[idx+1] if idx+1 < len(args) else None
        if filt:
            controls = [c for c in controls if c["tsc_category"].lower() == filt.lower()]

    results = run_audit(controls, evidence, exceptions)
    print_summary(results, exceptions)

    if "--exceptions" in args:
        print_exceptions(exceptions)
    if "--summary" not in args:
        build_report(results, exceptions, output)

if __name__ == "__main__":
    main()
