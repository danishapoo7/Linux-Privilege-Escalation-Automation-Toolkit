"""
Module: report_generator.py
Purpose: Generate structured TXT and HTML security reports
"""

import os
import datetime


# ── Severity colours for HTML ─────────────────────────────────────────────────
SEV_COLOR = {
    "critical": "#dc2626",
    "high"    : "#ea580c",
    "medium"  : "#d97706",
    "low"     : "#16a34a",
    "info"    : "#2563eb",
}

SEV_BG = {
    "critical": "#fef2f2",
    "high"    : "#fff7ed",
    "medium"  : "#fffbeb",
    "low"     : "#f0fdf4",
    "info"    : "#eff6ff",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  TEXT REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def _build_txt(findings: dict) -> str:
    lines = []
    sep   = "=" * 70

    def h(title):
        lines.append(f"\n{sep}")
        lines.append(f"  {title}")
        lines.append(sep)

    def item(finding, idx):
        sev = finding.get("severity", "info").upper()
        lines.append(f"\n  [{idx}] [{sev}] {finding.get('title', 'N/A')}")
        lines.append(f"       Category   : {finding.get('category', 'N/A')}")
        lines.append(f"       Description: {finding.get('description', 'N/A')}")
        lines.append(f"       Exploit    : {finding.get('exploitation_possibility', 'N/A')}")
        lines.append(f"       Mitigation : {finding.get('mitigation', 'N/A')}")
        if finding.get("path"):
            lines.append(f"       Path       : {finding['path']}")
        if finding.get("cve_id"):
            lines.append(f"       CVE        : {finding['cve_id']}")
        if finding.get("reference"):
            lines.append(f"       Reference  : {finding['reference']}")

    # ── Header ───────────────────────────────────────────────
    lines.append("=" * 70)
    lines.append("    LINUX PRIVILEGE ESCALATION AUTOMATION TOOLKIT (LPEAT)")
    lines.append("    Security Audit Report — Detection Only")
    lines.append("=" * 70)
    lines.append(f"  Generated : {findings['scan_time']}")
    lines.append(f"  Hostname  : {findings['system_info'].get('hostname', 'N/A')}")
    lines.append(f"  OS        : {findings['system_info'].get('os_release', 'N/A')}")
    lines.append(f"  Kernel    : {findings['system_info'].get('kernel_version', 'N/A')}")
    lines.append(f"  User      : {findings['system_info'].get('current_user', 'N/A')} "
                 f"(UID={findings['system_info'].get('uid', 'N/A')})")
    lines.append(f"  Groups    : {findings['system_info'].get('groups', 'N/A')}")

    # ── Summary ──────────────────────────────────────────────
    h("SEVERITY SUMMARY")
    s = findings["summary"]
    lines.append(f"  CRITICAL : {s['critical']}")
    lines.append(f"  HIGH     : {s['high']}")
    lines.append(f"  MEDIUM   : {s['medium']}")
    lines.append(f"  LOW      : {s['low']}")
    lines.append(f"  INFO     : {s['info']}")
    total = sum(s.values())
    lines.append(f"  TOTAL    : {total}")

    # ── Sections ─────────────────────────────────────────────
    sections = [
        ("SUID/SGID BINARY FINDINGS",          findings["suid_sgid"]),
        ("WEAK FILE PERMISSION FINDINGS",       findings["weak_permissions"]),
        ("MISCONFIGURED SERVICE FINDINGS",      findings["services"]),
        ("CRON JOB VULNERABILITY FINDINGS",     findings["cron_jobs"]),
        ("KERNEL EXPLOIT DETECTION FINDINGS",   findings["kernel_vulns"]),
        ("SUDO MISCONFIGURATION FINDINGS",      findings["sudo_misconfig"]),
    ]

    for title, data in sections:
        h(title)
        if not data:
            lines.append("  No issues found.")
        else:
            for i, finding in enumerate(data, 1):
                item(finding, i)

    # ── System Info ──────────────────────────────────────────
    h("FULL SYSTEM INFORMATION")
    si = findings["system_info"]
    for k, v in si.items():
        if isinstance(v, list):
            v = ", ".join(v) if v else "None"
        lines.append(f"  {k:25}: {v}")

    lines.append(f"\n{sep}")
    lines.append("  END OF REPORT")
    lines.append(sep)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def _severity_badge(severity: str) -> str:
    color = SEV_COLOR.get(severity.lower(), "#6b7280")
    label = severity.upper()
    return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.8em;font-weight:bold;">{label}</span>')


def _build_finding_card(finding: dict, idx: int) -> str:
    sev  = finding.get("severity", "info").lower()
    bg   = SEV_BG.get(sev, "#f9fafb")
    bc   = SEV_COLOR.get(sev, "#6b7280")

    rows = [
        ("Description",         finding.get("description",              "—")),
        ("Exploitation Chance",  finding.get("exploitation_possibility",  "—")),
        ("Mitigation",          finding.get("mitigation",               "—")),
        ("Category",            finding.get("category",                 "—")),
    ]
    if finding.get("path"):
        rows.append(("Path", f'<code>{finding["path"]}</code>'))
    if finding.get("cve_id"):
        rows.append(("CVE", finding["cve_id"]))
    if finding.get("reference"):
        ref = finding["reference"]
        rows.append(("Reference", f'<a href="{ref}" target="_blank">{ref}</a>'))
    if finding.get("gtfobins_ref"):
        ref = finding["gtfobins_ref"]
        rows.append(("GTFOBins", f'<a href="{ref}" target="_blank">{ref}</a>'))

    table_rows = "".join(
        f'<tr><td style="width:160px;font-weight:600;color:#374151;padding:4px 8px;">{k}</td>'
        f'<td style="padding:4px 8px;color:#4b5563;">{v}</td></tr>'
        for k, v in rows
    )

    return f"""
    <div style="border:1px solid {bc};border-left:4px solid {bc};
                background:{bg};border-radius:6px;margin:8px 0;padding:12px 16px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <span style="font-size:0.85em;color:#9ca3af;">[{idx}]</span>
        {_severity_badge(sev)}
        <strong style="color:#111827;">{finding.get("title","N/A")}</strong>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:0.9em;">
        {table_rows}
      </table>
    </div>"""


def _build_html(findings: dict) -> str:
    si = findings["system_info"]
    s  = findings["summary"]
    now = findings["scan_time"]

    def section(title, data, icon):
        if not data:
            return f"""
            <div class="section">
              <h2>{icon} {title}</h2>
              <p style="color:#6b7280;">No issues found in this category.</p>
            </div>"""
        cards = "".join(_build_finding_card(f, i+1) for i, f in enumerate(data))
        return f"""
        <div class="section">
          <h2>{icon} {title}
            <span style="font-size:0.7em;font-weight:normal;color:#6b7280;">
              ({len(data)} finding{'s' if len(data)!=1 else ''})
            </span>
          </h2>
          {cards}
        </div>"""

    sections_html = "".join([
        section("SUID / SGID Binary Findings",         findings["suid_sgid"],         "🔴"),
        section("Weak File Permission Findings",        findings["weak_permissions"],   "🟠"),
        section("Misconfigured Service Findings",       findings["services"],           "🟡"),
        section("Cron Job Vulnerability Findings",      findings["cron_jobs"],          "🟣"),
        section("Kernel Exploit Detection Findings",    findings["kernel_vulns"],       "⚫"),
        section("Sudo Misconfiguration Findings",       findings["sudo_misconfig"],     "🔵"),
    ])

    env_vars = "".join(
        f'<tr><td><code>{k}</code></td><td><code>{v}</code></td></tr>'
        for k, v in si.get("env_vars", {}).items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>LPEAT Security Report — {now}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f3f4f6;
           color: #111827; line-height: 1.6; }}
    .header {{ background: linear-gradient(135deg,#1e3a5f,#0f172a);
               color:#fff; padding: 32px 40px; }}
    .header h1 {{ font-size: 1.6em; margin-bottom: 4px; }}
    .header p  {{ font-size: 0.9em; opacity: 0.7; }}
    .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
                  gap:8px; margin-top:20px; }}
    .meta-item {{ background:rgba(255,255,255,0.1); border-radius:6px;
                  padding:8px 12px; }}
    .meta-item label {{ font-size:0.75em; opacity:0.7; display:block; }}
    .meta-item span  {{ font-size:0.9em; font-weight:600; }}
    .summary {{ display:grid; grid-template-columns:repeat(5,1fr);
                gap:12px; padding:24px 40px; background:#fff;
                border-bottom:1px solid #e5e7eb; }}
    .sev-card {{ text-align:center; padding:16px; border-radius:8px; }}
    .sev-card .count {{ font-size:2em; font-weight:800; }}
    .sev-card .label {{ font-size:0.8em; font-weight:600; margin-top:4px; }}
    .content {{ max-width:1100px; margin:0 auto; padding:24px 40px; }}
    .section {{ background:#fff; border-radius:10px; padding:24px;
                margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.08); }}
    .section h2 {{ font-size:1.1em; margin-bottom:16px; color:#1f2937;
                   padding-bottom:8px; border-bottom:2px solid #e5e7eb; }}
    .sysinfo td {{ padding:4px 12px; font-size:0.88em; border-bottom:1px solid #f3f4f6; }}
    .sysinfo td:first-child {{ font-weight:600; color:#374151; width:220px; }}
    .footer {{ text-align:center; padding:20px; font-size:0.8em; color:#9ca3af; }}
  </style>
</head>
<body>

<!-- ── Header ───────────────────────────────────────────── -->
<div class="header">
  <h1>🛡 Linux Privilege Escalation Automation Toolkit (LPEAT)</h1>
  <p>Educational Security Audit Report — Detection Only · {now}</p>
  <div class="meta-grid">
    <div class="meta-item"><label>Hostname</label><span>{si.get('hostname','N/A')}</span></div>
    <div class="meta-item"><label>OS</label><span>{si.get('os_release','N/A')}</span></div>
    <div class="meta-item"><label>Kernel</label><span>{si.get('kernel_version','N/A')}</span></div>
    <div class="meta-item"><label>User</label><span>{si.get('current_user','N/A')} (UID {si.get('uid','?')})</span></div>
    <div class="meta-item"><label>Architecture</label><span>{si.get('architecture','N/A')}</span></div>
  </div>
</div>

<!-- ── Severity Summary ──────────────────────────────────── -->
<div class="summary">
  <div class="sev-card" style="background:#fef2f2;">
    <div class="count" style="color:#dc2626;">{s['critical']}</div>
    <div class="label" style="color:#dc2626;">CRITICAL</div>
  </div>
  <div class="sev-card" style="background:#fff7ed;">
    <div class="count" style="color:#ea580c;">{s['high']}</div>
    <div class="label" style="color:#ea580c;">HIGH</div>
  </div>
  <div class="sev-card" style="background:#fffbeb;">
    <div class="count" style="color:#d97706;">{s['medium']}</div>
    <div class="label" style="color:#d97706;">MEDIUM</div>
  </div>
  <div class="sev-card" style="background:#f0fdf4;">
    <div class="count" style="color:#16a34a;">{s['low']}</div>
    <div class="label" style="color:#16a34a;">LOW</div>
  </div>
  <div class="sev-card" style="background:#eff6ff;">
    <div class="count" style="color:#2563eb;">{s['info']}</div>
    <div class="label" style="color:#2563eb;">INFO</div>
  </div>
</div>

<!-- ── Main Content ──────────────────────────────────────── -->
<div class="content">
  {sections_html}

  <!-- System Info Table -->
  <div class="section">
    <h2>ℹ System Information</h2>
    <table class="sysinfo" style="width:100%;border-collapse:collapse;">
      <tr><td>Hostname</td><td>{si.get('hostname','N/A')}</td></tr>
      <tr><td>OS Release</td><td>{si.get('os_release','N/A')}</td></tr>
      <tr><td>Kernel Version</td><td>{si.get('kernel_full','N/A')}</td></tr>
      <tr><td>Architecture</td><td>{si.get('architecture','N/A')}</td></tr>
      <tr><td>Current User</td><td>{si.get('current_user','N/A')}</td></tr>
      <tr><td>UID / GID</td><td>{si.get('uid','?')} / {si.get('gid','?')}</td></tr>
      <tr><td>Groups</td><td>{si.get('groups','N/A')}</td></tr>
      <tr><td>Home Directory</td><td>{si.get('home_dir','N/A')}</td></tr>
      <tr><td>Shell</td><td>{si.get('shell','N/A')}</td></tr>
      <tr><td>Writable PATH dirs</td><td>{', '.join(si.get('writable_path',[])) or 'None'}</td></tr>
      <tr><td>Login Users</td><td><pre style="font-size:0.8em;white-space:pre-wrap;">{si.get('login_users','N/A')}</pre></td></tr>
    </table>

    {"<h3 style='margin-top:16px;'>Interesting Environment Variables</h3><table class='sysinfo' style='width:100%;border-collapse:collapse;'>" + env_vars + "</table>" if env_vars else ""}
  </div>
</div>

<div class="footer">
  Generated by LPEAT v1.0 · Educational Use Only · {now}
</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(findings: dict, base_path: str, fmt: str) -> list:
    """
    Generate report file(s).
    fmt: 'txt' | 'html' | 'both'
    Returns list of written file paths.
    """
    os.makedirs(os.path.dirname(base_path) if os.path.dirname(base_path) else ".", exist_ok=True)
    written = []

    if fmt in ("txt", "both"):
        txt_path = base_path + ".txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(_build_txt(findings))
        written.append(txt_path)

    if fmt in ("html", "both"):
        html_path = base_path + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_build_html(findings))
        written.append(html_path)

    return written