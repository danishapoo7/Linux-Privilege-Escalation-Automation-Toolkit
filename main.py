#!/usr/bin/env python3
"""
=============================================================
  Linux Privilege Escalation Automation Toolkit (LPEAT)
  Educational Security Auditing Tool - Detection Only
=============================================================
  Author  : Student Project
  Purpose : Automated Linux privilege escalation enumeration
  Mode    : READ-ONLY detection (no exploitation)
=============================================================
"""

import os
import sys
import argparse
import datetime
from modules.system_info     import gather_system_info
from modules.suid_scanner    import scan_suid_sgid
from modules.permissions     import scan_weak_permissions
from modules.services        import scan_services
from modules.cron_scanner    import scan_cron_jobs
from modules.kernel_check    import check_kernel_vulns
from modules.sudo_check      import check_sudo_misconfig
from modules.report_generator import generate_report

# ── Colour helpers ──────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║     Linux Privilege Escalation Automation Toolkit (LPEAT)    ║
║          Educational Security Auditing Tool v1.0             ║
║         ⚠  Detection ONLY — No exploitation performed ⚠     ║
╚══════════════════════════════════════════════════════════════╝
{RESET}"""


def print_banner():
    print(BANNER)
    print(f"  {YELLOW}[*] Scan started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"  {YELLOW}[*] Running as     : {os.getenv('USER', 'unknown')} (UID={os.getuid()}){RESET}\n")


def run_scan(args):
    """Execute all scanning modules and collect findings."""
    findings = {
        "scan_time"       : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_info"     : {},
        "suid_sgid"       : [],
        "weak_permissions": [],
        "services"        : [],
        "cron_jobs"       : [],
        "kernel_vulns"    : [],
        "sudo_misconfig"  : [],
        "summary"         : {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    steps = [
        ("Step 1/7  System Information Collection", gather_system_info,   "system_info"),
        ("Step 2/7  SUID/SGID Binary Discovery",   scan_suid_sgid,        "suid_sgid"),
        ("Step 3/7  Weak File Permissions",         scan_weak_permissions, "weak_permissions"),
        ("Step 4/7  Misconfigured Services",        scan_services,         "services"),
        ("Step 5/7  Cron Job Vulnerabilities",      scan_cron_jobs,        "cron_jobs"),
        ("Step 6/7  Kernel Exploit Detection",      check_kernel_vulns,    "kernel_vulns"),
        ("Step 7/7  Sudo Misconfiguration Check",   check_sudo_misconfig,  "sudo_misconfig"),
    ]

    for label, func, key in steps:
        print(f"  {CYAN}[*]{RESET} {label} …")
        try:
            result = func()
            findings[key] = result
            count = len(result) if isinstance(result, list) else (
                len(result) if isinstance(result, dict) else 0)
            print(f"  {GREEN}[✓]{RESET} Done — {count} item(s) collected\n")
        except Exception as exc:
            print(f"  {RED}[✗]{RESET} Error in {label}: {exc}\n")

    # ── Build severity summary ──────────────────────────────
    all_items = (findings["suid_sgid"] + findings["weak_permissions"] +
                 findings["services"] + findings["cron_jobs"] +
                 findings["kernel_vulns"] + findings["sudo_misconfig"])

    for item in all_items:
        sev = item.get("severity", "info").lower()
        if sev in findings["summary"]:
            findings["summary"][sev] += 1

    return findings


def print_summary(findings):
    """Pretty-print a quick summary table to the terminal."""
    s = findings["summary"]
    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  SCAN SUMMARY{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"  {RED}CRITICAL : {s['critical']}{RESET}")
    print(f"  {RED}HIGH     : {s['high']}{RESET}")
    print(f"  {YELLOW}MEDIUM   : {s['medium']}{RESET}")
    print(f"  {GREEN}LOW      : {s['low']}{RESET}")
    print(f"  INFO     : {s['info']}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    # Print top findings
    all_items = (findings["suid_sgid"] + findings["weak_permissions"] +
                 findings["services"] + findings["cron_jobs"] +
                 findings["kernel_vulns"] + findings["sudo_misconfig"])

    critical_high = [i for i in all_items
                     if i.get("severity", "").lower() in ("critical", "high")]
    if critical_high:
        print(f"{BOLD}{RED}  ⚠  High-Priority Findings:{RESET}")
        for item in critical_high[:10]:
            print(f"  {RED}▶{RESET}  [{item['severity'].upper()}] {item['title']}")
        if len(critical_high) > 10:
            print(f"      … and {len(critical_high)-10} more (see report)")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Linux Privilege Escalation Automation Toolkit (LPEAT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 main.py --output /tmp/report --format both"
    )
    parser.add_argument("--output", default="reports/lpeat_report",
                        help="Output file path (without extension)")
    parser.add_argument("--format", choices=["txt", "html", "both"], default="both",
                        help="Report format (default: both)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    # ── Run all modules ─────────────────────────────────────
    print(f"{BOLD}[+] Starting privilege escalation enumeration …{RESET}\n")
    findings = run_scan(args)

    # ── Print terminal summary ───────────────────────────────
    print_summary(findings)

    # ── Generate report file(s) ──────────────────────────────
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)

    print(f"{BOLD}[+] Generating report(s) …{RESET}")
    paths = generate_report(findings, args.output, args.format)
    for p in paths:
        print(f"  {GREEN}[✓]{RESET} Report saved → {p}")

    print(f"\n{GREEN}{BOLD}[✓] Scan complete.{RESET}\n")


if __name__ == "__main__":
    main()