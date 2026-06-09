"""
Module: suid_scanner.py
Purpose: Discover SUID/SGID binaries and cross-reference with GTFOBins
"""

import subprocess
import os

# ── GTFOBins high-risk SUID binaries (subset — commonly exploitable) ──────────
GTFOBINS_SUID = {
    "awk", "bash", "busybox", "cp", "csh", "curl", "cut",
    "dash", "date", "dd", "diff", "dmsetup", "docker",
    "ed", "env", "expand", "expect", "find", "flock",
    "fmt", "fold", "gawk", "gdb", "genisoimage", "gimp",
    "grep", "gtester", "hd", "head", "hexdump", "iconv",
    "install", "ionice", "ip", "jjs", "journalctl",
    "jq", "jrunscript", "ksh", "ld.so", "less", "logsave",
    "look", "lua", "make", "mawk", "more", "mount",
    "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge",
    "msguniq", "mv", "mysql", "nano", "nawk", "newgrp",
    "nice", "nl", "nmap", "node", "nohup", "od",
    "openssl", "perl", "pg", "php", "pic", "pico",
    "pkexec", "pr", "python", "python2", "python3",
    "readelf", "restic", "rlwrap", "rpm", "rsync",
    "run-parts", "ruby", "rview", "rvim", "scp",
    "sed", "setarch", "shuf", "socat", "sort",
    "sqlite3", "ssh", "start-stop-daemon", "strace",
    "strings", "su", "suid_bin", "tail", "tar",
    "taskset", "tclsh", "tee", "telnet", "tftp",
    "time", "timeout", "tmux", "ul", "unexpand",
    "uniq", "unshare", "update-alternatives", "uudecode",
    "uuencode", "vi", "view", "vigr", "vipw", "vim",
    "vimdiff", "watch", "wget", "whiptail", "wish",
    "xargs", "xxd", "xz", "zsh",
}


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception:
        return ""


def _get_severity(binary_name, is_gtfobin):
    """Assign severity based on known risk."""
    critical = {"bash", "sh", "dash", "zsh", "python", "python3", "perl",
                "ruby", "php", "find", "vim", "nmap", "awk", "gawk"}
    high     = {"cp", "mv", "tar", "rsync", "wget", "curl", "openssl", "dd",
                "env", "less", "more", "nano", "gdb", "node", "lua"}
    if binary_name in critical:
        return "critical"
    if binary_name in high or is_gtfobin:
        return "high"
    return "medium"


def scan_suid_sgid() -> list:
    """
    Scan the filesystem for SUID and SGID binaries.
    Returns a list of finding dicts.
    """
    findings = []

    # ── Find SUID binaries ───────────────────────────────────
    suid_output = _run(
        "find / -perm -4000 -type f 2>/dev/null"
    )
    # ── Find SGID binaries ───────────────────────────────────
    sgid_output = _run(
        "find / -perm -2000 -type f 2>/dev/null"
    )

    suid_paths = [p for p in suid_output.splitlines() if p.strip()]
    sgid_paths = [p for p in sgid_output.splitlines() if p.strip()]

    def process_binary(path, bit_type):
        if not path:
            return
        binary_name = os.path.basename(path)
        is_gtfobin  = binary_name.lower() in GTFOBINS_SUID
        severity    = _get_severity(binary_name.lower(), is_gtfobin)

        # Get owner info
        owner = _run(f"stat -c '%U:%G %a' '{path}' 2>/dev/null")

        finding = {
            "title"      : f"{bit_type} Binary: {path}",
            "category"   : f"{bit_type} Binary",
            "severity"   : severity,
            "path"       : path,
            "binary_name": binary_name,
            "owner_info" : owner,
            "gtfobin"    : is_gtfobin,
            "description": (
                f"{'⚠ GTFOBins listed — known exploit paths exist. ' if is_gtfobin else ''}"
                f"Binary '{binary_name}' has {bit_type} bit set. "
                f"If misconfigured, may allow privilege escalation."
            ),
            "exploitation_possibility": (
                "HIGH — GTFOBins techniques applicable" if is_gtfobin else
                "MEDIUM — depends on binary version and context"
            ),
            "mitigation": (
                f"Remove {bit_type} bit: chmod u-s '{path}'  "
                f"(or g-s for SGID). Verify if {bit_type} is operationally required."
            ),
        }
        findings.append(finding)

    for p in suid_paths:
        process_binary(p, "SUID")
    for p in sgid_paths:
        # Skip duplicates (some binaries have both bits)
        if p not in suid_paths:
            process_binary(p, "SGID")

    # Sort: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return findings