"""
Module: services.py
Purpose: Detect misconfigured systemd services and dangerous PATH settings
"""

import subprocess
import os
import re


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


def _get_root_services() -> list:
    """Find systemd services running as root with writable ExecStart paths."""
    findings = []

    # List all enabled service unit files
    service_list = _run("systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'")
    services = [s for s in service_list.splitlines() if s.endswith(".service")]

    for svc in services[:80]:  # cap at 80 to avoid very long scans
        unit_file = _run(f"systemctl show -p FragmentPath {svc} 2>/dev/null | cut -d= -f2")
        if not unit_file or not os.path.isfile(unit_file):
            continue

        try:
            with open(unit_file, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        # Check if User= is set to root (or not set, defaulting to root)
        user_match = re.search(r"^User\s*=\s*(.+)$", content, re.MULTILINE)
        runs_as    = user_match.group(1).strip() if user_match else "root"

        if runs_as not in ("root", ""):
            continue

        # Look for ExecStart and check if the script/binary is writable
        exec_matches = re.findall(r"^Exec(?:Start|Stop|Reload)\s*=\s*(.+)$",
                                  content, re.MULTILINE)
        for exec_line in exec_matches:
            # Extract the binary path (first token, ignore flags)
            exec_line = exec_line.strip().lstrip("-+!")
            binary    = exec_line.split()[0] if exec_line.split() else ""
            if not binary or not os.path.isfile(binary):
                continue
            if os.access(binary, os.W_OK):
                findings.append({
                    "title"      : f"Writable Service Binary: {binary} ({svc})",
                    "category"   : "Misconfigured Service",
                    "severity"   : "critical",
                    "service"    : svc,
                    "unit_file"  : unit_file,
                    "binary"     : binary,
                    "runs_as"    : runs_as or "root",
                    "description": (
                        f"Service '{svc}' runs as '{runs_as or 'root'}' and its "
                        f"ExecStart binary '{binary}' is writable by the current user. "
                        "Replacing it allows arbitrary code execution as root."
                    ),
                    "exploitation_possibility": "CRITICAL — replace binary, restart service",
                    "mitigation" : (
                        f"chmod o-w '{binary}' — ensure service binaries are owned by root "
                        "and not writable by unprivileged users."
                    ),
                })

        # Check for insecure PATH in service file
        path_match = re.search(r"^Environment.*PATH\s*=\s*(.+)$", content, re.MULTILINE)
        if path_match:
            svc_path = path_match.group(1)
            for p in svc_path.split(":"):
                p = p.strip().replace('"', "").replace("'", "")
                if p and os.path.isdir(p) and os.access(p, os.W_OK):
                    findings.append({
                        "title"      : f"Insecure PATH in Service: {svc}",
                        "category"   : "Misconfigured Service",
                        "severity"   : "high",
                        "service"    : svc,
                        "unit_file"  : unit_file,
                        "binary"     : p,
                        "runs_as"    : runs_as or "root",
                        "description": (
                            f"Service '{svc}' PATH includes writable directory '{p}'. "
                            "PATH hijacking may allow privilege escalation."
                        ),
                        "exploitation_possibility": "HIGH — PATH hijacking",
                        "mitigation" : (
                            "Use absolute paths in service files. "
                            f"Remove writable directories from PATH: {p}"
                        ),
                    })

    return findings


def _check_sudo_nopasswd() -> list:
    """Check /etc/sudoers for NOPASSWD entries."""
    findings = []
    sudoers_files = ["/etc/sudoers"]
    sudoers_dir   = "/etc/sudoers.d"

    if os.path.isdir(sudoers_dir):
        for f in os.listdir(sudoers_dir):
            sudoers_files.append(os.path.join(sudoers_dir, f))

    for sf in sudoers_files:
        if not os.path.isfile(sf):
            continue
        try:
            content = _run(f"sudo cat '{sf}' 2>/dev/null || cat '{sf}' 2>/dev/null")
            if not content:
                continue
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "NOPASSWD" in line.upper():
                    findings.append({
                        "title"      : f"NOPASSWD Sudo Rule: {line[:80]}",
                        "category"   : "Sudo Misconfiguration",
                        "severity"   : "high",
                        "file"       : sf,
                        "rule"       : line,
                        "description": (
                            f"Sudoers rule allows password-less sudo: '{line}'. "
                            "This may allow privilege escalation without knowing root password."
                        ),
                        "exploitation_possibility": "HIGH — sudo command without password",
                        "mitigation" : (
                            "Remove NOPASSWD from sudoers. "
                            "If required, restrict to specific safe commands only."
                        ),
                    })
        except Exception:
            pass

    return findings


def _check_path_hijacking() -> list:
    """Check for relative paths or writable dirs in system PATH."""
    findings = []
    path_env  = os.getenv("PATH", "")
    path_dirs = path_env.split(":")

    for idx, p in enumerate(path_dirs):
        if not p:
            findings.append({
                "title"      : "Empty Entry in PATH (PATH hijacking risk)",
                "category"   : "PATH Misconfiguration",
                "severity"   : "high",
                "path"       : "(empty — current directory)",
                "description": "Empty PATH entry means current directory is searched. "
                               "Placing a malicious binary in CWD allows hijacking.",
                "exploitation_possibility": "HIGH — drop malicious binary in any directory",
                "mitigation" : "Remove empty entries from PATH in /etc/profile or ~/.bashrc",
            })
        elif not os.path.isabs(p):
            findings.append({
                "title"      : f"Relative PATH Entry: '{p}'",
                "category"   : "PATH Misconfiguration",
                "severity"   : "high",
                "path"       : p,
                "description": f"PATH contains relative directory '{p}' — PATH hijacking risk.",
                "exploitation_possibility": "HIGH",
                "mitigation" : "Use only absolute paths in PATH",
            })

    return findings


def scan_services() -> list:
    """Run all service-related checks."""
    findings = []
    findings.extend(_get_root_services())
    findings.extend(_check_sudo_nopasswd())
    findings.extend(_check_path_hijacking())

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return findings