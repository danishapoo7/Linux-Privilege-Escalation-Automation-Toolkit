"""
Module: permissions.py
Purpose: Scan for weak/dangerous file and directory permissions
"""

import os
import subprocess
import stat


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception:
        return ""


# ── Sensitive files that should NOT be world-readable/writable ────────────────
SENSITIVE_FILES = {
    "/etc/passwd"      : ("world-writable", "critical",
                          "Writable /etc/passwd allows adding root-level users"),
    "/etc/shadow"      : ("world-readable", "critical",
                          "Readable /etc/shadow exposes password hashes"),
    "/etc/sudoers"     : ("world-writable", "critical",
                          "Writable /etc/sudoers allows granting root sudo"),
    "/etc/crontab"     : ("world-writable", "high",
                          "Writable crontab allows injecting root-executed commands"),
    "/etc/hosts"       : ("world-writable", "medium",
                          "Writable /etc/hosts allows DNS spoofing"),
    "/etc/ssh/sshd_config": ("world-writable", "high",
                             "Writable sshd_config can allow unauthorized root login"),
    "/root"            : ("world-readable", "high",
                          "Readable /root directory exposes sensitive data"),
    "/root/.ssh"       : ("world-readable", "critical",
                          "Readable /root/.ssh may expose private keys"),
    "/root/.bash_history": ("world-readable", "medium",
                            "Root bash history may contain credentials or tokens"),
}


def _check_sensitive_files() -> list:
    findings = []
    for path, (check_type, severity, description) in SENSITIVE_FILES.items():
        if not os.path.exists(path):
            continue
        try:
            s = os.stat(path)
            mode = s.st_mode

            vulnerable = False
            detail = ""

            if check_type == "world-writable":
                if mode & stat.S_IWOTH:
                    vulnerable = True
                    detail = f"World-writable (mode {oct(mode)[-3:]})"
            elif check_type == "world-readable":
                if mode & stat.S_IROTH:
                    vulnerable = True
                    detail = f"World-readable (mode {oct(mode)[-3:]})"

            if vulnerable:
                findings.append({
                    "title"      : f"Insecure Permission: {path}",
                    "category"   : "Sensitive File Permission",
                    "severity"   : severity,
                    "path"       : path,
                    "permission" : oct(mode)[-4:],
                    "detail"     : detail,
                    "description": description,
                    "exploitation_possibility": "HIGH" if severity == "critical" else "MEDIUM",
                    "mitigation" : f"Fix permissions: chmod o-rw '{path}' and verify ownership",
                })
        except PermissionError:
            pass

    return findings


def _check_world_writable_dirs() -> list:
    """Find world-writable directories (excluding /tmp, /var/tmp)."""
    findings = []
    raw = _run(
        "find / -writable -type d -not -path '/proc/*' "
        "-not -path '/sys/*' -not -path '/dev/*' "
        "-not -path '/tmp' -not -path '/var/tmp' "
        "-not -path '/run/*' 2>/dev/null | head -50"
    )
    for path in raw.splitlines():
        path = path.strip()
        if not path:
            continue
        findings.append({
            "title"      : f"World-Writable Directory: {path}",
            "category"   : "World-Writable Directory",
            "severity"   : "medium",
            "path"       : path,
            "description": "Directory is writable by any user — may allow file injection",
            "exploitation_possibility": "MEDIUM — depends on processes that read from this path",
            "mitigation" : f"chmod o-w '{path}' — restrict write to owner/group only",
        })
    return findings


def _check_world_writable_files() -> list:
    """Find world-writable files outside /tmp (limit to 30)."""
    findings = []
    raw = _run(
        "find / -writable -type f -not -path '/proc/*' "
        "-not -path '/sys/*' -not -path '/dev/*' "
        "-not -path '/tmp/*' -not -path '/var/tmp/*' "
        "2>/dev/null | head -30"
    )
    for path in raw.splitlines():
        path = path.strip()
        if not path:
            continue
        owner = _run(f"stat -c '%U' '{path}' 2>/dev/null")
        severity = "high" if owner == "root" else "medium"
        findings.append({
            "title"      : f"World-Writable File: {path}",
            "category"   : "World-Writable File",
            "severity"   : severity,
            "path"       : path,
            "owner"      : owner,
            "description": (f"File owned by '{owner}' is world-writable. "
                            "If used by a privileged process, this is exploitable."),
            "exploitation_possibility": "HIGH" if severity == "high" else "MEDIUM",
            "mitigation" : f"chmod o-w '{path}' — review if world-write is necessary",
        })
    return findings


def _check_passwd_shadow_perms() -> list:
    """Specifically check /etc/passwd and /etc/shadow permissions."""
    findings = []
    for path in ["/etc/passwd", "/etc/shadow"]:
        if not os.path.exists(path):
            continue
        perm = _run(f"stat -c '%a %U %G' '{path}' 2>/dev/null")
        findings.append({
            "title"      : f"Auth File Permissions: {path}",
            "category"   : "Authentication File",
            "severity"   : "info",
            "path"       : path,
            "description": f"Current permissions: {perm}",
            "exploitation_possibility": "Informational",
            "mitigation" : "Ensure /etc/passwd is 644 and /etc/shadow is 640 or 000",
        })
    return findings


def _check_home_directory_permissions() -> list:
    """Check for world-readable home directories."""
    findings = []
    raw = _run("ls -la /home 2>/dev/null")
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        perms  = parts[0]
        owner  = parts[2]
        folder = parts[-1]
        if folder in (".", ".."):
            continue
        if len(perms) > 7 and perms[7] == "r":  # world-readable
            path = f"/home/{folder}"
            findings.append({
                "title"      : f"World-Readable Home Directory: {path}",
                "category"   : "Home Directory Permission",
                "severity"   : "medium",
                "path"       : path,
                "owner"      : owner,
                "permissions": perms,
                "description": f"Home directory of '{owner}' is world-readable. May expose SSH keys or credential files.",
                "exploitation_possibility": "MEDIUM — check for .ssh/id_rsa or credential files",
                "mitigation" : f"chmod 750 '{path}'",
            })
    return findings


def scan_weak_permissions() -> list:
    """Run all permission checks and return combined findings list."""
    findings = []
    findings.extend(_check_sensitive_files())
    findings.extend(_check_world_writable_dirs())
    findings.extend(_check_world_writable_files())
    findings.extend(_check_passwd_shadow_perms())
    findings.extend(_check_home_directory_permissions())

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return findings