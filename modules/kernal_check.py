"""
Module: kernel_check.py
Purpose: Check kernel version against known CVEs (detection only — no exploitation)
"""

import subprocess
import platform
import re


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


# ── Known CVE database (kernel version ranges → CVE info) ────────────────────
# Format: (max_version_tuple, cve_id, name, severity, description, mitigation)
KERNEL_CVES = [
    # DirtyPipe
    ((5, 16, 11), "CVE-2022-0847", "DirtyPipe", "critical",
     "Allows overwriting read-only files via pipe, enabling local root escalation.",
     "Upgrade kernel to >= 5.16.11, 5.15.25, or 5.10.102"),

    # DirtyCow
    ((4, 8, 3), "CVE-2016-5195", "DirtyCow", "critical",
     "Race condition in copy-on-write allows writing to read-only memory mappings.",
     "Upgrade kernel to >= 4.8.3 / 4.7.9 / 4.4.26. Apply vendor patches."),

    # Sudo Baron Samedit
    # (not kernel but very common — included for completeness)

    # Polkit pkexec (PwnKit)
    # Note: applies to polkit < 0.120 — check separately

    # OverlayFS
    ((5, 11, 0), "CVE-2021-3493", "OverlayFS Namespace Escape", "high",
     "Ubuntu-specific OverlayFS issue allows unprivileged users to gain root.",
     "Apply Ubuntu security patches; upgrade kernel."),

    # eBPF privilege escalation
    ((5, 16, 0), "CVE-2022-23222", "eBPF Local Privilege Escalation", "high",
     "eBPF verifier bug allows local privilege escalation via crafted BPF program.",
     "Upgrade kernel to >= 5.16; restrict BPF with sysctl kernel.unprivileged_bpf_disabled=1"),

    # PTRACE_SEIZE
    ((5, 14, 0), "CVE-2023-0468", "io_uring Race Condition", "high",
     "Use-after-free in io_uring can lead to privilege escalation.",
     "Upgrade kernel >= 6.1; disable io_uring if not needed"),

    # Spectre / Meltdown (informational — very old)
    ((4, 14, 0), "CVE-2017-5753", "Spectre Variant 1", "medium",
     "CPU speculative execution allows reading kernel memory from userspace.",
     "Apply retpoline patches; upgrade kernel. CPU microcode updates."),

    # Netfilter
    ((5, 18, 0), "CVE-2022-25636", "Netfilter heap-out-of-bounds", "high",
     "Heap out-of-bounds write in Netfilter nf_dup_netdev can lead to LPE.",
     "Upgrade kernel >= 5.18; restrict unprivileged user namespaces."),
]


def _version_str_to_tuple(version_str: str) -> tuple:
    """Convert '5.15.0-88-generic' → (5, 15, 0)."""
    clean = re.sub(r'[^0-9.]', '', version_str.split("-")[0])
    parts = clean.split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return (0, 0, 0)


def _check_kernel_version() -> list:
    """Compare running kernel against known CVE list."""
    findings = []
    kernel_str = platform.release()
    kernel_ver = _version_str_to_tuple(kernel_str)

    for (max_ver, cve_id, name, severity, description, mitigation) in KERNEL_CVES:
        if kernel_ver <= max_ver:
            findings.append({
                "title"      : f"Potential {cve_id} ({name}): Kernel {kernel_str}",
                "category"   : "Kernel Exploit Detection",
                "severity"   : severity,
                "cve_id"     : cve_id,
                "cve_name"   : name,
                "kernel_version": kernel_str,
                "max_patched_version": ".".join(str(v) for v in max_ver),
                "description": description,
                "exploitation_possibility": (
                    f"Potential — kernel {kernel_str} is at or below patched version "
                    f"{'.'.join(str(v) for v in max_ver)}. Verify with PoC testing in lab."
                ),
                "mitigation" : mitigation,
                "reference"  : f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

    return findings


def _check_kernel_protections() -> list:
    """Check for disabled kernel security protections."""
    findings = []

    # ASLR
    aslr = _run("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
    if aslr == "0":
        findings.append({
            "title"      : "ASLR Disabled (kernel.randomize_va_space=0)",
            "category"   : "Kernel Protection",
            "severity"   : "high",
            "description": "Address Space Layout Randomization is disabled, "
                           "making memory exploitation significantly easier.",
            "exploitation_possibility": "HIGH — memory corruption exploits are more reliable",
            "mitigation" : "Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space",
        })

    # DMESG restriction
    dmesg = _run("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null")
    if dmesg == "0":
        findings.append({
            "title"      : "dmesg Unrestricted (kernel.dmesg_restrict=0)",
            "category"   : "Kernel Protection",
            "severity"   : "medium",
            "description": "All users can read kernel ring buffer (dmesg), "
                           "which may leak kernel addresses useful for exploit development.",
            "exploitation_possibility": "MEDIUM — aids exploit development via kernel address leaks",
            "mitigation" : "Set kernel.dmesg_restrict=1 in /etc/sysctl.conf",
        })

    # Unprivileged BPF
    bpf = _run("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null")
    if bpf == "0":
        findings.append({
            "title"      : "Unprivileged BPF Enabled (kernel.unprivileged_bpf_disabled=0)",
            "category"   : "Kernel Protection",
            "severity"   : "medium",
            "description": "Unprivileged users can load BPF programs. "
                           "Multiple CVEs exploit this for privilege escalation.",
            "exploitation_possibility": "MEDIUM — required step for several kernel CVE exploits",
            "mitigation" : "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.conf",
        })

    # Perf events
    perf = _run("cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null")
    if perf and int(perf or "3") < 2:
        findings.append({
            "title"      : f"Permissive perf_event_paranoid ({perf})",
            "category"   : "Kernel Protection",
            "severity"   : "low",
            "description": "perf_event_paranoid < 2 allows unprivileged access to performance events, "
                           "potentially leaking kernel addresses.",
            "exploitation_possibility": "LOW — useful in chained exploits",
            "mitigation" : "Set kernel.perf_event_paranoid=3 in /etc/sysctl.conf",
        })

    # User namespaces
    userns = _run("cat /proc/sys/user/max_user_namespaces 2>/dev/null")
    if userns and userns != "0":
        findings.append({
            "title"      : "User Namespaces Enabled",
            "category"   : "Kernel Protection",
            "severity"   : "info",
            "description": f"User namespaces are enabled (max: {userns}). "
                           "Many container escapes and OverlayFS CVEs require this.",
            "exploitation_possibility": "Informational — required by several CVEs",
            "mitigation" : "If not needed: echo 0 > /proc/sys/user/max_user_namespaces",
        })

    return findings


def _check_ptrace_scope() -> list:
    """Check ptrace scope — relates to process inspection privilege."""
    findings = []
    scope = _run("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
    if scope == "0":
        findings.append({
            "title"      : "ptrace_scope=0 (permissive)",
            "category"   : "Kernel Protection",
            "severity"   : "medium",
            "description": "ptrace_scope=0 allows any process to ptrace any other process "
                           "owned by the same user, enabling memory inspection and injection.",
            "exploitation_possibility": "MEDIUM — allows credential dumping from other processes",
            "mitigation" : "Set kernel.yama.ptrace_scope=1 in /etc/sysctl.conf",
        })
    return findings


def _check_eol_kernel() -> list:
    """Check if kernel is an end-of-life version."""
    findings = []
    kernel_str = platform.release()
    kernel_ver = _version_str_to_tuple(kernel_str)

    # Long-term support kernels (rough reference)
    # Versions below 5.4 are generally EOL for most distros
    if kernel_ver[0] < 4 or (kernel_ver[0] == 4 and kernel_ver[1] < 19):
        findings.append({
            "title"      : f"End-of-Life Kernel: {kernel_str}",
            "category"   : "Kernel EOL",
            "severity"   : "high",
            "kernel"     : kernel_str,
            "description": (
                f"Kernel {kernel_str} is likely end-of-life and no longer receives "
                "security patches. Many unpatched CVEs likely apply."
            ),
            "exploitation_possibility": "HIGH — numerous unpatched CVEs may apply",
            "mitigation" : "Upgrade kernel to a supported LTS version (5.15+, 6.1+)",
        })

    return findings


def check_kernel_vulns() -> list:
    """Run all kernel checks."""
    findings = []
    findings.extend(_check_kernel_version())
    findings.extend(_check_kernel_protections())
    findings.extend(_check_ptrace_scope())
    findings.extend(_check_eol_kernel())

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return findings