"""
Module: system_info.py
Purpose: Collect basic system information for context
"""

import os
import subprocess
import platform


def _run(cmd, shell=True):
    """Run a shell command safely; return stdout string."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return "N/A"


def gather_system_info() -> dict:
    """
    Collect system context:
      - hostname, OS, kernel, architecture
      - current user, UID, GID, groups
      - PATH, environment variables of interest
      - Network interfaces
    Returns a plain dict (not a list of findings).
    """
    info = {}

    # ── Basic OS ────────────────────────────────────────────
    info["hostname"]       = _run("hostname")
    info["os_release"]     = _run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    info["kernel_version"] = platform.release()
    info["kernel_full"]    = _run("uname -a")
    info["architecture"]   = platform.machine()
    info["cpu_info"]       = _run("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2").strip()

    # ── Current user ────────────────────────────────────────
    info["current_user"]   = os.getenv("USER", _run("whoami"))
    info["uid"]            = str(os.getuid())
    info["gid"]            = str(os.getgid())
    info["groups"]         = _run("id")
    info["home_dir"]       = os.path.expanduser("~")
    info["shell"]          = os.getenv("SHELL", "unknown")
    info["is_root"]        = (os.getuid() == 0)

    # ── PATH ────────────────────────────────────────────────
    info["path"]           = os.getenv("PATH", "")
    info["writable_path"]  = []
    for p in info["path"].split(":"):
        if p and os.path.isdir(p) and os.access(p, os.W_OK):
            info["writable_path"].append(p)

    # ── Network ─────────────────────────────────────────────
    info["network_interfaces"] = _run("ip -o addr show 2>/dev/null || ifconfig 2>/dev/null")

    # ── Interesting env vars ────────────────────────────────
    interesting_vars = ["SUDO_USER", "SUDO_UID", "LD_PRELOAD", "LD_LIBRARY_PATH",
                        "PYTHONPATH", "PERL5LIB", "RUBYLIB"]
    info["env_vars"] = {v: os.getenv(v, "") for v in interesting_vars if os.getenv(v)}

    # ── Users with login shells ─────────────────────────────
    info["login_users"] = _run(
        "grep -v nologin /etc/passwd 2>/dev/null | grep -v false | cut -d: -f1,3,6,7"
    )

    # ── Writable PATH entries summary ───────────────────────
    info["writable_path_summary"] = (
        f"{len(info['writable_path'])} writable PATH director(y/ies) found"
    )

    return info