"""
core/compat.py — Capa de compatibilidad multi-distro
Compatible con: Kali Linux, Ubuntu/Debian, Arch Linux / Manjaro
"""
import os
import sys
import shutil
import platform
import subprocess
from pathlib import Path
from core.privileges import IS_ROOT, SUDO_PREFIX

# ─── Mapeo herramienta → paquete ──────────────────────────────────────────────
TOOL_PACKAGES = {
    # Reconocimiento
    "nmap":           {"apt": "nmap",                    "pacman": "nmap"},
    "whois":          {"apt": "whois",                   "pacman": "whois"},
    "dig":            {"apt": "dnsutils",                "pacman": "bind"},
    "curl":           {"apt": "curl",                    "pacman": "curl"},
    # Explotación
    "msfconsole":     {"apt": "metasploit-framework",    "pacman": "metasploit"},
    "searchsploit":   {"apt": "exploitdb",               "pacman": "exploitdb"},
    # Web
    "nikto":          {"apt": "nikto",                   "pacman": "nikto"},
    "gobuster":       {"apt": "gobuster",                "pacman": "gobuster"},
    # Inyección / Fuerza bruta
    "sqlmap":         {"apt": "sqlmap",                  "pacman": "sqlmap"},
    "hydra":          {"apt": "hydra",                   "pacman": "thc-hydra"},
    # WiFi
    "airmon-ng":      {"apt": "aircrack-ng",             "pacman": "aircrack-ng"},
    "airodump-ng":    {"apt": "aircrack-ng",             "pacman": "aircrack-ng"},
    "aireplay-ng":    {"apt": "aircrack-ng",             "pacman": "aircrack-ng"},
    "aircrack-ng":    {"apt": "aircrack-ng",             "pacman": "aircrack-ng"},
    "wifite":         {"apt": "wifite",                  "pacman": "wifite"},
    "tshark":         {"apt": "tshark",                  "pacman": "wireshark-cli"},
    "cowpatty":       {"apt": "cowpatty",                "pacman": "cowpatty"},
    "hcxpcapngtool":  {"apt": "hcxtools",                "pacman": "hcxtools"},
    "iw":             {"apt": "iw",                      "pacman": "iw"},
    # Python
    "python3":        {"apt": "python3",                 "pacman": "python"},
    "pip3":           {"apt": "python3-pip",             "pacman": "python-pip"},
}

INSTALL_CMDS = {
    "apt":    ["apt-get", "install", "-y"],
    "pacman": ["pacman",  "-S", "--noconfirm"],
}
UPDATE_CMDS = {
    "apt":    ["apt-get", "update", "-qq"],
    "pacman": ["pacman",  "-Sy",    "--noconfirm"],
}

# ─── Grupos de herramientas ───────────────────────────────────────────────────
CORE_TOOLS    = ["nmap", "whois", "dig", "curl"]
EXPLOIT_TOOLS = ["msfconsole", "searchsploit"]
WEB_TOOLS     = ["nikto", "gobuster", "sqlmap", "hydra"]
WIFI_TOOLS    = ["aircrack-ng", "airmon-ng", "airodump-ng", "wifite",
                 "tshark", "cowpatty", "hcxpcapngtool", "iw"]

# ─── Detección de distro ──────────────────────────────────────────────────────
def detect_distro() -> dict:
    info = {
        "id":      "unknown",
        "name":    "Unknown Linux",
        "pkg_mgr": None,
        "is_root": IS_ROOT,
        "arch":    platform.machine(),
    }
    os_release = {}
    for path in ["/etc/os-release", "/usr/lib/os-release"]:
        if Path(path).exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        os_release[k] = v.strip('"')
            break
    info["id"]   = os_release.get("ID", "").lower()
    info["name"] = os_release.get("PRETTY_NAME", os_release.get("NAME", "Unknown"))
    if shutil.which("pacman"):
        info["pkg_mgr"] = "pacman"
    elif shutil.which("apt-get"):
        info["pkg_mgr"] = "apt"
    else:
        like = os_release.get("ID_LIKE", "").lower()
        if "arch" in like or info["id"] in ("arch", "manjaro", "endeavouros"):
            info["pkg_mgr"] = "pacman"
        elif "debian" in like or "ubuntu" in like or info["id"] in ("kali", "parrot", "ubuntu", "debian"):
            info["pkg_mgr"] = "apt"
    return info

# ─── Verificación e instalación ───────────────────────────────────────────────
def tool_exists(tool: str) -> bool:
    return shutil.which(tool) is not None

def check_tools(tools: list[str]) -> dict[str, bool]:
    return {t: tool_exists(t) for t in tools}

def get_package_name(tool: str, pkg_mgr: str) -> str | None:
    return TOOL_PACKAGES.get(tool, {}).get(pkg_mgr)

def install_tool(tool: str, distro: dict, verbose: bool = True) -> bool:
    pkg_mgr  = distro.get("pkg_mgr")
    pkg_name = get_package_name(tool, pkg_mgr) if pkg_mgr else None
    if not pkg_mgr or not pkg_name:
        if verbose:
            print(f"  ✗ No hay paquete definido para '{tool}' en {pkg_mgr}.")
        return False
    cmd = SUDO_PREFIX + INSTALL_CMDS[pkg_mgr] + [pkg_name]
    if verbose:
        print(f"  → Instalando '{pkg_name}' con {pkg_mgr}...")
    try:
        result = subprocess.run(cmd, capture_output=not verbose, text=True)
        if result.returncode == 0:
            if verbose: print(f"  ✔ '{tool}' instalado.")
            return True
        return False
    except Exception as e:
        if verbose: print(f"  ✗ Error: {e}")
        return False

def install_python_deps(distro: dict) -> bool:
    req_file = Path(__file__).parent.parent / "requirements.txt"
    if not req_file.exists():
        return False
    needs_flag = distro.get("pkg_mgr") == "pacman" or _is_externally_managed()
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file), "-q"]
    if needs_flag:
        cmd.append("--break-system-packages")
    try:
        return subprocess.run(cmd, capture_output=True, text=True).returncode == 0
    except Exception:
        return False

def _is_externally_managed() -> bool:
    for p in sys.path:
        if (Path(p) / "EXTERNALLY-MANAGED").exists():
            return True
    return False

def environment_summary() -> dict:
    distro = detect_distro()
    return {
        "distro":        distro,
        "core_tools":    check_tools(CORE_TOOLS),
        "exploit_tools": check_tools(EXPLOIT_TOOLS),
        "web_tools":     check_tools(WEB_TOOLS),
        "wifi_tools":    check_tools(WIFI_TOOLS),
    }