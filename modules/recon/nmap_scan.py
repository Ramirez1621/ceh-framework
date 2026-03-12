"""
Módulo de escaneo con Nmap
Compatible con: Kali Linux, Ubuntu, Arch Linux
"""
import os
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from core.utils import (
    run_command, check_tool, print_result, print_error,
    print_info, print_warning, save_report, separator
)
from core.privileges import SUDO_PREFIX, IS_ROOT

console = Console()

SCAN_PROFILES = {
    "1": {
        "name": "Quick Scan",
        "desc": "Top 1000 puertos, detección de servicios",
        "flags": ["-sV", "-T4", "--open"],
        "icon": "⚡",
        "needs_root": False,
    },
    "2": {
        "name": "Full TCP Scan",
        "desc": "Todos los puertos TCP (1-65535)",
        "flags": ["-sV", "-sC", "-T4", "-p-", "--open"],
        "icon": "🔍",
        "needs_root": False,
    },
    "3": {
        "name": "Stealth SYN Scan",
        "desc": "Escaneo sigiloso SYN (máximo sigilo)",
        "flags": ["-sS", "-T2", "-p-", "--open"],
        "icon": "🥷",
        "needs_root": True,
    },
    "4": {
        "name": "UDP Scan",
        "desc": "Top 200 puertos UDP",
        "flags": ["-sU", "--top-ports", "200", "-T4"],
        "icon": "📡",
        "needs_root": True,
    },
    "5": {
        "name": "Vulnerability Scan",
        "desc": "Scripts NSE de vulnerabilidades conocidas",
        "flags": ["-sV", "--script=vuln", "-T4"],
        "icon": "🛡️",
        "needs_root": False,
    },
    "6": {
        "name": "OS Detection + Traceroute",
        "desc": "Detección de SO y ruta de red completa",
        "flags": ["-A", "-T4", "--traceroute"],
        "icon": "🖥️",
        "needs_root": True,
    },
}


def show_profiles():
    table = Table(title="Perfiles de Escaneo Nmap", box=box.ROUNDED, border_style="cyan")
    table.add_column("Opción",      style="bold yellow", justify="center", width=8)
    table.add_column("Perfil",      style="bold white",  width=26)
    table.add_column("Descripción", style="dim white")
    table.add_column("Root",        style="dim",         width=6, justify="center")

    for key, p in SCAN_PROFILES.items():
        needs_root = p.get("needs_root", False)
        req_tag = "[red]✔[/red]" if needs_root else "[green]—[/green]"
        label = f"{p['icon']} {p['name']}"
        if needs_root and not IS_ROOT:
            label = f"[dim]{p['icon']} {p['name']}[/dim]"
        table.add_row(f"[{key}]", label, p["desc"], req_tag)

    console.print(table)

    if not IS_ROOT:
        console.print(
            "\n  [yellow]⚠[/yellow]  Los perfiles marcados con [red]✔[/red] "
            "requieren [bold]sudo[/bold]. Ejecuta con [bold]sudo python3 main.py[/bold].\n"
        )


def run_nmap(target: str, silent: bool = False) -> str | None:
    """
    Ejecuta nmap contra el target.
    silent=True  → perfil automático para quick_attack (sin preguntar).
    Retorna el output crudo o None si falla.
    """
    if not check_tool("nmap"):
        print_error("nmap no está instalado.")
        print_info("Instala con:  sudo apt install nmap  /  sudo pacman -S nmap")
        return None

    console.print("\n[bold cyan]╔══ MÓDULO: NMAP SCANNER ══╗[/bold cyan]")
    separator()

    # ── Selección de perfil ───────────────────────────────────────────────────
    if silent:
        profile = dict(SCAN_PROFILES["1"])
        console.print(
            f"  [dim]Modo automático: {profile['icon']} {profile['name']}"
            f"{'  (root)' if IS_ROOT else ''}[/dim]\n"
        )
    else:
        show_profiles()
        choice = Prompt.ask(
            "\n[bold yellow]  Selecciona perfil[/bold yellow]",
            choices=list(SCAN_PROFILES.keys()),
            default="1"
        )
        profile = dict(SCAN_PROFILES[choice])

        if profile.get("needs_root") and not IS_ROOT:
            print_warning(
                f"El perfil [bold]{profile['name']}[/bold] requiere root. "
                "Resultados pueden ser incompletos."
            )

    flags = list(profile["flags"])

    # -Pn automático: en modo silent siempre; en interactivo preguntar
    if silent:
        if "-Pn" not in flags:
            flags = ["-Pn"] + flags
    else:
        pn = Prompt.ask(
            "\n  ¿Usar [bold]-Pn[/bold]? (recomendado en CTFs/firewalls) [s/n]",
            default="n"
        )
        if pn.lower() == "s":
            flags = ["-Pn"] + flags
            print_info("Flag [bold]-Pn[/bold] activado.")

    # ── Output file ───────────────────────────────────────────────────────────
    # Usamos el directorio reports/ del proyecto (no /tmp) para evitar
    # conflictos de permisos cuando nmap corre con sudo pero el proceso
    # padre fue iniciado por el usuario normal.
    import os as _os
    from core.utils import REPORTS_DIR as _REPORTS_DIR
    _os.makedirs(_REPORTS_DIR, exist_ok=True)

    safe_name   = target.replace("/", "_").replace(":", "_").replace(" ", "_")
    out_file    = f"{_REPORTS_DIR}/nmap_raw_{safe_name}.txt"
    extra_flags = ["-oN", out_file]

    if not silent:
        if Prompt.ask("  ¿Guardar resultado en archivo? [s/n]", default="s").lower() != "s":
            extra_flags = []

    # ── Construir y ejecutar comando ──────────────────────────────────────────
    cmd = SUDO_PREFIX + ["nmap"] + flags + extra_flags + [target]

    print_info(f"Ejecutando: [bold]{' '.join(cmd)}[/bold]")
    print_warning("Esto puede tardar varios minutos...\n")

    stdout, stderr, code = run_command(cmd, timeout=700)
    output = stdout or stderr

    # ── Retry automático con -Pn si el host parece caído ─────────────────────
    if output and ("Host seems down" in output or "0 hosts up" in output):
        if "-Pn" not in flags:
            print_warning("Host no responde a ping. Reintentando con [bold]-Pn[/bold]...")
            cmd2 = SUDO_PREFIX + ["nmap", "-Pn"] + flags + extra_flags + [target]
            print_info(f"Ejecutando: [bold]{' '.join(cmd2)}[/bold]\n")
            stdout2, stderr2, code = run_command(cmd2, timeout=700)
            output = stdout2 or stderr2 or output

    if not output:
        print_error(f"Nmap no retornó resultados. Código: {code}\n{stderr}")
        return None

    print_result(f"Nmap — {profile['name']} — {target}", output, style="green")

    report_file = save_report(target, f"nmap_{profile['name'].replace(' ', '_')}", output)
    print_info(f"Reporte guardado en: [bold]{report_file}[/bold]")

    return output