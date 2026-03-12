#!/usr/bin/env python3
"""
CEH Framework — Ethical Hacking Automation Toolkit
Uso exclusivo para pruebas autorizadas y entornos de laboratorio.
Compatible con: Kali Linux, Ubuntu / Debian, Arch Linux / Manjaro
"""
import sys
import os
import subprocess
from pathlib import Path

def _resolve_root() -> str:
    """Resuelve el directorio raíz del proyecto de forma robusta."""
    candidates = []

    # Estrategia 1: Path(__file__).resolve() — más robusta
    try:
        candidates.append(Path(__file__).resolve().parent)
    except Exception:
        pass

    # Estrategia 2: os.path.realpath — alternativa si resolve() falla
    try:
        candidates.append(Path(os.path.realpath(__file__)).parent)
    except Exception:
        pass

    # Estrategia 3: basado en argv[0]
    try:
        candidates.append(Path(os.path.realpath(sys.argv[0])).parent)
    except Exception:
        pass

    # Estrategia 4: CWD como último recurso
    candidates.append(Path(os.getcwd()))

    # Retornar el primero que contenga core/banner.py (validación real)
    for candidate in candidates:
        if (candidate / "core" / "banner.py").exists():
            return str(candidate)

    # Fallback absoluto
    return str(candidates[0]) if candidates else os.getcwd()


ROOT = _resolve_root()

# Limpiar y reconstruir sys.path sin duplicados
for _p in [ROOT, str(Path(ROOT).parent)]:
    while _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, ROOT)


# ── Bootstrap: instalar 'rich' automáticamente si no está ─────────────────────
def _bootstrap():
    try:
        import rich  # noqa: F401
        return
    except ImportError:
        pass

    print("[CEH Framework] Instalando dependencia 'rich'...")

    # Detectar entorno externally-managed (Arch/Manjaro, PEP 668)
    flags = []
    for p in sys.path:
        try:
            if (Path(p) / "EXTERNALLY-MANAGED").exists():
                flags = ["--break-system-packages"]
                break
        except Exception:
            pass

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "rich", "-q"] + flags,
        capture_output=True
    )
    if result.returncode == 0:
        print("[CEH Framework] 'rich' instalado correctamente.\n")
    else:
        print("ERROR: No se pudo instalar 'rich'. Ejecuta manualmente:")
        print("  pip install rich --break-system-packages")
        sys.exit(1)


_bootstrap()

# ── Imports principales ────────────────────────────────────────────────────────
from rich.console import Console          # noqa: E402
from rich.table import Table              # noqa: E402
from rich.panel import Panel              # noqa: E402
from rich.prompt import Prompt, Confirm   # noqa: E402
from rich import box                      # noqa: E402

from core.banner import print_banner, console                          # noqa: E402
from core.utils import print_info, print_error, separator, prompt_target  # noqa: E402
from core.privileges import IS_ROOT, print_privilege_status
from core.compat import detect_distro, check_tools, CORE_TOOLS, EXPLOIT_TOOLS  # noqa: E402
from modules.recon.nmap_scan import run_nmap                           # noqa: E402
from modules.recon.osint import run_whois, run_dns_enum, run_recon_full  # noqa: E402
from modules.exploit.msf_handler import run_exploit_module, run_listener  # noqa: E402
from modules.vuln.sqli import run_sqli_module                             # noqa: E402
from modules.exploit.searchsploit import run_searchsploit_from_nmap           # noqa: E402
from modules.wifi.wifi_audit import run_wifi_audit                                # noqa: E402


# ─── Menús ─────────────────────────────────────────────────────────────────────

MAIN_MENU = {
    "1": ("🔍 Reconocimiento",      "recon_menu"),
    "2": ("💣 Explotación",         "exploit_menu"),
    "3": ("🛡️  Vulnerabilidades",    "vuln_menu"),
    "4": ("📡 Auditoría WiFi",       "wifi_audit"),
    "5": ("⚡ Ataque Rápido Full",  "quick_attack"),
    "6": ("📂 Ver Reportes",        "view_reports"),
    "0": ("❌ Salir",               "exit"),
}

RECON_MENU = {
    "1": ("📡 Nmap — Escaneo de puertos/servicios",  "nmap"),
    "2": ("🌐 WHOIS — Información del dominio/IP",   "whois"),
    "3": ("🔤 DNS — Enumeración completa",           "dns"),
    "4": ("🚀 OSINT Completo (WHOIS + DNS + Nmap)",  "full"),
    "0": ("⬅  Volver",                               "back"),
}

EXPLOIT_MENU = {
    "1": ("💀 Lanzar Exploit con Metasploit",        "exploit"),
    "2": ("🔎 SearchSploit — Buscar exploits por IP",  "searchsploit"),
    "3": ("📻 Iniciar Listener Reverso (MSF)",         "listener"),
    "0": ("⬅  Volver",                                 "back"),
}


VULN_MENU = {
    "1": ("💉 SQL Injection (Manual + SQLMap)", "sqli"),
    "0": ("⬅  Volver",                         "back"),
}


# ─── Helpers de UI ─────────────────────────────────────────────────────────────

def render_menu(title: str, items: dict, color="cyan"):
    table = Table(
        title=f"[bold {color}]{title}[/bold {color}]",
        box=box.ROUNDED,
        border_style=color,
        show_header=False,
        min_width=55,
    )
    table.add_column("Opción", style="bold yellow", justify="center", width=8)
    table.add_column("Descripción", style="white")
    for key, (label, _) in items.items():
        dim = key == "0"
        table.add_row(f"[{key}]", f"[dim]{label}[/dim]" if dim else label)
    console.print(table)
    console.print()


def _show_env_status():
    """Panel de estado del entorno al arrancar."""
    distro     = detect_distro()
    core_ok    = check_tools(CORE_TOOLS)
    exploit_ok = check_tools(EXPLOIT_TOOLS)

    pkg_str  = distro["pkg_mgr"] or "[red]desconocido[/red]"
    priv_str = print_privilege_status()

    lines = [
        f"[bold cyan]Distro:[/bold cyan]    {distro['name']}",
        f"[bold cyan]Pkg Mgr:[/bold cyan]   {pkg_str}",
        f"[bold cyan]Privilegios:[/bold cyan] {priv_str}",
        "",
    ]

    parts = []
    for t, ok in {**core_ok, **exploit_ok}.items():
        parts.append(f"{'[green]✔[/green]' if ok else '[red]✗[/red]'} {t}")
    lines.append("  ".join(parts))

    missing = [t for t, ok in core_ok.items() if not ok]
    if missing:
        lines.append(
            f"\n  [yellow]⚠ Faltantes:[/yellow] {', '.join(missing)}"
            "\n  Ejecuta [bold]python3 setup.py[/bold] para instalarlas."
        )

    if not IS_ROOT:
        lines.append(
            "\n  [yellow]⚠[/yellow]  Para funcionalidad completa (SYN scan, OS detect):"
            "\n     [bold cyan]sudo python3 main.py[/bold cyan]"
        )

    console.print(Panel(
        "\n".join(lines),
        title="[bold white]Entorno Detectado[/bold white]",
        border_style="dim",
        box=box.ROUNDED,
    ))
    console.print()


# ─── Acciones ──────────────────────────────────────────────────────────────────

def quick_attack():
    console.print("\n[bold magenta]╔══ ATAQUE RÁPIDO FULL ══╗[/bold magenta]")
    separator()
    target = prompt_target()
    if not target:
        print_error("Target vacío.")
        return

    print_info(f"Target: [bold]{target}[/bold]")

    # ── FASE 1: OSINT ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ FASE 1/4 ] OSINT — WHOIS + DNS[/bold cyan]")
    run_recon_full(target)

    # ── FASE 2: Nmap ──────────────────────────────────────────────────────────
    separator()
    console.print("\n[bold cyan][ FASE 2/4 ] NMAP — Escaneo de puertos y versiones[/bold cyan]")
    nmap_output = run_nmap(target, silent=True)

    # ── FASE 3: SearchSploit automático ───────────────────────────────────────
    separator()
    console.print("\n[bold cyan][ FASE 3/4 ] SEARCHSPLOIT — Búsqueda de exploits[/bold cyan]")
    if nmap_output:
        run_searchsploit_from_nmap(nmap_output, target)
    else:
        print_error("No hay output de nmap para analizar. Saltando SearchSploit.")

    # ── FASE 4: Explotación manual con MSF ────────────────────────────────────
    separator()
    console.print("\n[bold cyan][ FASE 4/4 ] EXPLOTACIÓN — Metasploit Manual[/bold cyan]")
    if Confirm.ask(
        "  [bold red]¿Lanzar exploit manual con Metasploit?[/bold red]",
        default=False
    ):
        run_exploit_module(target)

    console.print("\n[bold green]✔ Ataque completo finalizado.[/bold green]")


def view_reports():
    reports_dir = Path(ROOT) / "reports"
    if not reports_dir.exists():
        print_info("No hay reportes generados aún.")
        return

    files = sorted(reports_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        print_info("Carpeta reports/ vacía.")
        return

    table = Table(title="📂 Reportes", box=box.ROUNDED, border_style="blue")
    table.add_column("#",       style="dim",       width=5)
    table.add_column("Archivo", style="bold white")
    table.add_column("Tamaño",  style="yellow",    justify="right")
    for i, f in enumerate(files[:20], 1):
        table.add_row(str(i), f.name, f"{f.stat().st_size:,} B")
    console.print(table)

    choice = Prompt.ask("\n  # para ver (o Enter para volver)", default="")
    if choice.strip().isdigit():
        idx = int(choice.strip()) - 1
        if 0 <= idx < len(files):
            from core.utils import print_result
            print_result(files[idx].name, files[idx].read_text(), style="blue")


# ─── Loops de menú ─────────────────────────────────────────────────────────────

def recon_loop():
    while True:
        render_menu("Módulo — Reconocimiento / OSINT", RECON_MENU, color="cyan")
        choice = Prompt.ask("[bold yellow]  Opción[/bold yellow]",
                            choices=list(RECON_MENU.keys()), default="0")
        action = RECON_MENU[choice][1]

        if action == "back":
            break

        target = prompt_target()
        if not target:
            print_error("Target vacío.")
            continue

        if   action == "nmap":  run_nmap(target)
        elif action == "whois": run_whois(target)
        elif action == "dns":   run_dns_enum(target)
        elif action == "full":  run_recon_full(target)

        input("\n  [Presiona Enter para continuar...]")


def exploit_loop():
    while True:
        render_menu("Módulo — Explotación", EXPLOIT_MENU, color="red")
        choice = Prompt.ask("[bold yellow]  Opción[/bold yellow]",
                            choices=list(EXPLOIT_MENU.keys()), default="0")
        action = EXPLOIT_MENU[choice][1]

        if action == "back":
            break
        elif action == "exploit":
            target = prompt_target()
            if target:
                run_exploit_module(target)
        elif action == "searchsploit":
            target = prompt_target()
            if target:
                # Lanzar nmap rápido y pasar a searchsploit
                from core.utils import print_warning as _pw
                _pw("Ejecutando nmap -sV rápido para obtener versiones...")
                from modules.recon.nmap_scan import run_nmap as _nmap
                nmap_out = _nmap(target, silent=True)
                if nmap_out:
                    run_searchsploit_from_nmap(nmap_out, target)
        elif action == "listener":
            from modules.exploit.msf_handler import get_local_ip
            lhost   = Prompt.ask("  LHOST",   default=get_local_ip())
            lport   = Prompt.ask("  LPORT",   default="4444")
            payload = Prompt.ask("  Payload", default="windows/x64/meterpreter/reverse_tcp")
            run_listener(lhost, lport, payload)

        input("\n  [Presiona Enter para continuar...]")

def vuln_loop():
    while True:
        render_menu("Módulo — Vulnerabilidades Web", VULN_MENU, color="yellow")
        choice = Prompt.ask("[bold yellow]  Opción[/bold yellow]",
                            choices=list(VULN_MENU.keys()), default="0")
        action = VULN_MENU[choice][1]

        if action == "back":
            break
        elif action == "sqli":
            target = prompt_target()
            if target:
                run_sqli_module(target)

        input("\n  [Presiona Enter para continuar...]")



# ─── Entrada principal ─────────────────────────────────────────────────────────

def main_loop():
    print_banner()
    _show_env_status()

    console.print(Panel(
        "[bold red]AVISO LEGAL:[/bold red] Uso exclusivo en entornos autorizados.\n"
        "Pruebas de penetración requieren permiso del propietario.\n"
        "El uso no autorizado viola leyes de ciberseguridad locales e internacionales.",
        border_style="red",
        box=box.HEAVY,
    ))
    console.print()

    if not Confirm.ask(
        "[bold yellow]  ¿Confirmas que tienes autorización?[/bold yellow]",
        default=False
    ):
        console.print("\n[bold red]Saliendo...[/bold red]")
        sys.exit(0)

    while True:
        console.print()
        render_menu("CEH Framework — Menú Principal", MAIN_MENU, color="magenta")
        choice = Prompt.ask("[bold yellow]  Opción[/bold yellow]",
                            choices=list(MAIN_MENU.keys()), default="0")
        action = MAIN_MENU[choice][1]

        if   action == "exit":         console.print("\n[bold cyan]Stay ethical! 🛡️[/bold cyan]\n"); sys.exit(0)
        elif action == "recon_menu":   recon_loop()
        elif action == "vuln_menu":    vuln_loop()
        elif action == "wifi_audit":   run_wifi_audit()
        elif action == "exploit_menu": exploit_loop()
        elif action == "quick_attack": quick_attack()
        elif action == "view_reports": view_reports()


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrumpido. Stay ethical! 🛡️[/bold yellow]\n")
        sys.exit(0)