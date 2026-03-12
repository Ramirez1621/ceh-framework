#!/usr/bin/env python3
"""
setup.py — Instalador interactivo del CEH Framework
Detecta la distro, verifica herramientas e instala las que falten.

Uso: python3 setup.py
"""
import sys
import os
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Verificar rich antes de todo ──────────────────────────────────────────────
def _bootstrap_rich():
    try:
        import rich
        return True
    except ImportError:
        print("  [setup] Instalando 'rich' (requerido para la TUI)...")
        flags = ["--break-system-packages"] if _needs_break_flag() else []
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "rich", "-q"] + flags,
            capture_output=True
        )
        if result.returncode == 0:
            print("  [setup] 'rich' instalado. ✔")
            return True
        else:
            print("  [setup] No se pudo instalar 'rich'.")
            print("  Intenta manualmente: pip install rich --break-system-packages")
            return False

def _needs_break_flag():
    from pathlib import Path
    for p in sys.path:
        if Path(p, "EXTERNALLY-MANAGED").exists():
            return True
    return False

if not _bootstrap_rich():
    sys.exit(1)

# ── Ahora sí con rich ─────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.compat import (
    detect_distro, environment_summary, install_tool,
    install_python_deps, CORE_TOOLS, EXPLOIT_TOOLS, OPTIONAL_TOOLS,
    UPDATE_CMDS,
)

console = Console()


def print_env_table(summary: dict):
    distro = summary["distro"]

    # Info del sistema
    wsl_tag  = "[bold magenta] WSL[/bold magenta]" if distro["is_wsl"] else ""
    root_tag = "[bold green] ROOT[/bold green]" if distro["is_root"] else "[yellow] sin sudo[/yellow]"

    console.print(Panel(
        f"[bold cyan]Distro:[/bold cyan]  {distro['name']}{wsl_tag}\n"
        f"[bold cyan]ID:[/bold cyan]      {distro['id']}\n"
        f"[bold cyan]Pkg Mgr:[/bold cyan] {distro['pkg_mgr'] or '[red]No detectado[/red]'}\n"
        f"[bold cyan]Arch:[/bold cyan]    {distro['arch']}\n"
        f"[bold cyan]Permisos:[/bold cyan]{root_tag}",
        title="[bold white]Entorno Detectado[/bold white]",
        border_style="cyan",
        box=box.ROUNDED
    ))

    # Tabla de herramientas
    table = Table(title="Estado de Herramientas", box=box.ROUNDED, border_style="white")
    table.add_column("Herramienta", style="bold white", width=16)
    table.add_column("Estado",      width=14)
    table.add_column("Categoría",   style="dim")

    def add_tools(tools_dict, category):
        for tool, ok in tools_dict.items():
            status = "[bold green]✔ Instalada[/bold green]" if ok else "[bold red]✗ Faltante[/bold red]"
            table.add_row(tool, status, category)

    add_tools(summary["core_tools"],     "Core")
    add_tools(summary["exploit_tools"],  "Exploit")
    add_tools(summary["optional_tools"], "Opcional")

    console.print(table)


def run_update(distro: dict):
    pkg_mgr = distro.get("pkg_mgr")
    if not pkg_mgr or pkg_mgr not in UPDATE_CMDS:
        return
    sudo_prefix = [] if distro["is_root"] else ["sudo"]
    cmd = sudo_prefix + UPDATE_CMDS[pkg_mgr]
    console.print(f"\n  [dim]Actualizando índice de paquetes ({pkg_mgr})...[/dim]")
    subprocess.run(cmd, capture_output=True)


def install_missing(summary: dict, categories: list[str]):
    distro = summary["distro"]

    all_tools = {}
    if "core" in categories:
        all_tools.update(summary["core_tools"])
    if "exploit" in categories:
        all_tools.update(summary["exploit_tools"])
    if "optional" in categories:
        all_tools.update(summary["optional_tools"])

    missing = [t for t, ok in all_tools.items() if not ok]

    if not missing:
        console.print("\n[bold green]✔ Todas las herramientas ya están instaladas.[/bold green]")
        return

    console.print(f"\n  Herramientas a instalar: [bold yellow]{', '.join(missing)}[/bold yellow]")

    # Actualizar índice una vez
    run_update(distro)

    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        for tool in missing:
            task = progress.add_task(f"Instalando [bold]{tool}[/bold]...", total=None)
            ok = install_tool(tool, distro, verbose=False)
            results[tool] = ok
            progress.remove_task(task)

    # Reporte
    for tool, ok in results.items():
        if ok:
            console.print(f"  [bold green]✔[/bold green] {tool} instalado")
        else:
            pkg = distro.get("pkg_mgr", "?")
            console.print(f"  [bold red]✗[/bold red] {tool} falló — intenta manualmente:")
            _print_manual_cmd(tool, distro)


def _print_manual_cmd(tool: str, distro: dict):
    from core.compat import get_package_name
    pkg_mgr = distro.get("pkg_mgr", "apt")
    pkg = get_package_name(tool, pkg_mgr) or tool
    sudo = "" if distro["is_root"] else "sudo "

    cmds = {
        "apt":    f"{sudo}apt install -y {pkg}",
        "pacman": f"{sudo}pacman -S --noconfirm {pkg}",
        "dnf":    f"{sudo}dnf install -y {pkg}",
        "zypper": f"{sudo}zypper install -y {pkg}",
    }
    cmd = cmds.get(pkg_mgr, f"instala {pkg} manualmente")
    console.print(f"    [dim]→ {cmd}[/dim]")

    # Instrucción especial para Metasploit
    if tool == "msfconsole":
        console.print(
            "    [dim]→ O descarga MSF: "
            "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html[/dim]"
        )


def main():
    console.print()
    console.print(Panel(
        "[bold cyan]CEH Framework — Setup & Verificación de Entorno[/bold cyan]\n"
        "[dim]Compatible con Kali, Parrot, Ubuntu, Debian, Arch, Manjaro, Fedora — nativos y WSL[/dim]",
        border_style="cyan",
        box=box.DOUBLE_EDGE
    ))
    console.print()

    summary = environment_summary()
    print_env_table(summary)

    # WSL warnings
    if summary["distro"]["is_wsl"]:
        console.print(Panel(
            "[bold yellow]Modo WSL detectado[/bold yellow]\n"
            "• Nmap requiere privilegios: [bold]sudo nmap[/bold]\n"
            "• Metasploit puede tener limitaciones de red en WSL1\n"
            "• Se recomienda WSL2 con [bold]systemd[/bold] habilitado\n"
            "• Para interfaces de red reales usa [bold]bridged network[/bold] en WSL2",
            border_style="yellow",
            box=box.ROUNDED
        ))

    # Sin gestor de paquetes
    if not summary["distro"]["pkg_mgr"]:
        console.print(
            "\n[bold red]✗ No se detectó un gestor de paquetes conocido.[/bold red]\n"
            "  Instala las herramientas manualmente y vuelve a correr este setup."
        )
        sys.exit(1)

    # ── Instalar deps Python ─────────────────────────────────────────
    console.print("\n[bold cyan][ 1/3 ] Dependencias Python[/bold cyan]")
    ok = install_python_deps(summary["distro"])
    if ok:
        console.print("  [bold green]✔[/bold green] Dependencias Python instaladas")
    else:
        console.print("  [bold yellow]⚠[/bold yellow] Revisa requirements.txt manualmente")

    # ── Instalar herramientas core ───────────────────────────────────
    console.print("\n[bold cyan][ 2/3 ] Herramientas Core (nmap, whois, dig)[/bold cyan]")
    missing_core = [t for t, ok in summary["core_tools"].items() if not ok]
    if missing_core:
        if Confirm.ask(f"  ¿Instalar herramientas core faltantes? ({', '.join(missing_core)})", default=True):
            install_missing(summary, ["core"])
    else:
        console.print("  [bold green]✔[/bold green] Todas las herramientas core están disponibles")

    # ── Herramientas opcionales ──────────────────────────────────────
    console.print("\n[bold cyan][ 3/3 ] Herramientas Opcionales[/bold cyan]")
    missing_opt = [t for t, ok in {**summary["exploit_tools"], **summary["optional_tools"]}.items() if not ok]
    if missing_opt:
        console.print(f"  Faltantes: [yellow]{', '.join(missing_opt)}[/yellow]")
        choice = Prompt.ask(
            "  ¿Instalar?",
            choices=["todas", "solo-msf", "ninguna"],
            default="ninguna"
        )
        if choice == "todas":
            install_missing(summary, ["exploit", "optional"])
        elif choice == "solo-msf":
            install_missing({**summary, "exploit_tools": summary["exploit_tools"], "optional_tools": {}}, ["exploit"])
    else:
        console.print("  [bold green]✔[/bold green] Herramientas opcionales disponibles")

    # ── Resultado final ──────────────────────────────────────────────
    console.print()
    final = environment_summary()
    all_core_ok = all(final["core_tools"].values())

    if all_core_ok:
        console.print(Panel(
            "[bold green]✔ Setup completo — puedes ejecutar:[/bold green]\n\n"
            "  [bold white]python3 main.py[/bold white]",
            border_style="green",
            box=box.DOUBLE_EDGE
        ))
    else:
        still_missing = [t for t, ok in final["core_tools"].items() if not ok]
        console.print(Panel(
            f"[bold yellow]⚠ Setup parcial — aún faltan: {', '.join(still_missing)}[/bold yellow]\n\n"
            "  El framework iniciará con funcionalidad limitada.\n"
            "  Revisa los comandos manuales indicados arriba.",
            border_style="yellow",
            box=box.ROUNDED
        ))

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Setup cancelado.[/dim]\n")
        sys.exit(0)