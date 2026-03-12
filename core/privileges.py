"""
core/privileges.py — Detección de privilegios
Compatible con: Kali Linux, Ubuntu, Arch Linux

Provee:
  IS_ROOT      → True si el proceso corre como root
  SUDO_PREFIX  → ["sudo"] si no es root, [] si ya es root
  require_root() → imprime error y retorna False si no hay root
"""
import os
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

IS_ROOT: bool = os.geteuid() == 0

# Prefijo que se antepone a comandos que necesitan privilegios
# Si ya somos root → lista vacía (no agregar sudo redundante)
# Si no somos root → ["sudo"] para elevar
SUDO_PREFIX: list[str] = [] if IS_ROOT else ["sudo"]


def require_root(tool_name: str = "esta operación") -> bool:
    """
    Verifica que el proceso tenga privilegios root.
    Si no los tiene, muestra instrucciones y retorna False.
    """
    if IS_ROOT:
        return True

    console.print(Panel(
        f"[bold red]✗ Permisos insuficientes[/bold red]\n\n"
        f"  [bold]{tool_name}[/bold] requiere privilegios de root.\n\n"
        f"  Reinicia el framework con:\n"
        f"  [bold cyan]sudo python3 main.py[/bold cyan]",
        border_style="red",
        box=box.ROUNDED,
    ))
    return False


def print_privilege_status():
    """Muestra el estado de privilegios actual (para el banner/env status)."""
    if IS_ROOT:
        return "[bold green]✔ root[/bold green]"
    else:
        return "[yellow]usuario normal[/yellow] [dim](sin sudo)[/dim]"