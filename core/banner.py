import time
import random
import shutil
import datetime
from pathlib import Path

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.live import Live
from rich.rule import Rule
from rich.align import Align
from rich import box

console = Console()

# ─── Metadatos ────────────────────────────────────────────────────────────────
VERSION    = "1.1.0"
AUTHOR     = "Ferney Ramirez"
CODENAME   = "BlueShift"
FRAMEWORK  = "CEH Framework"
BUILD_DATE = "2026"

# ─── Herramientas con categoría y módulo asociado ─────────────────────────────
# (tool, categoría, módulo del framework)
ALL_TOOLS = [
    # Core / Reconocimiento
    ("nmap",          "Reconocimiento",  "recon"),
    ("whois",         "Reconocimiento",  "recon"),
    ("dig",           "Reconocimiento",  "recon"),
    ("curl",          "Utilidad",        "core"),
    # Explotación
    ("msfconsole",    "Explotación",     "exploit"),
    ("searchsploit",  "Explotación",     "exploit"),
    # Web / Vulnerabilidades
    ("nikto",         "Escaneo Web",     "vuln"),
    ("gobuster",      "Fuzzing",         "vuln"),
    ("sqlmap",        "Inyección SQL",   "vuln"),
    ("hydra",         "Fuerza Bruta",    "exploit"),
    # WiFi
    ("aircrack-ng",   "WiFi",            "wifi"),
    ("wifite",        "WiFi",            "wifi"),
    ("tshark",        "WiFi",            "wifi"),
    ("cowpatty",      "WiFi",            "wifi"),
    ("hcxpcapngtool", "WiFi",            "wifi"),
    ("iw",            "WiFi",            "wifi"),
]

# ─── Quotes ───────────────────────────────────────────────────────────────────
QUOTES = [
    ("The quieter you become, the more you can hear.", "Ram Dass"),
    ("Hackers are breaking the systems for profit. Before, it was about intellectual curiosity.", "Kevin Mitnick"),
    ("Security is a process, not a product.", "Bruce Schneier"),
    ("The only truly secure system is one that is powered off.", "Gene Spafford"),
    ("Offense must inform defense.", "NSA Principle"),
    ("Know your enemy and know yourself.", "Sun Tzu"),
    ("In cyberspace, the attacker always has the advantage.", "Anonymous"),
    ("Every system is insecure. The question is: how much?", "Unknown"),
    ("Amateurs hack systems, professionals hack people.", "Bruce Schneier"),
    ("There are only two types of companies: those that have been hacked and those that will be.", "Robert Mueller"),
    ("Pen testing is about finding truth, not just vulnerabilities.", "Unknown CEH"),
    ("The art of war teaches us to rely not on the likelihood of the enemy's not coming, but on our own readiness.", "Sun Tzu"),
]

# ─── ASCII Art ────────────────────────────────────────────────────────────────
BANNER_ART = r"""
  ██████╗███████╗██╗  ██╗    ███████╗██████╗  █████╗ ███╗   ███╗███████╗
 ██╔════╝██╔════╝██║  ██║    ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝
 ██║     █████╗  ███████║    █████╗  ██████╔╝███████║██╔████╔██║█████╗
 ██║     ██╔══╝  ██╔══██║    ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝
 ╚██████╗███████╗██║  ██║    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗
  ╚═════╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝"""

SUBTITLE = "  Certified Ethical Hacker — Automation Framework"

# ─── Loader ───────────────────────────────────────────────────────────────────
LOADER_STEPS = [
    ("Initializing core modules",       0.16),
    ("Loading recon engine",            0.14),
    ("Connecting exploit framework",    0.18),
    ("Loading WiFi audit module",       0.14),
    ("Verifying tool availability",     0.14),
    ("Mounting session manager",        0.12),
    ("Applying security context",       0.12),
    ("Ready",                           0.10),
]

def _animated_loader():
    bar_width = 28
    total     = len(LOADER_STEPS)
    console.print()
    for i, (label, delay) in enumerate(LOADER_STEPS, 1):
        filled  = int(bar_width * i / total)
        bar     = "█" * filled + "░" * (bar_width - filled)
        pct     = int(100 * i / total)
        is_last = i == total
        color   = "bold green" if is_last else "cyan"
        icon    = "✔" if is_last else "›"
        status  = "[bold green]READY[/bold green]" if is_last else f"[cyan]{label}[/cyan]"
        console.print(
            f"  [{color}]{icon}[/{color}]  [bold white]{bar}[/bold white]  "
            f"[bold cyan]{pct:3d}%[/bold cyan]  {status}",
            end="\r" if not is_last else "\n"
        )
        time.sleep(delay)
    console.print()

# ─── Stats de herramientas ────────────────────────────────────────────────────
def _build_tool_stats():
    """Devuelve (total, installed, rows) con todas las herramientas."""
    rows      = []
    installed = 0
    for tool, cat, mod in ALL_TOOLS:
        ok = shutil.which(tool) is not None
        if ok:
            installed += 1
        rows.append((tool, cat, mod, ok))
    return len(ALL_TOOLS), installed, rows


def _render_stats_table(rows: list) -> Table:
    """Tabla compacta con secciones por módulo."""
    # Agrupar por módulo
    from collections import defaultdict
    groups = defaultdict(list)
    for tool, cat, mod, ok in rows:
        groups[mod].append((tool, cat, ok))

    ORDER  = ["recon", "exploit", "vuln", "wifi", "core"]
    LABELS = {
        "recon":   "RECONOCIMIENTO",
        "exploit": "EXPLOTACIÓN",
        "vuln":    "WEB / VULNERABILIDADES",
        "wifi":    "WIFI",
        "core":    "CORE",
    }

    table = Table(
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        min_width=40,
        padding=(0, 1),
    )
    table.add_column("Herramienta", style="bold white",  width=15)
    table.add_column("Categoría",   style="dim white",   width=18)
    table.add_column("Estado",      justify="center",    width=8)

    for mod in ORDER:
        if mod not in groups:
            continue
        # Separador de sección
        table.add_row(
            f"[bold blue]── {LABELS[mod]}",
            "", "",
            style="dim"
        )
        for tool, cat, ok in groups[mod]:
            status = "[bold green]✔ OK[/bold green]" if ok else "[bold red]✗ N/A[/bold red]"
            table.add_row(tool, cat, status)

    return table


def _render_info_panel(total: int, installed: int) -> Panel:
    now      = datetime.datetime.now()
    missing  = total - installed
    # Contar solo las herramientas críticas para el estado
    critical = ["nmap", "msfconsole", "searchsploit", "aircrack-ng", "sqlmap"]
    crit_ok  = sum(1 for t in critical if shutil.which(t))
    health   = "ÓPTIMO"  if missing == 0      else \
               "BUENO"   if crit_ok == len(critical) else \
               "PARCIAL" if missing <= 5       else "LIMITADO"
    hcolor   = "green"   if health == "ÓPTIMO" else \
               "cyan"    if health == "BUENO"  else \
               "yellow"  if health == "PARCIAL" else "red"

    wifi_tools = ["aircrack-ng", "wifite", "tshark", "cowpatty", "hcxpcapngtool", "iw"]
    wifi_ok    = sum(1 for t in wifi_tools if shutil.which(t))

    lines = [
        f"[bold cyan]Framework[/bold cyan]   {FRAMEWORK}",
        f"[bold cyan]Versión[/bold cyan]     v{VERSION}  [dim]({CODENAME})[/dim]",
        f"[bold cyan]Autor[/bold cyan]       {AUTHOR}",
        f"[bold cyan]Build[/bold cyan]       {BUILD_DATE}",
        "",
        f"[bold cyan]Fecha[/bold cyan]       {now.strftime('%Y-%m-%d')}",
        f"[bold cyan]Hora[/bold cyan]        {now.strftime('%H:%M:%S')}",
        "",
        f"[bold cyan]Tools[/bold cyan]       {installed}/{total} instaladas",
        f"[bold cyan]WiFi[/bold cyan]        {wifi_ok}/{len(wifi_tools)} herramientas",
        f"[bold cyan]Estado[/bold cyan]      [bold {hcolor}]{health}[/bold {hcolor}]",
    ]
    return Panel(
        "\n".join(lines),
        title="[bold cyan][ INFO ][/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 2),
    )


def _render_quote() -> Panel:
    text, author = random.choice(QUOTES)
    return Panel(
        Align.center(
            f'[italic white]"{text}"[/italic white]\n'
            f"[bold cyan]  — {author}[/bold cyan]"
        ),
        border_style="blue",
        box=box.HORIZONTALS,
        padding=(0, 2),
    )


# ─── Función principal ────────────────────────────────────────────────────────
def print_banner():
    terminal_width = console.size.width
    console.clear()

    console.print(Rule(style="bold blue"))
    console.print(Align.center(Text(BANNER_ART, style="bold cyan")))
    console.print(Align.center(Text(SUBTITLE, style="bold blue")))
    console.print()

    console.print(Rule(title="[bold cyan][ INITIALIZING ][/bold cyan]", style="blue"))
    console.print()
    _animated_loader()

    console.print(Rule(title="[bold cyan][ SYSTEM STATUS ][/bold cyan]", style="blue"))
    console.print()

    total, installed, rows = _build_tool_stats()
    info_panel  = _render_info_panel(total, installed)
    tools_panel = Panel(
        _render_stats_table(rows),
        title="[bold cyan][ TOOLS ][/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    if terminal_width >= 100:
        console.print(Columns([info_panel, tools_panel], equal=True, expand=True))
    else:
        console.print(info_panel)
        console.print(tools_panel)

    console.print()
    console.print(Rule(title="[bold blue][ QUOTE OF THE SESSION ][/bold blue]", style="blue"))
    console.print()
    console.print(_render_quote())
    console.print()
    console.print(Rule(style="bold blue"))
    console.print()