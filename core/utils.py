import subprocess
import os
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

console = Console()

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

def run_command(cmd: list[str] | str, shell=False, timeout=300) -> tuple[str, str, int]:
    """Ejecuta un comando y retorna (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout: el comando excedió el tiempo límite.", -1
    except FileNotFoundError as e:
        return "", f"Herramienta no encontrada: {e}", -1
    except Exception as e:
        return "", str(e), -1

def check_tool(tool: str) -> bool:
    """Verifica si una herramienta está instalada."""
    stdout, _, code = run_command(["which", tool])
    return code == 0 and bool(stdout.strip())

def print_result(title: str, content: str, style="green"):
    """Muestra resultados en un panel formateado."""
    console.print(Panel(
        content.strip() if content.strip() else "[dim]Sin resultados.[/dim]",
        title=f"[bold {style}]{title}[/bold {style}]",
        border_style=style,
        box=box.ROUNDED
    ))

def print_error(msg: str):
    console.print(f"[bold red]✗ Error:[/bold red] {msg}")

def print_info(msg: str):
    console.print(f"[bold cyan]ℹ[/bold cyan] {msg}")

def print_success(msg: str):
    console.print(f"[bold green]✔[/bold green] {msg}")

def print_warning(msg: str):
    console.print(f"[bold yellow]⚠[/bold yellow] {msg}")

def save_report(target: str, module: str, content: str) -> str:
    """Guarda un reporte en la carpeta reports/."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
    filename = f"{REPORTS_DIR}/{module}_{safe_target}_{ts}.txt"
    with open(filename, "w") as f:
        f.write(f"# CEH Framework - Reporte\n")
        f.write(f"# Módulo: {module}\n")
        f.write(f"# Target: {target}\n")
        f.write(f"# Fecha: {datetime.datetime.now()}\n")
        f.write("=" * 60 + "\n\n")
        f.write(content)
    return filename

def prompt_target(label="IP/URL/Dominio objetivo") -> str:
    """Solicita el target al usuario."""
    console.print(f"\n[bold cyan]  → {label}:[/bold cyan] ", end="")
    target = input("").strip()
    return target

def separator():
    console.print("[dim]" + "─" * 70 + "[/dim]")
