"""
Módulo de WHOIS y enumeración DNS
"""
import socket
import re
from rich.console import Console
from rich.table import Table
from rich import box
from core.utils import run_command, check_tool, print_result, print_error, print_info, save_report, separator

console = Console()

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

def run_whois(target: str):
    """Ejecuta WHOIS sobre el target."""
    if not check_tool("whois"):
        print_error("whois no está instalado. Instálalo con: sudo apt install whois")
        return None

    print_info(f"Ejecutando WHOIS para: [bold]{target}[/bold]")
    stdout, stderr, code = run_command(["whois", target], timeout=30)

    if not stdout:
        print_error(f"WHOIS falló: {stderr}")
        return None

    # Filtrar líneas relevantes
    important_keys = [
        "Domain Name", "Registrar", "Creation Date", "Updated Date",
        "Registry Expiry", "Name Server", "DNSSEC", "Registrant",
        "Admin", "Tech", "Country", "Organization", "Registrant Email"
    ]
    filtered_lines = []
    for line in stdout.splitlines():
        if any(k.lower() in line.lower() for k in important_keys):
            filtered_lines.append(line.strip())

    summary = "\n".join(filtered_lines) if filtered_lines else stdout[:3000]
    print_result(f"WHOIS — {target}", summary, style="cyan")
    return stdout

def run_dns_enum(target: str):
    """Enumeración completa de registros DNS."""
    # Limpiar protocolo si lo hubiera
    domain = re.sub(r'^https?://', '', target).split('/')[0]

    print_info(f"Enumerando DNS para: [bold]{domain}[/bold]\n")

    # Resolver IP
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"  [bold green]IP resuelta:[/bold green] {ip}")
    except socket.gaierror:
        console.print(f"  [bold red]No se pudo resolver la IP de {domain}[/bold red]")

    all_output = []

    # Registros con dig
    if check_tool("dig"):
        table = Table(title=f"Registros DNS — {domain}", box=box.ROUNDED, border_style="magenta")
        table.add_column("Tipo", style="bold yellow", width=8)
        table.add_column("Resultado", style="white")

        for rtype in DNS_RECORD_TYPES:
            stdout, _, code = run_command(
                ["dig", "+short", rtype, domain], timeout=15
            )
            result = stdout.strip() or "[dim]—[/dim]"
            table.add_row(rtype, result)
            all_output.append(f"{rtype}: {stdout.strip()}")

        console.print(table)
    else:
        print_error("dig no está instalado. Instálalo con: sudo apt install dnsutils")

    # Zone transfer attempt
    separator()
    print_info("Intentando transferencia de zona (AXFR)...")
    if check_tool("dig"):
        # Obtener servidores NS primero
        ns_out, _, _ = run_command(["dig", "+short", "NS", domain], timeout=10)
        ns_servers = [ns.strip().rstrip('.') for ns in ns_out.splitlines() if ns.strip()]

        if ns_servers:
            for ns in ns_servers[:3]:
                zt_out, _, zt_code = run_command(
                    ["dig", "AXFR", domain, f"@{ns}"], timeout=15
                )
                if "XFR size" in zt_out or ("IN" in zt_out and "SOA" in zt_out):
                    print_result(f"⚠ AXFR exitoso en {ns}!", zt_out, style="red")
                    all_output.append(f"AXFR@{ns}: {zt_out}")
                else:
                    console.print(f"  [dim]AXFR en {ns}: bloqueado/fallido[/dim]")
        else:
            console.print("  [dim]No se encontraron servidores NS.[/dim]")

    # Subdomain bruteforce básico
    separator()
    print_info("Búsqueda rápida de subdominios comunes...")
    subdomains = [
        "www", "mail", "ftp", "admin", "vpn", "remote", "dev",
        "staging", "api", "portal", "test", "beta", "shop", "blog",
        "webmail", "ns1", "ns2", "smtp", "pop", "imap"
    ]
    found = []
    for sub in subdomains:
        try:
            full = f"{sub}.{domain}"
            ip_sub = socket.gethostbyname(full)
            found.append((full, ip_sub))
        except socket.gaierror:
            pass

    if found:
        sub_table = Table(title="Subdominios encontrados", box=box.SIMPLE, border_style="green")
        sub_table.add_column("Subdominio", style="bold green")
        sub_table.add_column("IP", style="yellow")
        for sub, ip_sub in found:
            sub_table.add_row(sub, ip_sub)
            all_output.append(f"Subdominio: {sub} -> {ip_sub}")
        console.print(sub_table)
    else:
        console.print("  [dim]No se encontraron subdominios comunes.[/dim]")

    full_report = "\n".join(all_output)
    report_file = save_report(domain, "dns_enum", full_report)
    print_info(f"Reporte guardado en: [bold]{report_file}[/bold]")

def run_recon_full(target: str):
    """OSINT completo: WHOIS + DNS en secuencia."""
    console.print("\n[bold cyan]╔══ MÓDULO: RECONOCIMIENTO OSINT COMPLETO ══╗[/bold cyan]")
    separator()
    whois_data = run_whois(target)
    separator()
    run_dns_enum(target)
    console.print("\n[bold green]✔ Reconocimiento completado.[/bold green]")
