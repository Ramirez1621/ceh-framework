#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CEH Framework — Instalador Universal v1.1
# Compatible con: Kali, Parrot, Ubuntu, Debian, Arch, Manjaro
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✔ ${1}${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ ${1}${NC}"; }
err()  { echo -e "${RED}  ✗ ${1}${NC}"; }
info() { echo -e "${CYAN}  → ${1}${NC}"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────${NC}"; }
section() { echo -e "\n${BOLD}${CYAN}[ ${1} ]${NC}"; sep; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  ██████╗███████╗██╗  ██╗    ███████╗██████╗  █████╗ ███╗   ███╗███████╗${NC}"
echo -e "${CYAN}${BOLD} ██╔════╝██╔════╝██║  ██║    ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝${NC}"
echo -e "${CYAN}${BOLD} ██║     █████╗  ███████║    █████╗  ██████╔╝███████║██╔████╔██║█████╗  ${NC}"
echo -e "${CYAN}${BOLD} ██║     ██╔══╝  ██╔══██║    ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ${NC}"
echo -e "${CYAN}${BOLD} ╚██████╗███████╗██║  ██║    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗${NC}"
echo -e "${CYAN}${BOLD}  ╚═════╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝${NC}"
echo -e "${BOLD}             Instalador Universal — CEH Framework v1.1.0${NC}"
echo ""

# ── Detectar distro ───────────────────────────────────────────────────────────
section "SISTEMA"
info "Detectando distribución..."

PKG_MGR=""; DISTRO_NAME=""
[ -f /etc/os-release ] && source /etc/os-release && DISTRO_NAME="${PRETTY_NAME:-$ID}"

if   command -v pacman  &>/dev/null; then PKG_MGR="pacman"
elif command -v apt-get &>/dev/null; then PKG_MGR="apt"
else
    err "No se detectó gestor de paquetes (apt/pacman)."
    err "Instala las herramientas manualmente."
    exit 1
fi

SUDO=""
[ "$(id -u)" != "0" ] && SUDO="sudo"

ok "Distro: ${DISTRO_NAME}"
ok "Gestor: ${PKG_MGR}"
ok "Privilegios: $([ -z "$SUDO" ] && echo 'root' || echo 'sudo')"

# ── Funciones de instalación ──────────────────────────────────────────────────
pkg_update() {
    info "Actualizando repositorios..."
    case $PKG_MGR in
        apt)    $SUDO apt-get update -qq ;;
        pacman) $SUDO pacman -Sy --noconfirm ;;
    esac
}

pkg_install() {
    case $PKG_MGR in
        apt)    $SUDO apt-get install -y "$@" ;;
        pacman) $SUDO pacman -S --noconfirm "$@" ;;
    esac
}

# Retorna nombre del paquete según gestor
get_pkg() {
    local tool="$1"
    case $PKG_MGR in
        apt)
            case $tool in
                nmap)         echo "nmap" ;;
                whois)        echo "whois" ;;
                dig)          echo "dnsutils" ;;
                curl)         echo "curl" ;;
                msfconsole)   echo "metasploit-framework" ;;
                searchsploit) echo "exploitdb" ;;
                nikto)        echo "nikto" ;;
                gobuster)     echo "gobuster" ;;
                sqlmap)       echo "sqlmap" ;;
                hydra)        echo "hydra" ;;
                aircrack-ng)  echo "aircrack-ng" ;;
                wifite)       echo "wifite" ;;
                tshark)       echo "tshark" ;;
                cowpatty)     echo "cowpatty" ;;
                hcxpcapngtool) echo "hcxtools" ;;
                iw)           echo "iw" ;;
                python)       echo "python3" ;;
                pip)          echo "python3-pip" ;;
            esac ;;
        pacman)
            case $tool in
                nmap)         echo "nmap" ;;
                whois)        echo "whois" ;;
                dig)          echo "bind" ;;
                curl)         echo "curl" ;;
                msfconsole)   echo "metasploit" ;;
                searchsploit) echo "exploitdb" ;;
                nikto)        echo "nikto" ;;
                gobuster)     echo "gobuster" ;;
                sqlmap)       echo "sqlmap" ;;
                hydra)        echo "thc-hydra" ;;
                aircrack-ng)  echo "aircrack-ng" ;;
                wifite)       echo "wifite" ;;
                tshark)       echo "wireshark-cli" ;;
                cowpatty)     echo "cowpatty" ;;
                hcxpcapngtool) echo "hcxtools" ;;
                iw)           echo "iw" ;;
                python)       echo "python" ;;
                pip)          echo "python-pip" ;;
            esac ;;
    esac
}

ensure_tool() {
    local tool="$1" display="${2:-$1}"
    if command -v "$tool" &>/dev/null; then
        ok "${display} — ya instalado"
        return 0
    fi
    info "Instalando ${display}..."
    local pkg
    pkg=$(get_pkg "$tool")
    if pkg_install "$pkg" 2>/dev/null; then
        ok "${display} instalado"
    else
        err "${display} — falló la instalación del paquete '${pkg}'"
        warn "Instala manualmente: ${SUDO} ${PKG_MGR} install ${pkg}"
    fi
}

install_python_deps() {
    info "Verificando Python 3..."
    if ! command -v python3 &>/dev/null; then
        pkg_install "$(get_pkg python)"
    fi
    ok "Python $(python3 --version 2>&1 | awk '{print $2}')"

    info "Verificando pip..."
    if ! python3 -m pip --version &>/dev/null; then
        pkg_install "$(get_pkg pip)" 2>/dev/null || true
        python3 -m ensurepip --upgrade 2>/dev/null || true
    fi

    info "Instalando dependencias Python (rich)..."
    BREAK_FLAG=""
    if python3 -c "import sys; from pathlib import Path; sys.exit(0 if any(Path(p,'EXTERNALLY-MANAGED').exists() for p in sys.path) else 1)" 2>/dev/null; then
        BREAK_FLAG="--break-system-packages"
    fi
    local req_file
    req_file="$(dirname "$0")/requirements.txt"
    if [ -f "$req_file" ]; then
        python3 -m pip install -r "$req_file" -q $BREAK_FLAG && ok "Dependencias Python OK" || warn "Algunas dependencias fallaron"
    else
        python3 -m pip install rich -q $BREAK_FLAG && ok "'rich' instalado" || warn "'rich' no se pudo instalar"
    fi
}

# ── 1. Actualizar repos ───────────────────────────────────────────────────────
section "1/6 — Actualizando repositorios"
pkg_update

# ── 2. Python ─────────────────────────────────────────────────────────────────
section "2/6 — Python y dependencias"
install_python_deps

# ── 3. Herramientas Core ──────────────────────────────────────────────────────
section "3/6 — Herramientas Core (Reconocimiento)"
ensure_tool nmap         "Nmap"
ensure_tool whois        "Whois"
ensure_tool dig          "Dig (dnsutils)"
ensure_tool curl         "Curl"
ensure_tool searchsploit "SearchSploit (exploitdb)"

# ── 4. Herramientas de Explotación ────────────────────────────────────────────
section "4/6 — Explotación y Vulnerabilidades (opcionales)"
echo -e "  ${YELLOW}Responde s/n para cada herramienta:${NC}\n"

read -rp "  ¿Instalar Metasploit Framework? [s/N] " msf_ans
if [[ "$msf_ans" =~ ^[sS]$ ]]; then
    if command -v msfconsole &>/dev/null; then
        ok "Metasploit — ya instalado"
    elif [ "$PKG_MGR" = "apt" ]; then
        info "Instalando Metasploit (apt)..."
        pkg_install metasploit-framework && ok "Metasploit instalado" || {
            warn "No disponible en repo. Instalando vía script oficial..."
            curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | $SUDO bash
        }
    elif [ "$PKG_MGR" = "pacman" ]; then
        warn "En Arch, instala desde AUR: yay -S metasploit"
    fi
fi

read -rp "  ¿Instalar Nikto?     [s/N] " ans; [[ "$ans" =~ ^[sS]$ ]] && ensure_tool nikto    "Nikto"
read -rp "  ¿Instalar Gobuster?  [s/N] " ans; [[ "$ans" =~ ^[sS]$ ]] && ensure_tool gobuster "Gobuster"
read -rp "  ¿Instalar SQLMap?    [s/N] " ans; [[ "$ans" =~ ^[sS]$ ]] && ensure_tool sqlmap   "SQLMap"
read -rp "  ¿Instalar Hydra?     [s/N] " ans; [[ "$ans" =~ ^[sS]$ ]] && ensure_tool hydra    "Hydra"

# ── 5. WiFi Audit Suite ───────────────────────────────────────────────────────
section "5/6 — WiFi Audit Suite (opcional)"
echo -e "  ${YELLOW}Instala el módulo completo de auditoría WiFi:${NC}"
echo -e "  ${CYAN}Incluye: aircrack-ng, wifite, tshark, cowpatty, hcxtools, iw${NC}\n"

read -rp "  ¿Instalar herramientas WiFi? [s/N] " wifi_ans
if [[ "$wifi_ans" =~ ^[sS]$ ]]; then
    ensure_tool aircrack-ng   "Aircrack-ng suite"
    ensure_tool wifite        "Wifite2"
    ensure_tool tshark        "TShark"
    ensure_tool cowpatty      "Cowpatty"
    ensure_tool hcxpcapngtool "hcxtools (hcxpcapngtool)"
    ensure_tool iw            "iw"

    # rockyou.txt
    echo ""
    info "Verificando diccionario rockyou.txt..."
    if [ -f /usr/share/wordlists/rockyou.txt ] || [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
        ok "rockyou.txt encontrado en /usr/share/wordlists/"
        # Descomprimir si está en .gz
        if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /tmp/ceh_rockyou.txt ]; then
            info "Descomprimiendo rockyou.txt.gz → /tmp/ceh_rockyou.txt ..."
            zcat /usr/share/wordlists/rockyou.txt.gz > /tmp/ceh_rockyou.txt 2>/dev/null && ok "Descomprimido en /tmp/ceh_rockyou.txt" || warn "Descompresión fallida — el módulo lo intentará en runtime"
        fi
    else
        warn "rockyou.txt no encontrado — el módulo WiFi lo descargará automáticamente."
    fi
fi

# ── 6. Permisos ───────────────────────────────────────────────────────────────
section "6/6 — Configuración final"

# Crear directorio de reportes
mkdir -p "$(dirname "$0")/reports"
ok "Directorio reports/ creado"

# Verificar nota de airmon-ng
if command -v airmon-ng &>/dev/null; then
    info "Para WiFi en modo monitor se recomienda ejecutar con sudo:"
    warn "sudo python3 main.py"
fi

# ── Resultado ─────────────────────────────────────────────────────────────────
echo ""
sep
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   ✔  Instalación completada                  ║"
echo "  ║                                              ║"
echo "  ║   Ejecuta:  sudo python3 main.py             ║"
echo "  ║                                              ║"
echo "  ║   Los reportes se guardan en: reports/       ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""